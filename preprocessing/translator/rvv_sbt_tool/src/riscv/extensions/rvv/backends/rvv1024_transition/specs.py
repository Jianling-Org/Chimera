"""RVV256→RVV1024 过渡后端的唯一指令规格表。

本模块把 opcode、操作数 form、掩码策略、SEW/LMUL 边界和纯验证逻辑放在
一起。prepare 阶段只调用这里的 validator：它会检查源物理组布局和临时组
容量，但绝不调用 assembly builder，也不会分配标签或生成后再丢弃文本。

复杂指令仍由各自 ``handlers`` 模块显式降低；数据表只合并能够共享同一组
结构约束的指令，不从 opcode 字符串猜测有符号性、舍入、tail 或 vstart
语义。
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import Iterable

from riscv.extensions.rvv.backends.rvv1024_transition.operands import is_vector_csr_instruction
from riscv.extensions.rvv.backends.rvv1024_transition.handlers import (
    arithmetic as arithmetic_handler,
    config as config_handler,
    convert,
    csr as csr_handler,
    gather,
    mask as mask_handler,
    memory,
    reduction as reduction_handler,
    slide,
    widen,
)
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _VECTOR_CSR_WRITE_OR_RMW_OPCODES,
)
from riscv.extensions.rvv.backends.rvv1024_transition.handlers.csr import (
    _build_vector_csr_write_lines,
)
from riscv.extensions.rvv.backends.rvv1024_transition.lowering import TRANSITION_LOWERER
from riscv.extensions.rvv.backends.rvv1024_transition.lowering_metadata import (
    TransitionLoweringMetadata,
)
from riscv.extensions.rvv.translation.specs import (
    expand_semantic_groups,
    make_scalar_result_resolvers,
)
from riscv.extensions.rvv.translation.contracts import (
    InstructionSpec,
    MaskPolicy,
    TailPolicy,
    VStartPolicy,
)
from riscv.extensions.rvv.translation.specs import HandlerRegistry

from riscv.extensions.rvv.backends.rvv1024_transition.validation import (
    _Seed,
    _ALL_SEWS,
    _ALL_LMULS,
    _WHOLE_FACTORS,
    SCALAR_RESULT_OPCODES,
    _validator,
)


_FLOAT_SEWS = frozenset({16, 32, 64})
_WIDEN_FLOAT_SEWS = frozenset({16, 32})


@dataclass(frozen=True, slots=True)
class _SemanticAxes:
    """一个 validation kind 共享、且不从 opcode 名称猜测的语义轴。"""

    operand_order: tuple[str, ...]
    # ``None`` 表示该 validation kind 内部存在多种语义，必须从上方逐 opcode
    # 事实表取得；写入 InstructionSpec 前一定会被解析为具体值。
    signedness: str | None
    rounding_policy: str | None


_EXACT_INTEGER = "exact-integer"
_ARCHITECTURAL_FRM = "architectural-frm"
_NOT_APPLICABLE = "not-applicable"


def _expand_semantic_groups(
    groups: tuple[tuple[tuple[str, ...], str], ...], *, fact_name: str
) -> dict[str, str]:
    """展开显式 opcode 语义分组；重复事实属于规格表错误。"""

    return expand_semantic_groups(
        groups, backend_label="RVV1024 过渡后端", fact_name=fact_name
    )


_EXPLICIT_SIGNEDNESS = _expand_semantic_groups((
    (("vadd.vi", "vadd.vv", "vadd.vx", "vsub.vv", "vsub.vx", "vrsub.vi", "vmul.vv", "vmul.vx", "vmacc.vv", "vmacc.vx", "vmadd.vv", "vmadd.vx"), "modular-integer"),
    (("vand.vi", "vand.vv", "vand.vx", "vandn.vv", "vor.vi", "vor.vv", "vor.vx", "vxor.vv", "vnot.v", "vredor.vs"), "bitwise"),
    (("vsll.vi", "vsll.vv", "vsll.vx", "vsrl.vi", "vsrl.vv", "vsrl.vx", "vwsll.vi", "vnsrl.wi"), "logical-shift"),
    (("vsra.vi", "vnsra.wi"), "arithmetic-shift"),
    (("vdiv.vx", "vmax.vv"), "signed-integer"),
    (("vmaxu.vv", "vredmaxu.vs"), "unsigned-integer"),
    (("vredsum.vs",), "modular-reduction"),
    (("vid.v",), "unsigned-index"),
    (("vmv.s.x", "vmv.v.v", "vmv.v.x", "vmv.x.s", "vmerge.vim", "vmerge.vvm", "vmerge.vxm"), "bit-preserving"),
    (("vlseg2e32.v", "vlseg2e64.v", "vlsseg2e32.v", "vlsseg2e64.v", "vsseg2e32.v", "vsseg2e64.v", "vsseg4e64.v", "vssseg2e32.v", "vssseg2e64.v"), "not-applicable"),
    (("vmseq.vi", "vmseq.vx", "vmsne.vi", "vmsne.vv", "vmsne.vx"), "equality-compare"),
    (("vmsgtu.vi", "vmsgtu.vx", "vmsleu.vi", "vmsleu.vv", "vmsltu.vv", "vmsltu.vx"), "unsigned-compare"),
    (("vmsle.vi",), "signed-compare"),
    (("vmfgt.vf", "vmfle.vf", "vmfne.vf"), "floating-point-compare"),
    (("vfncvt.f.f.w", "vfwcvt.f.f.v"), "floating-point"),
    (("vfncvt.f.xu.w",), "unsigned-integer-to-floating-point"),
    (("vfncvt.x.f.w",), "floating-point-to-signed-integer"),
    (("vfwcvt.f.x.v",), "signed-integer-to-floating-point"),
    (("vfwcvt.f.xu.v",), "unsigned-integer-to-floating-point"),
    (("vfwcvt.x.f.v",), "floating-point-to-signed-integer"),
    (("vfwcvt.xu.f.v",), "floating-point-to-unsigned-integer"),
    (("vnclip.wi",), "signed-fixed-point"),
    (("vncvt.x.x.w", "vwcvt.x.x.v"), "signed-integer"),
    (("vwcvtu.x.x.v",), "unsigned-integer"),
    (("vsext.vf2", "vsext.vf4", "vsext.vf8"), "signed-extension"),
    (("vzext.vf2", "vzext.vf4", "vzext.vf8"), "zero-extension"),
    (("vwadd.vv", "vwadd.wv"), "signed-widen-add"),
    (("vwaddu.vx", "vwaddu.wv"), "unsigned-widen-add"),
    (("vwmacc.vv", "vwmacc.vx", "vwmul.vv", "vwmul.vx"), "signed-widen-multiply"),
    (("vwmulu.vv", "vwmulu.vx"), "unsigned-widen-multiply"),
    (("vwmulsu.vv",), "signed-times-unsigned-widen-multiply"),
), fact_name="signedness")

_EXPLICIT_ROUNDING = _expand_semantic_groups((
    (("vfncvt.f.f.w", "vfncvt.f.xu.w", "vfncvt.x.f.w"), "architectural-frm"),
    (("vnclip.wi",), "architectural-vxrm"),
    (("vncvt.x.x.w", "vnsra.wi", "vnsrl.wi"), "exact-integer"),
), fact_name="rounding")

# 每个 _add 数据行必须显式选择 validation_kind；该 kind 在这里同时绑定
# 操作数角色、有符号性和舍入合同。这样同一组可共享结构 validator，但不会
# 通过 opcode 后缀猜测关键语义。更细的 vv/vx/vi 差异由各显式 handler 保留。
_SEMANTIC_AXES_BY_VALIDATION_KIND = {
    "config-literal": _SemanticAxes(("rd", "rs1", "sew", "lmul", "tail", "mask"), _NOT_APPLICABLE, _NOT_APPLICABLE),
    "config-immediate": _SemanticAxes(("rd", "uimm5", "sew", "lmul", "tail", "mask"), _NOT_APPLICABLE, _NOT_APPLICABLE),
    "config-dynamic": _SemanticAxes(("rd", "rs1", "rs2"), _NOT_APPLICABLE, _NOT_APPLICABLE),
    "csr-read": _SemanticAxes(("rd", "csr"), _NOT_APPLICABLE, _NOT_APPLICABLE),
    "csr-write": _SemanticAxes(("rd-or-csr", "csr-or-source", "source-if-rmw"), "bitfield", _EXACT_INTEGER),
    "move-simm5": _SemanticAxes(("vd", "simm5"), "bit-preserving", _EXACT_INTEGER),
    "same-width": _SemanticAxes(("destination", "source-1", "source-2-if-present"), None, _EXACT_INTEGER),
    "integer-same-width": _SemanticAxes(("vd", "vs2", "vector-scalar-or-immediate"), None, _EXACT_INTEGER),
    "float-move": _SemanticAxes(("destination", "source"), "floating-point", _NOT_APPLICABLE),
    "float-same-width": _SemanticAxes(("vd", "vs2", "vector-or-fp-scalar"), "floating-point", _ARCHITECTURAL_FRM),
    "float-convert-widen": _SemanticAxes(("wide-vd", "narrow-vs2"), None, _ARCHITECTURAL_FRM),
    "float-widen": _SemanticAxes(("wide-vd", "narrow-source-1", "narrow-source-2"), "floating-point", _ARCHITECTURAL_FRM),
    "reduction": _SemanticAxes(("vd-m1", "vs2-lmul", "vs1-m1"), None, _EXACT_INTEGER),
    "float-reduction": _SemanticAxes(("vd-m1", "vs2-lmul", "vs1-m1"), "floating-point", _ARCHITECTURAL_FRM),
    "float-reduction-widen": _SemanticAxes(("wide-vd-m1", "narrow-vs2-lmul", "wide-vs1-m1"), "floating-point", _ARCHITECTURAL_FRM),
    "integer-reduction-widen": _SemanticAxes(("wide-vd-m1", "narrow-vs2-lmul", "wide-vs1-m1"), "signed-integer", _EXACT_INTEGER),
    "integer-widen": _SemanticAxes(("wide-vd", "narrow-source-1", "narrow-source-2"), None, _EXACT_INTEGER),
    "integer-widen-immediate": _SemanticAxes(("wide-vd", "narrow-vs2", "uimm5"), None, _EXACT_INTEGER),
    "integer-wide-narrow": _SemanticAxes(("wide-vd", "wide-vs2", "narrow-vs1"), None, _EXACT_INTEGER),
    "extend-2": _SemanticAxes(("vd", "narrow-vs2"), None, _EXACT_INTEGER),
    "extend-4": _SemanticAxes(("vd", "narrow-vs2"), None, _EXACT_INTEGER),
    "extend-8": _SemanticAxes(("vd", "narrow-vs2"), None, _EXACT_INTEGER),
    "narrow": _SemanticAxes(("narrow-vd", "wide-vs2"), None, None),
    "narrow-immediate": _SemanticAxes(("narrow-vd", "wide-vs2", "uimm5"), None, None),
    "gather": _SemanticAxes(("vd", "vs2", "index-vector"), "unsigned-index", _EXACT_INTEGER),
    "gather-e16-index": _SemanticAxes(("vd", "vs2", "e16-index-vector"), "unsigned-index", _EXACT_INTEGER),
    "slide": _SemanticAxes(("vd", "vs2", "offset-or-scalar"), "unsigned-offset", _EXACT_INTEGER),
    "slide-immediate": _SemanticAxes(("vd", "vs2", "uimm5"), "unsigned-offset", _EXACT_INTEGER),
    "slide-non-overlap": _SemanticAxes(("vd", "vs2", "scalar"), "bit-preserving", _EXACT_INTEGER),
    "mask-single": _SemanticAxes(("mask-destination-or-source",), "mask-bit", _EXACT_INTEGER),
    "mask-all": _SemanticAxes(("mask-destination",), "mask-bit", _EXACT_INTEGER),
    "mask-scan": _SemanticAxes(("rd", "mask-source"), "mask-bit", _EXACT_INTEGER),
    "mask-compare": _SemanticAxes(("mask-vd", "vs2", "vector-scalar-or-immediate"), None, _EXACT_INTEGER),
    "mask-merge": _SemanticAxes(("vd", "vs2", "vector-scalar-or-immediate", "v0-selector"), None, _EXACT_INTEGER),
    "memory-unit": _SemanticAxes(("vector-data", "base"), _NOT_APPLICABLE, _NOT_APPLICABLE),
    "memory-strided": _SemanticAxes(("vector-data", "base", "byte-stride"), "signed-byte-stride", _NOT_APPLICABLE),
    "memory-indexed": _SemanticAxes(("vector-data", "base", "index-vector"), "unsigned-byte-index", _NOT_APPLICABLE),
    "memory-segment": _SemanticAxes(("vector-tuple", "base", "stride-if-present"), None, _NOT_APPLICABLE),
    "whole-move": _SemanticAxes(("raw-vd", "raw-vs2"), "bit-preserving", _NOT_APPLICABLE),
    "whole-memory": _SemanticAxes(("raw-vector-group", "base"), "bit-preserving", _NOT_APPLICABLE),
}

_TARGET_MNEMONIC_OVERRIDES = {
    "vnot.v": "vxor.vi",
    "vandn.vv": "vxor.vi+vand.vv",
}


# TransitionLoweringMetadata / lowering_metadata() 的唯一定义位于
# riscv.extensions.rvv.backends.rvv1024_transition.lowering_metadata；本模块经顶部 import 复用并
# 保持原有公开名（__all__），registry 消费方不需要第二份类型来源。


_SEEDS: dict[str, _Seed] = {}


def _add(
    opcodes: Iterable[str],
    *,
    category: str,
    form: str,
    operand_count: int,
    validation_kind: str,
    builder_kind: str = "explicit",
    operand_order: tuple[str, ...] | None = None,
    mask_policy: MaskPolicy = MaskPolicy.FORBIDDEN,
    supported_sews: frozenset[int] = _ALL_SEWS,
    supported_lmuls: frozenset[float] = _ALL_LMULS,
    tail_policy: TailPolicy = TailPolicy.UNDISTURBED,
    reads_old_vd: bool = False,
    vtype_independent: bool = False,
) -> None:
    """登记一组共享完全相同结构语义的 opcode，并拒绝重复事实。"""

    try:
        axes = _SEMANTIC_AXES_BY_VALIDATION_KIND[validation_kind]
    except KeyError as exc:
        raise ValueError(
            f"RVV1024 过渡规格缺少 validation kind 语义轴: {validation_kind}"
        ) from exc

    for opcode in opcodes:
        if opcode in _SEEDS:
            raise ValueError(f"RVV1024 过渡规格重复声明 opcode: {opcode}")
        if axes.signedness is None:
            try:
                concrete_signedness = _EXPLICIT_SIGNEDNESS[opcode]
            except KeyError as exc:
                raise ValueError(f"{opcode} 缺少实际 signedness 声明") from exc
        else:
            concrete_signedness = axes.signedness
        if axes.rounding_policy is None:
            try:
                concrete_rounding = _EXPLICIT_ROUNDING[opcode]
            except KeyError as exc:
                raise ValueError(f"{opcode} 缺少实际 rounding policy 声明") from exc
        else:
            concrete_rounding = axes.rounding_policy
        _SEEDS[opcode] = _Seed(
            opcode=opcode,
            category=category,
            form=form,
            operand_count=operand_count,
            validation_kind=validation_kind,
            builder_kind=builder_kind,
            mask_policy=mask_policy,
            supported_sews=supported_sews,
            supported_lmuls=supported_lmuls,
            tail_policy=tail_policy,
            reads_old_vd=reads_old_vd,
            vtype_independent=vtype_independent,
            operand_order=axes.operand_order if operand_order is None else operand_order,
            signedness=concrete_signedness,
            rounding_policy=concrete_rounding,
            target_mnemonic=_TARGET_MNEMONIC_OVERRIDES.get(opcode, opcode),
        )


# 配置指令的输入 vtype 与自身语义无关；validator 在 clone 上检查字面输出
# vtype，避免 prepare 污染随后指令的线性状态。
_add(
    ("vsetvli",),
    category="config",
    form="rd, rs1, eSEW, LMUL, tail, mask",
    operand_count=6,
    validation_kind="config-literal",
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
)
_add(
    ("vsetivli",),
    category="config",
    form="rd, uimm5, eSEW, LMUL, tail, mask",
    operand_count=6,
    validation_kind="config-immediate",
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
)
_add(
    ("vsetvl",),
    category="config",
    form="rd, rs1, rs2",
    operand_count=3,
    validation_kind="config-dynamic",
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
)


# 基础等宽整数族。form 在数据行中显式分组，公共 builder 只读取这里选择的
# ``builder_kind`` 和 ``target_mnemonic``，绝不根据 ``.vv/.vx/.vi`` 后缀猜测。
_add(
    ("vadd.vv", "vsub.vv", "vand.vv", "vor.vv", "vxor.vv", "vsll.vv", "vsrl.vv", "vmul.vv"),
    category="integer-same-width",
    form="vd, vs2, vs1[, v0.t]",
    operand_count=3,
    validation_kind="integer-same-width",
    builder_kind="integer-vv",
    operand_order=("vd", "vs2", "vs1"),
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vadd.vx", "vsub.vx", "vand.vx", "vor.vx", "vsll.vx", "vsrl.vx", "vmul.vx"),
    category="integer-same-width",
    form="vd, vs2, rs1[, v0.t]",
    operand_count=3,
    validation_kind="integer-same-width",
    builder_kind="integer-vx",
    operand_order=("vd", "vs2", "rs1"),
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vadd.vi", "vand.vi", "vor.vi", "vrsub.vi"),
    category="integer-same-width",
    form="vd, vs2, simm5[, v0.t]",
    operand_count=3,
    validation_kind="integer-same-width",
    builder_kind="integer-vi",
    operand_order=("vd", "vs2", "simm5"),
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vsll.vi", "vsrl.vi", "vsra.vi"),
    category="integer-same-width",
    form="vd, vs2, uimm5[, v0.t]",
    operand_count=3,
    validation_kind="integer-same-width",
    builder_kind="integer-shift-vi",
    operand_order=("vd", "vs2", "uimm5"),
    mask_policy=MaskPolicy.V0_ONLY,
)

_add(
    ("vmv.v.i",),
    category="integer-move",
    form="vd, simm5",
    operand_count=2,
    validation_kind="move-simm5",
)
_add(
    ("vmv.v.x", "vmv.v.v", "vmv.s.x"),
    category="integer-move",
    form="destination, source",
    operand_count=2,
    validation_kind="same-width",
)
_add(
    ("vmv.x.s",),
    category="integer-move",
    form="rd, vs2",
    operand_count=2,
    validation_kind="same-width",
    tail_policy=TailPolicy.NOT_APPLICABLE,
)
_add(
    ("vfmv.v.f", "vfmv.s.f"),
    category="float-move",
    form="destination, source",
    operand_count=2,
    validation_kind="float-move",
    supported_sews=_FLOAT_SEWS,
)
_add(
    ("vfmv.f.s",),
    category="float-move",
    form="fp-rd, vs2",
    operand_count=2,
    validation_kind="float-move",
    supported_sews=_FLOAT_SEWS,
    tail_policy=TailPolicy.NOT_APPLICABLE,
)


_add(
    ("vfmul.vv", "vfadd.vv"),
    category="float-same-width",
    form="vd, vs2, vs1[, v0.t]",
    operand_count=3,
    validation_kind="float-same-width",
    builder_kind="float-binary-vv",
    operand_order=("vd", "vs2", "vs1"),
    supported_sews=_FLOAT_SEWS,
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vfsub.vv", "vfdiv.vv", "vfmax.vv", "vfmin.vv"),
    category="float-same-width",
    form="vd, vs2, vs1",
    operand_count=3,
    validation_kind="float-same-width",
    builder_kind="float-binary-vv",
    operand_order=("vd", "vs2", "vs1"),
    supported_sews=_FLOAT_SEWS,
)
_add(
    ("vfmul.vf", "vfadd.vf"),
    category="float-same-width",
    form="vd, vs2, fs1[, v0.t]",
    operand_count=3,
    validation_kind="float-same-width",
    builder_kind="float-binary-vf",
    operand_order=("vd", "vs2", "fs1"),
    supported_sews=_FLOAT_SEWS,
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vfsub.vf", "vfrsub.vf"),
    category="float-same-width",
    form="vd, vs2, fs1",
    operand_count=3,
    validation_kind="float-same-width",
    builder_kind="float-binary-vf",
    operand_order=("vd", "vs2", "fs1"),
    supported_sews=_FLOAT_SEWS,
)
_add(
    ("vfmacc.vv", "vfmadd.vv", "vfmsub.vv", "vfmsac.vv"),
    category="float-fused",
    form="vd, vs1, vs2",
    operand_count=3,
    validation_kind="float-same-width",
    builder_kind="float-fused-vv",
    operand_order=("vd", "vs1", "vs2"),
    supported_sews=_FLOAT_SEWS,
    reads_old_vd=True,
)
_add(
    ("vfmacc.vf", "vfnmsac.vf", "vfmadd.vf"),
    category="float-fused",
    form="vd, fs1, vs2",
    operand_count=3,
    validation_kind="float-same-width",
    builder_kind="float-fused-vf",
    operand_order=("vd", "fs1", "vs2"),
    supported_sews=_FLOAT_SEWS,
    reads_old_vd=True,
)


_add(
    ("vfcvt.f.x.v", "vfcvt.x.f.v"),
    category="float-convert",
    form="vd, vs2[, v0.t]",
    operand_count=2,
    validation_kind="float-same-width",
    builder_kind="equal-width-float-convert",
    operand_order=("vd", "vs2"),
    supported_sews=_FLOAT_SEWS,
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vfcvt.f.xu.v", "vfcvt.xu.f.v"),
    category="float-convert",
    form="vd, vs2",
    operand_count=2,
    validation_kind="float-same-width",
    builder_kind="equal-width-float-convert",
    operand_order=("vd", "vs2"),
    supported_sews=_FLOAT_SEWS,
)
_add(
    (
        "vfwcvt.f.f.v", "vfwcvt.f.x.v", "vfwcvt.f.xu.v",
        "vfwcvt.x.f.v", "vfwcvt.xu.f.v",
    ),
    category="float-convert-widen",
    form="wide vd, narrow vs2",
    operand_count=2,
    validation_kind="float-convert-widen",
    supported_sews=_WIDEN_FLOAT_SEWS,
)


_add(
    ("vmacc.vv", "vmadd.vv"),
    category="integer-accumulate",
    form="vd, vs1, vs2",
    operand_count=3,
    validation_kind="same-width",
    builder_kind="integer-accumulate-vv",
    operand_order=("vd", "vs1", "vs2"),
    reads_old_vd=True,
)
_add(
    ("vmacc.vx", "vmadd.vx"),
    category="integer-accumulate",
    form="vd, rs1, vs2",
    operand_count=3,
    validation_kind="same-width",
    builder_kind="integer-accumulate-vx",
    operand_order=("vd", "rs1", "vs2"),
    reads_old_vd=True,
)
_add(
    ("vdiv.vx",),
    category="integer-same-width",
    form="vd, vs2, rs1",
    operand_count=3,
    validation_kind="same-width",
    builder_kind="plain-integer-vx",
    operand_order=("vd", "vs2", "rs1"),
)
_add(
    ("vmax.vv", "vmaxu.vv"),
    category="integer-same-width",
    form="vd, vs2, vs1",
    operand_count=3,
    validation_kind="same-width",
    builder_kind="plain-integer-vv",
    operand_order=("vd", "vs2", "vs1"),
)
_add(
    ("vandn.vv",),
    category="integer-same-width",
    form="vd, vs2, vs1",
    operand_count=3,
    validation_kind="same-width",
)
_add(
    ("vnot.v",),
    category="integer-unary",
    form="vd, vs2",
    operand_count=2,
    validation_kind="same-width",
)
_add(
    ("vid.v",),
    category="integer-index",
    form="vd",
    operand_count=1,
    validation_kind="same-width",
)
_add(
    ("vfneg.v",),
    category="float-unary",
    form="vd, vs2[, v0.t]",
    operand_count=2,
    validation_kind="float-same-width",
    builder_kind="float-unary",
    operand_order=("vd", "vs2"),
    supported_sews=_FLOAT_SEWS,
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vfabs.v",),
    category="float-unary",
    form="vd, vs2",
    operand_count=2,
    validation_kind="float-same-width",
    builder_kind="float-unary",
    operand_order=("vd", "vs2"),
    supported_sews=_FLOAT_SEWS,
)
_add(
    ("vredsum.vs", "vredor.vs", "vredmaxu.vs"),
    category="integer-reduction",
    form="vd(m1), vs2(LMUL), vs1(m1)",
    operand_count=3,
    validation_kind="reduction",
    builder_kind="integer-reduction",
    operand_order=("vd-m1", "vs2-lmul", "vs1-m1"),
    reads_old_vd=True,
)
_add(
    ("vfredusum.vs", "vfredmax.vs", "vfredmin.vs"),
    category="float-reduction",
    form="vd(m1), vs2(LMUL), vs1(m1)",
    operand_count=3,
    validation_kind="float-reduction",
    supported_sews=_FLOAT_SEWS,
    reads_old_vd=True,
)
_add(
    ("vfwredusum.vs", "vfwredosum.vs"),
    category="float-reduction-widen",
    form="wide vd(m1), narrow vs2(LMUL), wide vs1(m1)",
    operand_count=3,
    validation_kind="float-reduction-widen",
    supported_sews=_WIDEN_FLOAT_SEWS,
    reads_old_vd=True,
)
_add(
    ("vfwmacc.vv", "vfwmul.vf"),
    category="float-widen",
    form="wide vd, narrow vector/scalar sources",
    operand_count=3,
    validation_kind="float-widen",
    supported_sews=_WIDEN_FLOAT_SEWS,
    reads_old_vd=True,
)


# 整数宽化/窄化。各表项明确标出 data width 方向，不根据 mnemonic 中的
# 字母组合猜测 EMUL。
_add(
    ("vwmul.vv", "vwmul.vx", "vwmulu.vv", "vwmulu.vx", "vwmulsu.vv"),
    category="integer-widen",
    form="wide vd, narrow vector/scalar sources",
    operand_count=3,
    validation_kind="integer-widen",
    supported_sews=frozenset({8, 16, 32}),
)
_add(
    ("vwmacc.vv", "vwmacc.vx"),
    category="integer-widen-accumulate",
    form="wide vd, narrow vector/scalar sources[, v0.t]",
    operand_count=3,
    validation_kind="integer-widen",
    mask_policy=MaskPolicy.V0_ONLY,
    supported_sews=frozenset({8, 16, 32}),
    reads_old_vd=True,
)
_add(
    ("vwadd.vv",),
    category="integer-widen",
    form="wide vd, narrow vs2, narrow vs1",
    operand_count=3,
    validation_kind="integer-widen",
    supported_sews=frozenset({8, 16, 32}),
)
_add(
    ("vwadd.wv", "vwaddu.wv"),
    category="integer-wide-narrow",
    form="wide vd, wide vs2, narrow vs1",
    operand_count=3,
    validation_kind="integer-wide-narrow",
    supported_sews=frozenset({8, 16, 32}),
)
_add(
    ("vwaddu.vx",),
    category="integer-widen",
    form="wide vd, narrow vs2, scalar source",
    operand_count=3,
    validation_kind="integer-widen",
    supported_sews=frozenset({8, 16, 32}),
)
_add(
    ("vwredsum.vs",),
    category="integer-reduction-widen",
    form="wide vd(m1), narrow vs2(LMUL), wide vs1(m1)[, v0.t]",
    operand_count=3,
    validation_kind="integer-reduction-widen",
    mask_policy=MaskPolicy.V0_ONLY,
    supported_sews=frozenset({8, 16, 32}),
    reads_old_vd=True,
)


_add(
    ("vzext.vf2", "vsext.vf2"),
    category="integer-extend",
    form="vd, narrow vs2 (factor 2)",
    operand_count=2,
    validation_kind="extend-2",
)
_add(
    ("vzext.vf4", "vsext.vf4"),
    category="integer-extend",
    form="vd, narrow vs2 (factor 4)",
    operand_count=2,
    validation_kind="extend-4",
)
_add(
    ("vzext.vf8", "vsext.vf8"),
    category="integer-extend",
    form="vd, narrow vs2 (factor 8)",
    operand_count=2,
    validation_kind="extend-8",
)
_add(
    ("vnsrl.wi", "vnsra.wi", "vnclip.wi"),
    category="integer-narrow",
    form="narrow vd, wide vs2, uimm5",
    operand_count=3,
    validation_kind="narrow-immediate",
    supported_sews=frozenset({8, 16, 32}),
)
_add(
    ("vwcvtu.x.x.v", "vwcvt.x.x.v"),
    category="integer-convert-widen",
    form="wide vd, narrow vs2",
    operand_count=2,
    validation_kind="integer-widen",
    supported_sews=frozenset({8, 16, 32}),
)
_add(
    ("vwsll.vi",),
    category="integer-shift-widen",
    form="wide vd, narrow vs2, uimm5",
    operand_count=3,
    validation_kind="integer-widen-immediate",
    supported_sews=frozenset({8, 16, 32}),
)
_add(
    ("vfncvt.f.f.w",),
    category="convert-narrow",
    form="narrow vd, wide vs2[, v0.t]",
    operand_count=2,
    validation_kind="narrow",
    supported_sews=frozenset({8, 16, 32}),
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vncvt.x.x.w", "vfncvt.f.xu.w", "vfncvt.x.f.w"),
    category="convert-narrow",
    form="narrow vd, wide vs2",
    operand_count=2,
    validation_kind="narrow",
    supported_sews=frozenset({8, 16, 32}),
)


_add(
    ("vrgather.vv",),
    category="gather",
    form="vd, data vs2, index vs1",
    operand_count=3,
    validation_kind="gather",
)
_add(
    ("vrgatherei16.vv",),
    category="gather",
    form="vd, data vs2, e16-index vs1",
    operand_count=3,
    validation_kind="gather-e16-index",
)
_add(
    ("vslidedown.vi",),
    category="slide",
    form="vd, vs2, uimm5[, v0.t]",
    operand_count=3,
    validation_kind="slide-immediate",
    reads_old_vd=True,
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vslideup.vi",),
    category="slide",
    form="vd, vs2, uimm5",
    operand_count=3,
    validation_kind="slide-immediate",
    reads_old_vd=True,
)
_add(
    ("vslidedown.vx", "vslide1down.vx"),
    category="slide",
    form="vd, vs2, rs1",
    operand_count=3,
    validation_kind="slide",
    reads_old_vd=True,
)
_add(
    ("vslide1up.vx",),
    category="slide",
    form="non-overlapping vd, vs2, rs1",
    operand_count=3,
    validation_kind="slide-non-overlap",
    reads_old_vd=True,
)


# Mask 指令的数据源 LMUL 与 bit-packed mask 源不同，故单独声明验证类别。
_add(
    ("vlm.v",),
    category="mask-load",
    form="vd(mask), (rs1)",
    operand_count=2,
    validation_kind="mask-single",
)
_add(
    (
        "vmseq.vi", "vmseq.vx", "vmsne.vv", "vmsne.vi", "vmsne.vx",
        "vmsle.vi", "vmsgtu.vi", "vmsgtu.vx", "vmsleu.vi", "vmsleu.vv",
        "vmsltu.vv", "vmsltu.vx", "vmfgt.vf", "vmfle.vf", "vmfne.vf",
    ),
    category="mask-compare",
    form="mask vd, data vs2, vector/scalar/immediate source",
    operand_count=3,
    validation_kind="mask-compare",
)
_add(
    ("vmclr.m",),
    category="mask-logic",
    form="mask vd",
    operand_count=1,
    validation_kind="mask-single",
)
_add(
    ("vmor.mm", "vmand.mm"),
    category="mask-logic",
    form="mask vd, mask vs2, mask vs1",
    operand_count=3,
    validation_kind="mask-all",
)
_add(
    ("vmnot.m",),
    category="mask-logic",
    form="mask vd, mask vs2",
    operand_count=2,
    validation_kind="mask-all",
)
_add(
    ("vfirst.m", "vcpop.m"),
    category="mask-scan",
    form="rd, mask vs2",
    operand_count=2,
    validation_kind="mask-scan",
    tail_policy=TailPolicy.NOT_APPLICABLE,
)
_add(
    ("vmerge.vvm", "vmerge.vxm", "vmerge.vim"),
    category="mask-merge",
    form="vd, vs2, vector/scalar/immediate source, v0",
    operand_count=4,
    validation_kind="mask-merge",
    reads_old_vd=True,
)


# 内存表明确列出 EEW/NF 与访问 form；validator 通过这些静态表计算 EMUL，
# 不解析 mnemonic 文本。
_MEMORY_EEW: dict[str, int] = {}
for _eew in (8, 16, 32, 64):
    for _opcode in (f"vle{_eew}.v", f"vse{_eew}.v"):
        _MEMORY_EEW[_opcode] = _eew
_add(
    ("vle8.v", "vle16.v", "vle32.v", "vle64.v"),
    category="memory-load",
    form="vd, (rs1)[, v0.t]",
    operand_count=2,
    validation_kind="memory-unit",
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vse8.v", "vse16.v", "vse32.v", "vse64.v"),
    category="memory-store",
    form="vs3, (rs1)[, v0.t]",
    operand_count=2,
    validation_kind="memory-unit",
    mask_policy=MaskPolicy.V0_ONLY,
    tail_policy=TailPolicy.NOT_APPLICABLE,
)

for _eew in (8, 16, 32, 64):
    for _opcode in (f"vlse{_eew}.v", f"vsse{_eew}.v"):
        _MEMORY_EEW[_opcode] = _eew
_add(
    ("vlse64.v",),
    category="memory-load-strided",
    form="vd, (rs1), rs2[, v0.t]",
    operand_count=3,
    validation_kind="memory-strided",
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vlse8.v", "vlse16.v", "vlse32.v"),
    category="memory-load-strided",
    form="vd, (rs1), rs2",
    operand_count=3,
    validation_kind="memory-strided",
)
_add(
    ("vsse32.v", "vsse64.v"),
    category="memory-store-strided",
    form="vs3, (rs1), rs2[, v0.t]",
    operand_count=3,
    validation_kind="memory-strided",
    tail_policy=TailPolicy.NOT_APPLICABLE,
    mask_policy=MaskPolicy.V0_ONLY,
)
_add(
    ("vsse8.v", "vsse16.v"),
    category="memory-store-strided",
    form="vs3, (rs1), rs2",
    operand_count=3,
    validation_kind="memory-strided",
    tail_policy=TailPolicy.NOT_APPLICABLE,
)

_INDEX_EEW = {"vluxei16.v": 16, "vluxei64.v": 64}
_add(
    tuple(_INDEX_EEW),
    category="memory-load-indexed",
    form="vd, (rs1), index vs2",
    operand_count=3,
    validation_kind="memory-indexed",
)

_SEGMENT_SHAPES = {
    "vlseg2e32.v": (32, 2, True, False),
    "vlseg2e64.v": (64, 2, True, False),
    "vsseg2e32.v": (32, 2, False, False),
    "vsseg2e64.v": (64, 2, False, False),
    "vsseg4e64.v": (64, 4, False, False),
    "vlsseg2e32.v": (32, 2, True, True),
    "vlsseg2e64.v": (64, 2, True, True),
    "vssseg2e32.v": (32, 2, False, True),
    "vssseg2e64.v": (64, 2, False, True),
}
for _opcode, (_eew, _nf, _is_load, _is_strided) in _SEGMENT_SHAPES.items():
    _add(
        (_opcode,),
        category="memory-segment-load" if _is_load else "memory-segment-store",
        form="first vreg, (rs1), rs2" if _is_strided else "first vreg, (rs1)",
        operand_count=3 if _is_strided else 2,
        validation_kind="memory-segment",
        tail_policy=TailPolicy.UNDISTURBED if _is_load else TailPolicy.NOT_APPLICABLE,
    )

_add(
    ("vsm.v",),
    category="memory-mask-store",
    form="mask vs3, (rs1)",
    operand_count=2,
    validation_kind="mask-single",
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
)

_add(
    ("vmv1r.v", "vmv2r.v", "vmv4r.v", "vmv8r.v"),
    category="whole-register-move",
    form="vd, vs2",
    operand_count=2,
    validation_kind="whole-move",
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
)
_add(
    (
        "vl1r.v", "vl1re16.v", "vl1re32.v", "vl1re64.v", "vl2r.v",
        "vl2re16.v", "vl2re32.v", "vl4r.v", "vl4re16.v", "vl4re32.v",
        "vl4re64.v", "vl8r.v", "vl8re32.v", "vl8re64.v",
    ),
    category="whole-register-load",
    form="vd, (rs1)",
    operand_count=2,
    validation_kind="whole-memory",
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
)
_add(
    ("vs1r.v", "vs2r.v", "vs4r.v", "vs8r.v"),
    category="whole-register-store",
    form="vs3, (rs1)",
    operand_count=2,
    validation_kind="whole-memory",
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
)
_MEMORY_EEW["vle8ff.v"] = 8
_add(
    ("vle8ff.v",),
    category="memory-fof-load",
    form="vd, (rs1)",
    operand_count=2,
    validation_kind="memory-unit",
)


# vector CSR 在普通 parser 中属于标量指令，但必须由过渡后端截获。每个
# pseudo/base form 都有自己的显式规格，且完全不依赖 source vtype。
_add(
    ("csrr",),
    category="csr-read",
    form="rd, vector-csr",
    operand_count=2,
    validation_kind="csr-read",
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
)
_add(
    tuple(sorted(_VECTOR_CSR_WRITE_OR_RMW_OPCODES)),
    category="csr-write",
    form="vector-csr write/read-modify-write form",
    operand_count=3,
    validation_kind="csr-write",
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
)


_LOWERING_MODULES = (
    arithmetic_handler,
    config_handler,
    convert,
    csr_handler,
    gather,
    mask_handler,
    memory,
    reduction_handler,
    slide,
    widen,
)


def _resolve_lowering(seed: _Seed) -> TransitionLoweringMetadata:
    """把 seed 绑定到唯一 builder；重复或缺失在模块导入期立即失败。"""

    # 简单指令族由 builder_kind 显式选择模板。partial 只绑定实现函数与
    # 已声明的立即数策略，不从 opcode 字符串推测符号性、operand form、
    # mask/tail、舍入或 vstart 语义。
    with_opcode = arithmetic_handler.build_with_opcode
    shared_builders = {
        "integer-vv": partial(with_opcode, emitter=arithmetic_handler._emit_vv),
        "integer-vx": partial(with_opcode, emitter=arithmetic_handler._emit_vx),
        "integer-vi": partial(with_opcode, emitter=arithmetic_handler._emit_vi),
        "integer-shift-vi": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_vi,
            shift=True,
        ),
        "float-binary-vv": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_float_binary_vv,
        ),
        "float-binary-vf": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_float_binary_vf,
        ),
        "float-fused-vv": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_float_accumulate_vv,
        ),
        "float-fused-vf": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_float_accumulate_vf,
        ),
        "equal-width-float-convert": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_equal_width_vfcvt,
        ),
        "integer-accumulate-vv": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_integer_accumulate_vv,
        ),
        "integer-accumulate-vx": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_integer_accumulate_vx,
        ),
        "plain-integer-vv": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_plain_integer_vv,
        ),
        "plain-integer-vx": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_plain_integer_vx,
        ),
        "float-unary": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_float_unary,
        ),
        "integer-reduction": partial(
            with_opcode,
            emitter=arithmetic_handler._emit_integer_reduction_vs,
        ),
    }
    if seed.category == "memory-load" and seed.opcode != "vle8ff.v":
        builder = partial(
            memory.build_unit_load_lines,
            eew=_MEMORY_EEW[seed.opcode],
        )
    elif seed.category == "memory-store":
        builder = partial(
            memory.build_unit_store_lines,
            eew=_MEMORY_EEW[seed.opcode],
        )
    elif seed.category == "memory-load-strided":
        builder = partial(
            memory.build_strided_load_lines,
            eew=_MEMORY_EEW[seed.opcode],
        )
    elif seed.category == "memory-store-strided":
        builder = partial(
            memory.build_strided_store_lines,
            eew=_MEMORY_EEW[seed.opcode],
        )
    elif seed.category == "memory-load-indexed":
        builder = partial(
            memory.build_indexed_load_lines,
            index_eew=_INDEX_EEW[seed.opcode],
        )
    elif seed.category in {"memory-segment-load", "memory-segment-store"}:
        eew, field_count, is_load, is_strided = _SEGMENT_SHAPES[seed.opcode]
        builder = partial(
            memory.build_segment_memory_lines,
            eew=eew,
            field_count=field_count,
            is_load=is_load,
            is_strided=is_strided,
        )
    elif seed.category in {"whole-register-load", "whole-register-store"}:
        builder = partial(
            memory.build_whole_memory_lines,
            factor=_WHOLE_FACTORS[seed.opcode],
            is_load=seed.category == "whole-register-load",
        )
    elif seed.category == "whole-register-move":
        builder = partial(
            memory.build_whole_move_lines,
            factor=_WHOLE_FACTORS[seed.opcode],
        )
    elif seed.builder_kind in shared_builders:
        builder = shared_builders[seed.builder_kind]
    elif seed.builder_kind != "explicit":
        raise ValueError(
            f"{seed.opcode} 声明了未知 builder_kind: {seed.builder_kind}"
        )
    elif seed.category == "csr-write":
        builder = _build_vector_csr_write_lines
    else:
        symbol = f"_build_{seed.opcode.replace('.', '_')}_lines"
        matches = [
            getattr(module, symbol)
            for module in _LOWERING_MODULES
            if hasattr(module, symbol)
        ]
        if len(matches) != 1:
            raise ValueError(
                f"{seed.opcode} 必须恰好绑定一个过渡 builder，实际为 {len(matches)}"
            )
        (builder,) = matches

    return TransitionLoweringMetadata(builder=builder)


# 标量语义结果事实：SCALAR_RESULT_OPCODES 的第一个操作数是写入的 GPR 结果，
# vfmv.f.s 的第一个操作数是 FPR 结果。解析机制由 riscv.extensions.rvv.translation.specs
# 唯一提供，这里只声明数据。
_semantic_outputs, _semantic_inputs = make_scalar_result_resolvers(
    gpr_result_opcodes=SCALAR_RESULT_OPCODES,
    fpr_result_opcodes=frozenset({"vfmv.f.s"}),
)


def _state_sets(seed: _Seed) -> tuple[frozenset[str], frozenset[str]]:
    if seed.category == "config":
        return frozenset({"vl", "vtype", "vlenb"}), frozenset({"vl", "vtype", "vstart"})
    if seed.category == "csr-read":
        return frozenset({"vector-csr"}), frozenset()
    if seed.category == "csr-write":
        return frozenset({"vector-csr"}), frozenset({"vector-csr"})
    writes = {"vstart"}
    if seed.rounding_policy == "architectural-vxrm":
        writes.add("vcsr")
    if "store" not in seed.category and seed.category not in {"mask-scan"}:
        writes.add("vreg")
    return frozenset({"vl", "vtype", "vreg", "vcsr", "vstart"}), frozenset(writes)


def build_transition_registry() -> HandlerRegistry:
    """构造全局稳定 registry；同一 plan 可被不同发射轮的 dispatcher 复用。"""

    registry = HandlerRegistry()
    for opcode in sorted(_SEEDS):
        seed = _SEEDS[opcode]
        state_reads, state_writes = _state_sets(seed)
        registry.register(InstructionSpec(
            opcode=seed.opcode,
            category=seed.category,
            operand_forms=(seed.form,),
            supported_sews=seed.supported_sews,
            supported_lmuls=seed.supported_lmuls,
            mask_policy=seed.mask_policy,
            tail_policy=seed.tail_policy,
            vstart_policy=(
                VStartPolicy.NOT_APPLICABLE
                if seed.category in {"config", "csr-read", "csr-write"}
                else VStartPolicy.REQUIRE_ZERO
            ),
            reads_old_vd=seed.reads_old_vd,
            vtype_independent=seed.vtype_independent,
            validator=_validator(seed, _MEMORY_EEW, _INDEX_EEW, _SEGMENT_SHAPES),
            lowerer=TRANSITION_LOWERER,
            semantic_inputs=_semantic_inputs,
            semantic_outputs=_semantic_outputs,
            state_reads=state_reads,
            state_writes=state_writes,
            scalar_instruction_matcher=(
                is_vector_csr_instruction
                if seed.category in {"csr-read", "csr-write"}
                else None
            ),
            target_mnemonic=seed.target_mnemonic,
            operand_order=seed.operand_order,
            signedness=seed.signedness,
            rounding_policy=seed.rounding_policy,
            lowering_metadata=_resolve_lowering(seed),
        ))
    return registry


TRANSITION_REGISTRY = build_transition_registry()


__all__ = [
    "SCALAR_RESULT_OPCODES",
    "TransitionLoweringMetadata",
    "TRANSITION_REGISTRY",
    "build_transition_registry",
]
