"""RVV1024→RVV256 后端的唯一指令规格表。

本模块显式登记每个 opcode 的 builder、操作数顺序、SEW/LMUL、掩码、tail、
``vstart``、有符号性和舍入策略。dispatcher、运行时 vtype 分发、宽路径与
支持文档都读取同一个 :class:`InstructionSpec` registry，不再各自维护白名单。

复杂 widening、reduction、segment memory 等指令仍保留独立 builder；只有确实
共享逐元素等宽循环的指令携带 :class:`RVV256SameWidthSpec`。因此数据驱动不会
合并有符号性、旧 ``vd``、掩码或舍入语义不同的实现。
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from types import ModuleType
from typing import Literal

from riscv.frontend.literals import parse_integer_literal
from riscv.extensions.rvv.analysis.model import LEGAL_LMULS
from riscv.extensions.rvv.backends.rvv256.handlers import config, mask, memory
from riscv.extensions.rvv.translation import vector_csr as csr
from riscv.extensions.rvv.backends.rvv256.handlers.arithmetic import (
    elementwise,
    floating_multiply,
    conversion,
    floating,
    integer,
    multiply,
    reduction,
    rearrange,
    widening,
)
from riscv.extensions.rvv.backends.rvv256.lowering import RVV256Lowerer
from riscv.extensions.rvv.backends.rvv256.lowering_metadata import (
    RVV256LoweringMetadata,
    RVV256SameWidthSpec,
)
from riscv.extensions.rvv.translation.specs import (
    expand_semantic_groups,
    make_scalar_result_resolvers,
)
from riscv.extensions.rvv.translation.lowering import AssemblyLineBuilder
from riscv.extensions.rvv.translation.contracts import (
    HandlerContext,
    InstructionSpec,
    InstructionValidationError,
    LoweringStatus,
    MaskPolicy,
    TailPolicy,
    VStartPolicy,
)
from riscv.extensions.rvv.translation.specs import HandlerRegistry
from riscv.extensions.rvv.translation.validation import validate_source_operands


_ALL_SEWS = frozenset({8, 16, 32, 64})
_FLOAT_SEWS = frozenset({16, 32, 64})
_WIDEN_FLOAT_SEWS = frozenset({16, 32})
_NARROW_DESTINATION_SEWS = frozenset({8, 16, 32})
_WIDEN_INTEGER_SEWS = frozenset({8, 16, 32})
_ALL_LMULS = frozenset(LEGAL_LMULS)
_MASK_BOTH = frozenset({"conservative", "wide"})
_MASK_WIDE = frozenset({"wide"})

# 算术包不再手工再导出一整张 builder 清单。规格构造只在明确的语义模块
# 集合中查找同名实现，并要求恰好命中一次，从而让文件移动与重复定义立即失败。
arithmetic = (
    elementwise,
    floating_multiply,
    conversion,
    floating,
    integer,
    multiply,
    reduction,
    rearrange,
    widening,
)


def _expand_semantic_groups(
    groups: tuple[tuple[tuple[str, ...], str], ...]
) -> dict[str, str]:
    """把显式 opcode 分组展开为逐 opcode 事实，并拒绝重复声明。"""

    return expand_semantic_groups(
        groups, backend_label="RVV256", fact_name="signedness"
    )


_EXPLICIT_SIGNEDNESS = _expand_semantic_groups((
    (("vadd.vi", "vadd.vv", "vadd.vx", "vsub.vv", "vsub.vx", "vrsub.vi", "vmul.vv", "vmul.vx"), "modular-integer"),
    (("vand.vi", "vand.vv", "vand.vx", "vor.vi", "vor.vv", "vor.vx", "vxor.vv", "vredor.vs"), "bitwise"),
    (("vsll.vi", "vsll.vv", "vsll.vx", "vsrl.vi", "vsrl.vv", "vsrl.vx", "vwsll.vi", "vnsrl.wi"), "logical-shift"),
    (("vsra.vi", "vnsra.wi"), "arithmetic-shift"),
    (("vdiv.vx", "vmax.vv"), "signed-integer"),
    (("vmaxu.vv", "vredmaxu.vs"), "unsigned-integer"),
    (("vredsum.vs",), "modular-reduction"),
    (("vmerge.vim", "vmerge.vvm", "vmerge.vxm"), "bit-preserving"),
    (("vmseq.vi", "vmseq.vx", "vmsne.vi", "vmsne.vv"), "equality-compare"),
    (("vmsgtu.vi", "vmsgtu.vx", "vmsleu.vi", "vmsleu.vv", "vmsltu.vv", "vmsltu.vx"), "unsigned-compare"),
    (("vmsle.vi",), "signed-compare"),
    (("vfcvt.f.x.v", "vfwcvt.f.x.v"), "signed-integer-to-floating-point"),
    (("vfcvt.f.xu.v", "vfncvt.f.xu.w"), "unsigned-integer-to-floating-point"),
    (("vfcvt.x.f.v", "vfncvt.x.f.w"), "floating-point-to-signed-integer"),
    (("vfncvt.f.f.w", "vfwcvt.f.f.v"), "floating-point"),
    (("vnclip.wi",), "signed-fixed-point"),
    (("vncvt.x.x.w", "vwcvt.x.x.v"), "signed-integer"),
    (("vwcvtu.x.x.v",), "unsigned-integer"),
    (("vsext.vf2", "vsext.vf4"), "signed-extension"),
    (("vzext.vf2", "vzext.vf4", "vzext.vf8"), "zero-extension"),
    (("vwadd.vv", "vwadd.wv"), "signed-widen-add"),
    (("vwaddu.vx", "vwaddu.wv"), "unsigned-widen-add"),
    (("vwmul.vv", "vwmul.vx"), "signed-widen-multiply"),
    (("vwmulu.vv", "vwmulu.vx"), "unsigned-widen-multiply"),
    (("vwmulsu.vv",), "signed-times-unsigned-widen-multiply"),
))


# RVV256SameWidthSpec / RVV256LoweringMetadata / lowering_metadata() 的唯一
# 定义位于 riscv.extensions.rvv.backends.rvv256.lowering_metadata；本模块经顶部 import 复用并保持
# 原有公开名（__all__），避免 registry 消费方出现第二份类型来源。


@dataclass(frozen=True, slots=True)
class _Seed:
    """构造 InstructionSpec 的 RVV256 静态事实。"""

    opcode: str
    category: str
    form: str
    operand_order: tuple[str, ...]
    operand_count: int
    builder: AssemblyLineBuilder | None
    supported_sews: frozenset[int]
    supported_lmuls: frozenset[float]
    mask_profiles: frozenset[str]
    tail_policy: TailPolicy
    vstart_policy: VStartPolicy
    reads_old_vd: bool
    vtype_independent: bool
    signedness: str
    rounding_policy: str
    target_mnemonic: str
    same_width: RVV256SameWidthSpec | None


_SEEDS: dict[str, _Seed] = {}


def _resolve_builder(
    module: ModuleType | tuple[ModuleType, ...] | None,
    opcode: str,
) -> AssemblyLineBuilder | None:
    """按统一的 ``_build_<opcode>_lines`` 命名约定取得 builder。

    这里只解析实现符号，不从 opcode 推导任何语义。form、有符号性、掩码、
    舍入和寄存器角色都必须由调用 ``_add`` 的数据行显式给出。
    """

    if module is None:
        return None
    name = f"_build_{opcode.replace('.', '_')}_lines"
    modules = module if isinstance(module, tuple) else (module,)
    matches = [
        getattr(candidate, name)
        for candidate in modules
        if hasattr(candidate, name)
    ]
    if len(matches) != 1:
        module_names = ", ".join(candidate.__name__ for candidate in modules)
        raise ValueError(
            f"{opcode} 必须在 [{module_names}] 中恰好绑定一个显式 "
            f"assembly builder {name}，实际为 {len(matches)}"
        )
    return matches[0]


def _same_width(
    operand_form: str,
    *,
    allowed_sews: tuple[int, ...] = (),
    lowering: Literal["direct", "not_base_v", "and_not_base_v"] = "direct",
) -> RVV256SameWidthSpec:
    """由明确的 form 标记建立等宽寄存器位置，不检查 opcode 后缀。"""

    layouts = {
        "unary": ((1,), None),
        "vv": ((1, 2), None),
        "vx": ((1,), 2),
        "vi": ((1,), 2),
        "vf": ((1,), 2),
    }
    if operand_form not in layouts:
        raise ValueError(f"未知 RVV256 等宽 form: {operand_form}")
    vector_positions, scalar_position = layouts[operand_form]
    return RVV256SameWidthSpec(
        operand_form=operand_form,
        vector_operand_positions=vector_positions,
        scalar_operand_position=scalar_position,
        allowed_sews=allowed_sews,
        lowering=lowering,
    )


def _add(
    opcodes: Iterable[str],
    *,
    module: ModuleType | tuple[ModuleType, ...] | None,
    category: str,
    form: str,
    operand_order: tuple[str, ...],
    operand_count: int,
    supported_sews: frozenset[int] = _ALL_SEWS,
    supported_lmuls: frozenset[float] = _ALL_LMULS,
    mask_profiles: frozenset[str] = frozenset(),
    tail_policy: TailPolicy = TailPolicy.UNDISTURBED,
    vstart_policy: VStartPolicy = VStartPolicy.REQUIRE_ZERO,
    reads_old_vd: bool = False,
    vtype_independent: bool = False,
    signedness: str = "not-applicable",
    signedness_by_opcode: bool = False,
    rounding_policy: str = "exact",
    target_mnemonic: str | None = None,
    same_width: RVV256SameWidthSpec | None = None,
) -> None:
    """登记一组语义轴完全相同的 opcode，并在导入期拒绝重复。"""

    for opcode in opcodes:
        if opcode in _SEEDS:
            raise ValueError(f"RVV256 规格重复声明 opcode: {opcode}")
        concrete_signedness = signedness
        if signedness_by_opcode:
            try:
                concrete_signedness = _EXPLICIT_SIGNEDNESS[opcode]
            except KeyError as exc:
                raise ValueError(
                    f"{opcode} 缺少逐 opcode signedness 事实"
                ) from exc
        sews, lmuls = supported_sews, supported_lmuls
        if category in {
            "float-convert-widen", "float-convert-narrow", "fixed-point-narrow",
            "float-widen", "float-widen-fused", "integer-widen",
            "integer-widen-multiply", "integer-widen-accumulate", "integer-convert",
        }:
            lmuls = frozenset(value for value in lmuls if value <= 4)
            sews = sews & frozenset({8, 16, 32})
        if category == "integer-extend":
            factor = int(opcode[-1])
            sews = frozenset(value for value in sews if value >= 8 * factor)
            lmuls = frozenset(value for value in lmuls if value >= factor / 8)
        if opcode == "vfwmul.vf":
            sews, lmuls = frozenset({16}), frozenset({1.0})
        _SEEDS[opcode] = _Seed(
            opcode=opcode,
            category=category,
            form=form,
            operand_order=operand_order,
            operand_count=operand_count,
            builder=_resolve_builder(module, opcode),
            supported_sews=sews,
            supported_lmuls=lmuls,
            mask_profiles=mask_profiles,
            tail_policy=tail_policy,
            vstart_policy=vstart_policy,
            reads_old_vd=reads_old_vd,
            vtype_independent=vtype_independent,
            signedness=concrete_signedness,
            rounding_policy=rounding_policy,
            target_mnemonic=opcode if target_mnemonic is None else target_mnemonic,
            same_width=same_width,
        )


# 配置指令：目标 vtype 由指令自身决定，当前输入 vtype 不参与合法性判断。
_add(
    ("vsetvli", "vsetivli"),
    module=config,
    category="config",
    form="rd, avl, eSEW, LMUL, tail, mask",
    operand_order=("rd", "avl", "sew", "lmul", "tail", "mask"),
    operand_count=6,
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vstart_policy=VStartPolicy.NOT_APPLICABLE,
    rounding_policy="not-applicable",
)
_add(
    ("vsetvl",),
    module=config,
    category="config",
    form="rd, rs1, rs2",
    operand_order=("rd", "rs1", "rs2"),
    operand_count=3,
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vstart_policy=VStartPolicy.NOT_APPLICABLE,
    rounding_policy="not-applicable",
)


# 等宽整数族。每组显式声明操作数角色和 signedness；宽路径只读取
# same_width 描述，不再维护第二张 opcode 表。
_add(
    ("vadd.vv",),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, vs1[, v0.t]",
    operand_order=("vd", "vs2", "vs1"),
    operand_count=3,
    mask_profiles=_MASK_BOTH,
    signedness_by_opcode=True,
)
_add(
    ("vor.vv", "vsll.vv"),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, vs1[, v0.t]",
    operand_order=("vd", "vs2", "vs1"),
    operand_count=3,
    mask_profiles=_MASK_BOTH,
    signedness_by_opcode=True,
    same_width=_same_width("vv"),
)
_add(
    ("vsub.vv", "vxor.vv", "vand.vv", "vmax.vv", "vmaxu.vv", "vmul.vv", "vsrl.vv"),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, vs1",
    operand_order=("vd", "vs2", "vs1"),
    operand_count=3,
    signedness_by_opcode=True,
    same_width=_same_width("vv"),
)
_add(
    ("vandn.vv",),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, vs1",
    operand_order=("vd", "vs2", "vs1"),
    operand_count=3,
    signedness="bitwise",
    target_mnemonic="vand.vv",
    same_width=_same_width("vv", lowering="and_not_base_v"),
)
_add(
    ("vadd.vx", "vor.vx"),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, rs1[, v0.t]",
    operand_order=("vd", "vs2", "rs1"),
    operand_count=3,
    mask_profiles=_MASK_BOTH,
    signedness_by_opcode=True,
)
_add(
    ("vsub.vx", "vand.vx"),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, rs1[, v0.t]",
    operand_order=("vd", "vs2", "rs1"),
    operand_count=3,
    mask_profiles=_MASK_BOTH,
    signedness_by_opcode=True,
    same_width=_same_width("vx"),
)
_add(
    ("vsll.vx", "vsrl.vx", "vmul.vx", "vdiv.vx"),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, rs1",
    operand_order=("vd", "vs2", "rs1"),
    operand_count=3,
    signedness_by_opcode=True,
    same_width=_same_width("vx"),
)
_add(
    ("vadd.vi", "vrsub.vi"),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, immediate[, v0.t]",
    operand_order=("vd", "vs2", "immediate"),
    operand_count=3,
    mask_profiles=_MASK_BOTH,
    signedness_by_opcode=True,
)
_add(
    ("vor.vi", "vsll.vi"),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, immediate[, v0.t]",
    operand_order=("vd", "vs2", "immediate"),
    operand_count=3,
    mask_profiles=_MASK_BOTH,
    signedness_by_opcode=True,
    same_width=_same_width("vi"),
)
_add(
    ("vand.vi", "vsrl.vi", "vsra.vi"),
    module=arithmetic,
    category="integer-same-width",
    form="vd, vs2, immediate",
    operand_order=("vd", "vs2", "immediate"),
    operand_count=3,
    signedness_by_opcode=True,
    same_width=_same_width("vi"),
)
_add(
    ("vnot.v",),
    module=arithmetic,
    category="integer-unary",
    form="vd, vs2",
    operand_order=("vd", "vs2"),
    operand_count=2,
    signedness="bitwise",
    target_mnemonic="vxor.vi",
    same_width=_same_width("unary", lowering="not_base_v"),
)


# 浮点等宽与融合族。FRM 表示目标环境的动态浮点舍入模式。
_add(
    ("vfadd.vv", "vfsub.vv", "vfmul.vv", "vfdiv.vv"),
    module=arithmetic,
    category="float-same-width",
    form="vd, vs2, vs1[, v0.t]",
    operand_order=("vd", "vs2", "vs1"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    mask_profiles=_MASK_BOTH,
    signedness="floating",
    rounding_policy="dynamic-frm",
    same_width=_same_width("vv", allowed_sews=(32, 64)),
)
_add(
    ("vfmax.vv", "vfmin.vv"),
    module=arithmetic,
    category="float-same-width",
    form="vd, vs2, vs1",
    operand_order=("vd", "vs2", "vs1"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    signedness="floating",
    rounding_policy="dynamic-frm",
    same_width=_same_width("vv", allowed_sews=(32, 64)),
)
_add(
    ("vfadd.vf", "vfrsub.vf"),
    module=arithmetic,
    category="float-same-width",
    form="vd, vs2, rs1[, v0.t]",
    operand_order=("vd", "vs2", "rs1-fpr"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    mask_profiles=_MASK_BOTH,
    signedness="floating",
    rounding_policy="dynamic-frm",
    same_width=_same_width("vf", allowed_sews=(32, 64)),
)
_add(
    ("vfsub.vf",),
    module=arithmetic,
    category="float-same-width",
    form="vd, vs2, rs1",
    operand_order=("vd", "vs2", "rs1-fpr"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    signedness="floating",
    rounding_policy="dynamic-frm",
    same_width=_same_width("vf", allowed_sews=(32, 64)),
)
_add(
    ("vfmul.vf",),
    module=arithmetic,
    category="float-same-width",
    form="vd, vs2, rs1[, v0.t]",
    operand_order=("vd", "vs2", "rs1-fpr"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    mask_profiles=_MASK_BOTH,
    signedness="floating",
    rounding_policy="dynamic-frm",
)
_add(
    ("vfabs.v",),
    module=arithmetic,
    category="float-unary",
    form="vd, vs2",
    operand_order=("vd", "vs2"),
    operand_count=2,
    supported_sews=_FLOAT_SEWS,
    signedness="floating",
    rounding_policy="exact",
    same_width=_same_width("unary"),
)
_add(
    ("vfneg.v",),
    module=arithmetic,
    category="float-unary",
    form="vd, vs2[, v0.t]",
    operand_order=("vd", "vs2"),
    operand_count=2,
    supported_sews=_FLOAT_SEWS,
    mask_profiles=_MASK_BOTH,
    signedness="floating",
    rounding_policy="exact",
    same_width=_same_width("unary"),
)
_add(
    ("vfmacc.vf",),
    module=arithmetic,
    category="float-fused",
    form="vd, rs1, vs2[, v0.t]",
    operand_order=("vd-read-write", "rs1-fpr", "vs2"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    mask_profiles=_MASK_BOTH,
    reads_old_vd=True,
    signedness="floating",
    rounding_policy="dynamic-frm",
)
_add(
    ("vfnmsac.vf",),
    module=arithmetic,
    category="float-fused",
    form="vd, rs1, vs2[, v0.t]",
    operand_order=("vd-read-write", "rs1-fpr", "vs2"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    mask_profiles=_MASK_WIDE,
    reads_old_vd=True,
    signedness="floating",
    rounding_policy="dynamic-frm",
)
_add(
    ("vfmacc.vv",),
    module=arithmetic,
    category="float-fused",
    form="vd, vs1, vs2[, v0.t]",
    operand_order=("vd-read-write", "vs1", "vs2"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    mask_profiles=_MASK_WIDE,
    reads_old_vd=True,
    signedness="floating",
    rounding_policy="dynamic-frm",
)
_add(
    ("vfmadd.vf", "vfmadd.vv", "vfmsub.vv", "vfmsac.vv"),
    module=arithmetic,
    category="float-fused",
    form="vd, multiplicand, addend",
    operand_order=("vd-read-write", "multiplicand", "addend"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    reads_old_vd=True,
    signedness="floating",
    rounding_policy="dynamic-frm",
)


# 归约、搬移、索引和整数累加保留显式 builder。
_add(
    ("vfredusum.vs", "vfredmax.vs", "vfredmin.vs"),
    module=arithmetic,
    category="float-reduction",
    form="vd, vs2, vs1",
    operand_order=("vd", "vs2", "vs1-seed"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    reads_old_vd=True,
    signedness="floating",
    rounding_policy="dynamic-frm",
)
_add(
    ("vfwredosum.vs", "vfwredusum.vs"),
    module=arithmetic,
    category="float-reduction-widen",
    form="wide vd, narrow vs2, wide vs1",
    operand_order=("wide-vd", "narrow-vs2", "wide-vs1-seed"),
    operand_count=3,
    supported_sews=_WIDEN_FLOAT_SEWS,
    reads_old_vd=True,
    signedness="floating",
    rounding_policy="dynamic-frm",
)
_add(
    ("vredsum.vs", "vredor.vs", "vredmaxu.vs"),
    module=arithmetic,
    category="integer-reduction",
    form="vd, vs2, vs1",
    operand_order=("vd", "vs2", "vs1-seed"),
    operand_count=3,
    reads_old_vd=True,
    signedness_by_opcode=True,
)
_add(
    ("vfmv.v.f", "vfmv.s.f"),
    module=arithmetic,
    category="float-move",
    form="destination, source",
    operand_order=("destination", "source"),
    operand_count=2,
    supported_sews=_FLOAT_SEWS,
    signedness="floating-bit-preserving",
    rounding_policy="exact",
)
_add(
    ("vfmv.f.s",),
    module=arithmetic,
    category="float-move",
    form="fp-rd, vs2",
    operand_order=("fp-rd", "vs2"),
    operand_count=2,
    supported_sews=_FLOAT_SEWS,
    tail_policy=TailPolicy.NOT_APPLICABLE,
    signedness="floating-bit-preserving",
    rounding_policy="exact",
)
_add(
    ("vmv.v.i", "vmv.v.x", "vmv.v.v", "vmv.s.x"),
    module=arithmetic,
    category="integer-move",
    form="destination, source",
    operand_order=("destination", "source"),
    operand_count=2,
    signedness="bit-preserving",
)
_add(
    ("vmv.x.s",),
    module=arithmetic,
    category="integer-move",
    form="rd, vs2",
    operand_order=("rd", "vs2"),
    operand_count=2,
    tail_policy=TailPolicy.NOT_APPLICABLE,
    signedness="bit-preserving",
)
_add(
    ("vid.v",),
    module=arithmetic,
    category="integer-index",
    form="vd",
    operand_order=("vd",),
    operand_count=1,
    signedness="unsigned-index",
)
_add(
    ("vmadd.vv", "vmadd.vx", "vmacc.vv"),
    module=arithmetic,
    category="integer-accumulate",
    form="vd, multiplicand, addend",
    operand_order=("vd-read-write", "multiplicand", "addend"),
    operand_count=3,
    reads_old_vd=True,
    signedness="two-complement",
)
_add(
    ("vmacc.vx",),
    module=arithmetic,
    category="integer-accumulate",
    form="vd, multiplicand, addend",
    operand_order=("vd-read-write", "multiplicand", "addend"),
    operand_count=3,
    vstart_policy=VStartPolicy.ARCHITECTURAL,
    reads_old_vd=True,
    signedness="two-complement",
)


# 浮点/整数转换。每组明确声明扩展方向与舍入来源。
_add(
    ("vfcvt.f.x.v", "vfcvt.x.f.v", "vfcvt.f.xu.v"),
    module=arithmetic,
    category="float-convert",
    form="vd, vs2",
    operand_order=("vd", "vs2"),
    operand_count=2,
    supported_sews=_FLOAT_SEWS,
    signedness_by_opcode=True,
    rounding_policy="dynamic-frm",
)
_add(
    ("vfncvt.f.xu.w", "vfncvt.f.f.w", "vfncvt.x.f.w"),
    module=arithmetic,
    category="float-convert-narrow",
    form="narrow vd, wide vs2",
    operand_order=("narrow-vd", "wide-vs2"),
    operand_count=2,
    supported_sews=_WIDEN_FLOAT_SEWS,
    signedness_by_opcode=True,
    rounding_policy="dynamic-frm",
)
_add(
    ("vfwcvt.f.f.v", "vfwcvt.f.x.v"),
    module=arithmetic,
    category="float-convert-widen",
    form="wide vd, narrow vs2",
    operand_order=("wide-vd", "narrow-vs2"),
    operand_count=2,
    supported_sews=_WIDEN_FLOAT_SEWS,
    signedness_by_opcode=True,
    rounding_policy="dynamic-frm",
)
_add(
    ("vwcvtu.x.x.v", "vwcvt.x.x.v", "vncvt.x.x.w"),
    module=arithmetic,
    category="integer-convert",
    form="vd, vs2",
    operand_order=("vd", "vs2"),
    operand_count=2,
    supported_sews=_ALL_SEWS,
    signedness_by_opcode=True,
)
_add(
    ("vzext.vf2", "vzext.vf4", "vzext.vf8", "vsext.vf2", "vsext.vf4"),
    module=arithmetic,
    category="integer-extend",
    form="wide vd, narrow vs2",
    operand_order=("wide-vd", "narrow-vs2"),
    operand_count=2,
    signedness_by_opcode=True,
)
_add(
    ("vnsrl.wi",),
    module=arithmetic,
    category="fixed-point-narrow",
    form="narrow vd, wide vs2, uimm[, v0.t]",
    operand_order=("narrow-vd", "wide-vs2", "uimm"),
    operand_count=3,
    supported_sews=_NARROW_DESTINATION_SEWS,
    mask_profiles=_MASK_BOTH,
    signedness_by_opcode=True,
    rounding_policy="vxrm-for-vnclip",
)
_add(
    ("vnsra.wi", "vnclip.wi"),
    module=arithmetic,
    category="fixed-point-narrow",
    form="narrow vd, wide vs2, uimm",
    operand_order=("narrow-vd", "wide-vs2", "uimm"),
    operand_count=3,
    supported_sews=_NARROW_DESTINATION_SEWS,
    signedness_by_opcode=True,
    rounding_policy="vxrm-for-vnclip",
)


# 宽化整数/浮点族。累加和归约明确读取旧目标或 seed。
_add(
    ("vfwmacc.vv",),
    module=None,
    category="float-widen-fused",
    form="wide vd, narrow vs1, narrow vs2",
    operand_order=("wide-vd-read-write", "narrow-vs1", "narrow-vs2"),
    operand_count=3,
    supported_sews=_WIDEN_FLOAT_SEWS,
    reads_old_vd=True,
    signedness="floating",
    rounding_policy="dynamic-frm",
)
_add(
    ("vfwmul.vf",),
    module=arithmetic,
    category="float-widen",
    form="wide vd, narrow vs2, narrow rs1",
    operand_order=("wide-vd", "narrow-vs2", "narrow-rs1-fpr"),
    operand_count=3,
    supported_sews=_WIDEN_FLOAT_SEWS,
    signedness="floating",
    rounding_policy="dynamic-frm",
)
_add(
    ("vwmul.vx", "vwmul.vv", "vwmulu.vx", "vwmulu.vv", "vwmulsu.vv"),
    module=arithmetic,
    category="integer-widen-multiply",
    form="wide vd, narrow operands",
    operand_order=("wide-vd", "narrow-source-1", "narrow-source-2"),
    operand_count=3,
    supported_sews=_WIDEN_INTEGER_SEWS,
    signedness_by_opcode=True,
)
_add(
    ("vwmacc.vx",),
    module=arithmetic,
    category="integer-widen-accumulate",
    form="wide vd, rs1, narrow vs2[, v0.t]",
    operand_order=("wide-vd-read-write", "rs1", "narrow-vs2"),
    operand_count=3,
    supported_sews=_WIDEN_INTEGER_SEWS,
    mask_profiles=_MASK_BOTH,
    reads_old_vd=True,
    signedness="signed",
)
_add(
    ("vwmacc.vv",),
    module=arithmetic,
    category="integer-widen-accumulate",
    form="wide vd, narrow vs1, narrow vs2",
    operand_order=("wide-vd-read-write", "narrow-vs1", "narrow-vs2"),
    operand_count=3,
    supported_sews=_WIDEN_INTEGER_SEWS,
    reads_old_vd=True,
    signedness="signed",
)
_add(
    ("vwadd.wv", "vwaddu.wv", "vwaddu.vx", "vwadd.vv", "vwsll.vi"),
    module=arithmetic,
    category="integer-widen",
    form="wide vd, narrow/wide source, source",
    operand_order=("wide-vd", "source-1", "source-2"),
    operand_count=3,
    supported_sews=_WIDEN_INTEGER_SEWS,
    signedness_by_opcode=True,
)
_add(
    ("vwredsum.vs",),
    module=arithmetic,
    category="integer-widen-reduction",
    form="wide vd, narrow vs2, wide vs1[, v0.t]",
    operand_order=("wide-vd", "narrow-vs2", "wide-vs1-seed"),
    operand_count=3,
    supported_sews=_WIDEN_INTEGER_SEWS,
    mask_profiles=_MASK_BOTH,
    reads_old_vd=True,
    signedness="signed",
)


# 整寄存器搬移不依赖当前 vtype；模拟槽位仍固定为 128 B。
_add(
    ("vmv1r.v", "vmv2r.v", "vmv4r.v", "vmv8r.v"),
    module=arithmetic,
    category="arithmetic",
    form="vd, vs2",
    operand_order=("raw-vd-group", "raw-vs2-group"),
    operand_count=2,
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
    signedness="bit-preserving",
    rounding_policy="not-applicable",
)


# Slide/gather 的旧目标读取语义不能与普通等宽族合并。
_add(
    ("vslidedown.vi", "vslidedown.vx"),
    module=arithmetic,
    category="slide",
    form="vd, vs2, offset",
    operand_order=("vd", "vs2", "offset"),
    operand_count=3,
    signedness="unsigned-offset",
)
_add(
    ("vslideup.vi",),
    module=arithmetic,
    category="slide",
    form="vd, vs2, offset",
    operand_order=("vd-read-write", "vs2", "offset"),
    operand_count=3,
    reads_old_vd=True,
    signedness="unsigned-offset",
)
_add(
    ("vslide1up.vx",),
    module=arithmetic,
    category="slide",
    form="vd, vs2, rs1",
    operand_order=("vd-read-write", "vs2", "rs1"),
    operand_count=3,
    reads_old_vd=True,
    signedness="bit-preserving",
)
_add(
    ("vslide1down.vx",),
    module=arithmetic,
    category="slide",
    form="vd, vs2, rs1",
    operand_order=("vd", "vs2", "rs1"),
    operand_count=3,
    signedness="bit-preserving",
)
_add(
    ("vrgather.vv", "vrgatherei16.vv"),
    module=arithmetic,
    category="gather",
    form="vd, vs2, index-vector",
    operand_order=("vd", "vs2", "index-vector"),
    operand_count=3,
    signedness="unsigned-index",
)


# Mask 比较、逻辑、扫描与 merge。这里的 v0 selector 与末尾 v0.t 执行
# 掩码不是同一概念，因而 form 单独列出。
_add(
    ("vmfgt.vf", "vmfle.vf", "vmfne.vf"),
    module=mask,
    category="mask-compare",
    form="vd-mask, vs2, rs1",
    operand_order=("vd-mask", "vs2", "rs1-fpr"),
    operand_count=3,
    supported_sews=_FLOAT_SEWS,
    signedness="floating",
    rounding_policy="quiet-compare",
)
_add(
    ("vmsne.vv", "vmsleu.vv", "vmsltu.vv"),
    module=mask,
    category="mask-compare",
    form="vd-mask, vs2, vs1",
    operand_order=("vd-mask", "vs2", "vs1"),
    operand_count=3,
    signedness_by_opcode=True,
)
_add(
    ("vmsne.vi", "vmseq.vi", "vmsle.vi", "vmsleu.vi", "vmsgtu.vi"),
    module=mask,
    category="mask-compare",
    form="vd-mask, vs2, simm5",
    operand_order=("vd-mask", "vs2", "simm5"),
    operand_count=3,
    signedness_by_opcode=True,
)
_add(
    ("vmseq.vx", "vmsgtu.vx", "vmsltu.vx"),
    module=mask,
    category="mask-compare",
    form="vd-mask, vs2, rs1",
    operand_order=("vd-mask", "vs2", "rs1"),
    operand_count=3,
    signedness_by_opcode=True,
)
_add(
    ("vmclr.m",),
    module=mask,
    category="mask-logic",
    form="vd-mask",
    operand_order=("vd-mask",),
    operand_count=1,
    signedness="mask-bits",
)
_add(
    ("vmor.mm", "vmand.mm"),
    module=mask,
    category="mask-logic",
    form="vd-mask, vs2-mask, vs1-mask",
    operand_order=("vd-mask", "vs2-mask", "vs1-mask"),
    operand_count=3,
    signedness="mask-bits",
)
_add(
    ("vmnot.m",),
    module=mask,
    category="mask-logic",
    form="vd-mask, vs2-mask",
    operand_order=("vd-mask", "vs2-mask"),
    operand_count=2,
    signedness="mask-bits",
)
_add(
    ("vcpop.m", "vfirst.m"),
    module=mask,
    category="mask-scan",
    form="rd, vs2-mask",
    operand_order=("rd", "vs2-mask"),
    operand_count=2,
    tail_policy=TailPolicy.NOT_APPLICABLE,
    signedness="mask-bits",
)
_add(
    ("vmerge.vvm", "vmerge.vxm", "vmerge.vim"),
    module=mask,
    category="mask-merge",
    form="vd, vs2, source, v0",
    operand_order=("vd", "vs2", "source", "v0-selector"),
    operand_count=4,
    reads_old_vd=False,
    signedness_by_opcode=True,
)
_add(
    ("vlm.v",),
    module=mask,
    category="mask-load",
    form="vd-mask, (rs1)",
    operand_order=("vd-mask", "rs1-address"),
    operand_count=2,
    signedness="mask-bits",
)


# 普通、strided、indexed、fault-only-first 与 segment 访存。
_add(
    ("vle8.v", "vle16.v", "vle32.v", "vle64.v"),
    module=memory,
    category="memory",
    form="vd, (rs1)[, v0.t]",
    operand_order=("vd", "rs1-address"),
    operand_count=2,
    mask_profiles=_MASK_BOTH,
    signedness="raw-elements",
)
_add(
    ("vse8.v", "vse16.v", "vse32.v", "vse64.v"),
    module=memory,
    category="memory",
    form="vs3, (rs1)[, v0.t]",
    operand_order=("vs3", "rs1-address"),
    operand_count=2,
    mask_profiles=_MASK_BOTH,
    tail_policy=TailPolicy.NOT_APPLICABLE,
    signedness="raw-elements",
)
_add(
    ("vlse8.v", "vlse16.v", "vlse32.v", "vlse64.v"),
    module=memory,
    category="memory",
    form="vd, (rs1), rs2-stride[, v0.t]",
    operand_order=("vd", "rs1-address", "rs2-stride"),
    operand_count=3,
    mask_profiles=_MASK_BOTH,
    signedness="raw-elements",
)
_add(
    ("vsse32.v", "vsse64.v"),
    module=memory,
    category="memory",
    form="vs3, (rs1), rs2-stride[, v0.t]",
    operand_order=("vs3", "rs1-address", "rs2-stride"),
    operand_count=3,
    mask_profiles=_MASK_BOTH,
    tail_policy=TailPolicy.NOT_APPLICABLE,
    signedness="raw-elements",
)
_add(
    ("vluxei16.v", "vluxei64.v"),
    module=memory,
    category="memory",
    form="vd, (rs1), index-vector",
    operand_order=("vd", "rs1-address", "index-vector"),
    operand_count=3,
    signedness="unsigned-index",
)
_add(
    ("vle8ff.v",),
    module=memory,
    category="memory",
    form="vd, (rs1)",
    operand_order=("vd", "rs1-address"),
    operand_count=2,
    signedness="raw-elements",
)
_add(
    ("vsm.v",),
    module=memory,
    category="memory",
    form="vs3-mask, (rs1)",
    operand_order=("vs3-mask", "rs1-address"),
    operand_count=2,
    tail_policy=TailPolicy.NOT_APPLICABLE,
    signedness="mask-bits",
)
_add(
    ("vlseg2e32.v", "vlseg2e64.v"),
    module=memory,
    category="memory",
    form="vd-group, (rs1)",
    operand_order=("vd-group", "rs1-address"),
    operand_count=2,
    signedness="raw-elements",
)
_add(
    ("vsseg2e32.v", "vsseg2e64.v", "vsseg4e64.v"),
    module=memory,
    category="memory",
    form="vs3-group, (rs1)",
    operand_order=("vs3-group", "rs1-address"),
    operand_count=2,
    tail_policy=TailPolicy.NOT_APPLICABLE,
    signedness="raw-elements",
)
_add(
    ("vlsseg2e32.v", "vlsseg2e64.v"),
    module=memory,
    category="memory",
    form="vd-group, (rs1), rs2-stride",
    operand_order=("vd-group", "rs1-address", "rs2-stride"),
    operand_count=3,
    signedness="raw-elements",
)
_add(
    ("vssseg2e32.v", "vssseg2e64.v"),
    module=memory,
    category="memory",
    form="vs3-group, (rs1), rs2-stride",
    operand_order=("vs3-group", "rs1-address", "rs2-stride"),
    operand_count=3,
    tail_policy=TailPolicy.NOT_APPLICABLE,
    signedness="raw-elements",
)


# Whole-register load/store 的固定 raw group 不读取 vtype。三条历史上只由
# 宽 helper 实现的 opcode 显式使用 ``module=None``，并非漏注册 builder。
_add(
    (
        "vl1r.v", "vl1re16.v", "vl1re32.v", "vl1re64.v",
        "vl2r.v", "vl2re16.v", "vl2re32.v",
        "vl4r.v", "vl4re16.v", "vl4re32.v", "vl4re64.v",
        "vl8re32.v", "vl8re64.v",
    ),
    module=memory,
    category="memory",
    form="raw-vector-group, (rs1)",
    operand_order=("raw-vector-group", "rs1-address"),
    operand_count=2,
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
    signedness="raw-bytes",
    rounding_policy="not-applicable",
)
_add(
    ("vs1r.v", "vs2r.v", "vs4r.v", "vs8r.v"),
    module=memory,
    category="memory",
    form="raw-vector-group, (rs1)",
    operand_order=("raw-vector-group", "rs1-address"),
    operand_count=2,
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
    signedness="raw-bytes",
    rounding_policy="not-applicable",
)
_add(
    ("vl8r.v", "vl8re16.v", "vl2re64.v"),
    module=None,
    category="whole-register",
    form="raw-vector-group, (rs1)",
    operand_order=("raw-vector-group", "rs1-address"),
    operand_count=2,
    supported_sews=frozenset(),
    supported_lmuls=frozenset(),
    tail_policy=TailPolicy.NOT_APPLICABLE,
    vtype_independent=True,
    signedness="raw-bytes",
    rounding_policy="not-applicable",
)


for opcodes, form, order in (
    (("csrr",), "rd, vector-csr", ("rd", "vector-csr")),
    (("csrw", "csrs", "csrc"), "vector-csr, rs1", ("vector-csr", "rs1")),
    (("csrwi", "csrsi", "csrci"), "vector-csr, zimm", ("vector-csr", "zimm")),
    (("csrrw", "csrrs", "csrrc"), "rd, vector-csr, rs1", ("rd", "vector-csr", "rs1")),
    (("csrrwi", "csrrsi", "csrrci"), "rd, vector-csr, zimm", ("rd", "vector-csr", "zimm")),
):
    _add(
        opcodes,
        module=csr,
        category="csr",
        form=form,
        operand_order=order,
        operand_count=len(order),
        supported_sews=frozenset(),
        supported_lmuls=frozenset(),
        tail_policy=TailPolicy.NOT_APPLICABLE,
        vstart_policy=VStartPolicy.NOT_APPLICABLE,
        vtype_independent=True,
        signedness="raw-csr-value",
        rounding_policy="not-applicable",
    )


def _validator(seed: _Seed, *, wide_lmul: bool):
    """建立只做结构归一化和掩码能力判断的纯 validator。"""

    def validate(context: HandlerContext) -> tuple[str, ...]:
        insn = context.instruction
        operands = tuple(str(operand).strip() for operand in insn.operands)
        if operands and operands[-1].lower().endswith(".t"):
            operands = (*operands[:-1], operands[-1].lower())
        mask_operand = operands[-1] if operands and operands[-1].endswith(".t") else None
        base_count = len(operands) - (1 if mask_operand is not None else 0)
        if base_count != seed.operand_count:
            raise InstructionValidationError(
                insn,
                f"{insn.opcode} 需要恰好 {seed.operand_count} 个非掩码操作数，"
                f"实际为 {base_count}",
            )
        if mask_operand is not None and mask_operand != "v0.t":
            raise InstructionValidationError(
                insn,
                f"{insn.opcode}: RVV256 only supports explicit v0.t mask: {insn.op_str}",
            )
        mask_supported = (
            "wide" in seed.mask_profiles
            if wide_lmul
            else "conservative" in seed.mask_profiles
        )
        if mask_operand is not None and not mask_supported:
            raise InstructionValidationError(
                insn,
                f"{insn.opcode}: RVV256 masked form is not implemented yet: {insn.op_str}",
                status=LoweringStatus.UNSUPPORTED,
                code="unsupported-mask-form",
            )
        if insn.opcode in {"vsll.vi", "vsrl.vi", "vsra.vi"}:
            try:
                immediate = parse_integer_literal(operands[2])
            except ValueError as exc:
                raise InstructionValidationError(
                    insn, f"{insn.opcode} uimm5 must be an integer in 0..31",
                ) from exc
            if not 0 <= immediate <= 31:
                raise InstructionValidationError(
                    insn, f"{insn.opcode} uimm5 must be in 0..31, got {immediate}",
                )
            operands = (*operands[:2], str(immediate), *operands[3:])
        validate_source_operands(context, operands)
        return operands

    return validate


# 标量语义结果事实：哪些 opcode 的第一个操作数是写入的 GPR/FPR 结果。
# 解析机制由 riscv.extensions.rvv.translation.specs 唯一提供，这里只声明数据。
_SCALAR_RESULT_OPCODES = frozenset({
    "vsetvli", "vsetivli", "vsetvl", "vmv.x.s", "vcpop.m", "vfirst.m",
    "csrr", "csrrw", "csrrwi", "csrrs", "csrrsi", "csrrc", "csrrci",
})
_semantic_outputs, _semantic_inputs = make_scalar_result_resolvers(
    gpr_result_opcodes=_SCALAR_RESULT_OPCODES,
    fpr_result_opcodes=frozenset({"vfmv.f.s"}),
)


def _state_sets(seed: _Seed) -> tuple[frozenset[str], frozenset[str]]:
    """声明模拟状态读写；具体偏移仍只来自 SimulatedStateLayout。"""

    if seed.category == "config":
        return frozenset({"vl", "vtype", "vlenb"}), frozenset({"vl", "vtype", "vstart"})
    if seed.category == "csr":
        writes = frozenset() if seed.opcode == "csrr" else frozenset({"vector-csr"})
        return frozenset({"vector-csr", "vcsr"}), writes
    writes = {"vstart"}
    if not (
        (seed.category == "memory" and seed.opcode.startswith("vs"))
        or seed.opcode in {"vcpop.m", "vfirst.m", "vmv.x.s", "vfmv.f.s"}
    ):
        writes.add("vreg")
    reads = {"vl", "vtype", "vreg", "vstart"}
    if seed.opcode == "vnclip.wi":
        reads.add("vcsr")
        writes.update({"vcsr", "vxrm", "vxsat"})
    return frozenset(reads), frozenset(writes)


def build_rvv256_registry(*, wide_lmul: bool) -> HandlerRegistry:
    """构造 profile 专用 registry；opcode 集合在宽/保守模式完全一致。"""

    profile = "wide" if wide_lmul else "conservative"
    registry = HandlerRegistry()
    lowerer = RVV256Lowerer(wide_lmul=wide_lmul)
    for opcode in sorted(_SEEDS):
        seed = _SEEDS[opcode]
        mask_supported = profile in seed.mask_profiles
        state_reads, state_writes = _state_sets(seed)
        metadata = RVV256LoweringMetadata(
            builder=seed.builder,
            same_width=seed.same_width,
            conservative_mask_supported="conservative" in seed.mask_profiles,
        )
        base_form = seed.form.replace("[, v0.t]", "")
        masked_form = f"{base_form}, v0.t"
        registry.register(InstructionSpec(
            opcode=seed.opcode,
            category=seed.category,
            operand_forms=(base_form, masked_form) if mask_supported else (base_form,),
            supported_sews=seed.supported_sews,
            supported_lmuls=seed.supported_lmuls,
            mask_policy=MaskPolicy.V0_ONLY if mask_supported else MaskPolicy.FORBIDDEN,
            tail_policy=seed.tail_policy,
            vstart_policy=seed.vstart_policy,
            reads_old_vd=seed.reads_old_vd or mask_supported,
            vtype_independent=seed.vtype_independent,
            validator=_validator(seed, wide_lmul=wide_lmul),
            lowerer=lowerer,
            semantic_inputs=_semantic_inputs,
            semantic_outputs=_semantic_outputs,
            state_reads=state_reads,
            state_writes=state_writes,
            scalar_instruction_matcher=(
                csr.is_vector_csr_instruction if seed.category == "csr" else None
            ),
            target_mnemonic=seed.target_mnemonic,
            operand_order=seed.operand_order,
            signedness=seed.signedness,
            rounding_policy=seed.rounding_policy,
            lowering_metadata=metadata,
        ))
    return registry


RVV256_SAME_WIDTH_OPCODES = frozenset(
    opcode for opcode, seed in _SEEDS.items() if seed.same_width is not None
)


__all__ = [
    "RVV256LoweringMetadata",
    "RVV256_SAME_WIDTH_OPCODES",
    "RVV256SameWidthSpec",
    "build_rvv256_registry",
]
