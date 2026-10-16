"""validation：后端内部职责。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable
from riscv.frontend.literals import parse_integer_literal
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _effective_lmul,
    _segment_field_registers,
)
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _require_non_overlapping_groups,
    _parse_slide_uimm5,
)
from riscv.extensions.rvv.backends.rvv1024_transition.operands import _index_e16_shape
from riscv.extensions.rvv.backends.rvv1024_transition.operands import _validate_lmul
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _widened_lmul,
    _wide_result_shape,
)
from riscv.extensions.rvv.backends.rvv1024_transition.operands import _validate_source_profile
from riscv.extensions.rvv.analysis.model import LEGAL_LMULS
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _float_shape,
    _parse_simm5,
    _parse_uimm5,
    _require_float_sew,
    _source_shape,
)
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _CSR_VALUE_OPERAND_INDEX_BY_OPCODE,
    _VECTOR_CSR_IMMEDIATE_OPCODES,
    _VECTOR_CSR_RMW_OPCODES,
    _WRITABLE_VECTOR_CSRS,
    _csr_operation_kind,
    _is_zero_gpr,
    _parse_zimm,
    vector_csr_from_instruction,
)
from riscv.extensions.rvv.backends.rvv1024_transition.state_view import (
    SOURCE_VLENB,
    validate_source_group,
)
from riscv.extensions.rvv.backends.rvv1024_transition.temp_regs import (
    RegisterAllocationError, VRegTempAllocator,
)
from riscv.extensions.rvv.translation.contracts import (
    HandlerContext,
    InstructionValidationError,
    MaskPolicy,
    TailPolicy,
)
from riscv.extensions.rvv.translation.validation import validate_source_operands


_ALL_SEWS = frozenset({8, 16, 32, 64})


_ALL_LMULS = frozenset(LEGAL_LMULS)


@dataclass(frozen=True, slots=True)
class _Seed:
    """构造 :class:`InstructionSpec` 所需的过渡后端专用静态事实。"""

    opcode: str
    category: str
    form: str
    operand_count: int
    validation_kind: str
    # ``builder_kind`` 只选择一个已经显式定义语义轴的公共 builder；它不能从
    # opcode 后缀反推 form。值为 ``explicit`` 时仍绑定独立复杂实现。
    builder_kind: str = "explicit"
    mask_policy: MaskPolicy = MaskPolicy.FORBIDDEN
    supported_sews: frozenset[int] = _ALL_SEWS
    supported_lmuls: frozenset[float] = _ALL_LMULS
    tail_policy: TailPolicy = TailPolicy.UNDISTURBED
    reads_old_vd: bool = False
    vtype_independent: bool = False
    operand_order: tuple[str, ...] = ()
    signedness: str = ""
    rounding_policy: str = ""
    target_mnemonic: str = ""


_WHOLE_FACTORS = {
    "vmv1r.v": 1, "vmv2r.v": 2, "vmv4r.v": 4, "vmv8r.v": 8,
    "vl1r.v": 1, "vl1re16.v": 1, "vl1re32.v": 1, "vl1re64.v": 1,
    "vl2r.v": 2, "vl2re16.v": 2, "vl2re32.v": 2,
    "vl4r.v": 4, "vl4re16.v": 4, "vl4re32.v": 4, "vl4re64.v": 4,
    "vl8r.v": 8, "vl8re32.v": 8, "vl8re64.v": 8,
    "vs1r.v": 1, "vs2r.v": 2, "vs4r.v": 4, "vs8r.v": 8,
}


SCALAR_RESULT_OPCODES = frozenset({
    "vsetvli", "vsetivli", "vsetvl", "vmv.x.s", "vfirst.m", "vcpop.m",
    "csrr", "csrrw", "csrrwi", "csrrs", "csrrsi", "csrrc", "csrrci",
})


def _base_operands(operands: tuple[str, ...]) -> tuple[str, ...]:
    if operands and operands[-1].lower().endswith(".t"):
        return operands[:-1]
    return operands


def _normalized_operands(context: HandlerContext, seed: _Seed) -> tuple[str, ...]:
    """校验操作数个数和 mask form，并返回规范化文本。"""

    insn = context.instruction
    operands = tuple(str(operand).strip() for operand in insn.operands)
    mask = operands[-1].lower() if operands and operands[-1].lower().endswith(".t") else None
    base_count = len(operands) - (1 if mask is not None else 0)

    # CSR pseudo form 的实际数量不同：csrw/csrs/csrc 是两个操作数，带 rd
    # 的基础 RMW 是三个。seed 的 operand_count 只作为文档上限，具体规则
    # 由 CSR validator 在下方精确检查。
    if seed.validation_kind != "csr-write" and base_count != seed.operand_count:
        raise InstructionValidationError(
            insn,
            f"{insn.opcode} 需要 form `{seed.form}`；"
            f"实际得到 {len(operands)} 个操作数: {insn.op_str}",
        )
    if mask is not None:
        if mask != "v0.t":
            raise InstructionValidationError(
                insn, f"RVV256->RVV1024 只支持显式 v0.t 执行掩码: {insn.op_str}"
            )
        if seed.mask_policy is MaskPolicy.FORBIDDEN:
            raise InstructionValidationError(
                insn, f"RVV256->RVV1024 未验证的 v0.t 掩码 form: {insn.op_str}"
            )
    return operands


def _validate_profile(context: HandlerContext, seed: _Seed) -> tuple[int, float]:
    """验证 source vtype 与 spec 声明一致，并返回 SEW/LMUL。"""

    insn = context.instruction
    state = context.state
    if state.vlenb != SOURCE_VLENB:
        raise InstructionValidationError(
            insn,
            f"{insn.opcode} 只支持 source vlenb={SOURCE_VLENB}，当前为 {state.vlenb}",
        )
    try:
        sew, lmul, _token, _width = _source_shape(state)
    except ValueError as exc:
        raise InstructionValidationError(insn, str(exc)) from exc
    # 复杂宽化/窄化族需要保留更具体的诊断（例如“目的 SEW”或“浮点
    # e8”），因此由下方专用 validator 检查；规格中的集合仍准确描述能力。
    deferred_sew_kinds = {
        "float-move", "float-same-width", "float-reduction",
        "float-convert-widen", "float-widen", "float-reduction-widen",
        "integer-widen", "integer-widen-immediate", "integer-wide-narrow",
        "integer-reduction-widen", "narrow", "narrow-immediate",
    }
    if (
        seed.supported_sews
        and sew not in seed.supported_sews
        and seed.validation_kind not in deferred_sew_kinds
    ):
        raise InstructionValidationError(
            insn, f"{insn.opcode} 不支持 source SEW=e{sew}"
        )
    if seed.supported_lmuls and lmul not in seed.supported_lmuls:
        raise InstructionValidationError(
            insn, f"{insn.opcode} 不支持 source LMUL={lmul:g}"
        )
    return sew, lmul


def _validate_groups(
    insn,
    groups: Iterable[tuple[str, float]],
    *,
    temp_widths: Iterable[int] | None = None,
) -> None:
    """纯检查 source 物理组及目标临时组容量。"""

    collected = tuple(groups)
    try:
        for vreg, lmul in collected:
            validate_source_group(vreg, lmul)
    except ValueError as exc:
        raise InstructionValidationError(insn, str(exc)) from exc
    widths = tuple(
        temp_widths
        if temp_widths is not None
        else (int(lmul) if lmul >= 1 else 1 for _vreg, lmul in collected)
    )
    if widths:
        try:
            VRegTempAllocator().alloc_groups(widths)
        except RegisterAllocationError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc


def _vector_tokens(operands: Iterable[str]) -> tuple[str, ...]:
    """只提取精确的 ``v0..v31`` token；地址和标量寄存器不会混入。"""

    result: list[str] = []
    for operand in operands:
        token = str(operand).strip().lower()
        if token.startswith("v") and token[1:].isdigit() and 0 <= int(token[1:]) <= 31:
            result.append(token)
    return tuple(result)


def _validate_config(context: HandlerContext, seed: _Seed, operands: tuple[str, ...]) -> None:
    insn = context.instruction
    try:
        _validate_source_profile(context.state, insn)
        probe = context.state.clone()
        if seed.validation_kind == "config-immediate":
            raw = operands[1]
            value = parse_integer_literal(raw)
            if not 0 <= value <= 31:
                raise ValueError("vsetivli uimm out of range (0..31)")
        if seed.validation_kind != "config-dynamic":
            probe.update(insn)
            _validate_source_profile(probe, insn)
    except InstructionValidationError:
        raise
    except (TypeError, ValueError) as exc:
        raise InstructionValidationError(insn, f"{exc}: {insn.op_str}") from exc


def _validate_csr(context: HandlerContext, seed: _Seed, operands: tuple[str, ...]) -> None:
    insn = context.instruction
    csr_name = vector_csr_from_instruction(insn)
    if csr_name is None:
        raise InstructionValidationError(insn, f"不是可模拟的 vector CSR form: {insn.op_str}")
    if seed.validation_kind == "csr-read":
        return

    value_index = _CSR_VALUE_OPERAND_INDEX_BY_OPCODE.get(insn.opcode)
    expected = 3 if insn.opcode in _VECTOR_CSR_RMW_OPCODES else 2
    if len(operands) != expected or value_index is None or value_index >= len(operands):
        raise InstructionValidationError(
            insn, f"malformed vector CSR 写/读改写: {insn.op_str}"
        )
    source = operands[value_index]
    try:
        source_is_zero = (
            _parse_zimm(source) == 0
            if insn.opcode in _VECTOR_CSR_IMMEDIATE_OPCODES
            else _is_zero_gpr(source)
        )
        operation = _csr_operation_kind(insn.opcode)
    except ValueError as exc:
        raise InstructionValidationError(insn, f"{exc}: {insn.op_str}") from exc
    no_state_write = operation in {"set", "clear"} and source_is_zero
    if csr_name not in _WRITABLE_VECTOR_CSRS and not no_state_write:
        raise InstructionValidationError(
            insn,
            f"RVV256->RVV1024 不允许写只读 vector CSR {csr_name}: {insn.op_str}",
        )


def _validate_data_shape(
    context: HandlerContext,
    seed: _Seed,
    operands: tuple[str, ...],
    memory_eew, index_eew, segment_shapes,
) -> None:
    """按显式 validation kind 检查复杂 EMUL/寄存器组关系。"""

    insn = context.instruction
    base = _base_operands(operands)
    kind = seed.validation_kind
    sew, lmul = _validate_profile(context, seed)

    if kind == "move-simm5":
        try:
            _parse_simm5(base[1])
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        _validate_groups(insn, ((base[0], lmul),))
        return
    elif kind == "integer-same-width" and insn.opcode in {
        "vadd.vi", "vand.vi", "vor.vi", "vrsub.vi"
    }:
        try:
            _parse_simm5(base[2])
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
    elif kind == "integer-same-width" and insn.opcode in {
        "vsll.vi", "vsrl.vi", "vsra.vi"
    }:
        try:
            _parse_uimm5(base[2])
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
    elif kind in {"narrow-immediate", "integer-widen-immediate"}:
        try:
            _parse_uimm5(base[2])
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
    elif kind == "slide-immediate":
        try:
            _parse_slide_uimm5(base[2], insn.opcode)
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc

    if kind in {"float-move", "float-same-width", "float-reduction"}:
        try:
            _require_float_sew(context.state)
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
    if kind == "float-reduction-widen":
        try:
            _float_shape(context.state)
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        if sew not in (16, 32):
            raise InstructionValidationError(
                insn,
                f"{insn.opcode} 仅支持 e16->e32 或 e32->e64，当前为 e{sew}"
            )

    if insn.opcode in {"vmv.s.x", "vmv.x.s", "vfmv.s.f", "vfmv.f.s"}:
        # .s move 只访问 element 0；handler 也按独立 m1 物理寄存器组
        # Pack/执行/Unpack，而不是按当前 source LMUL 读取整组。
        _validate_groups(
            insn,
            ((token, 1.0) for token in _vector_tokens(base)),
        )
        return

    if kind in {
        "same-width", "integer-same-width", "float-move", "float-same-width",
    }:
        groups = [(token, lmul) for token in _vector_tokens(base)]
        _validate_groups(insn, groups)
        return

    if kind in {"reduction", "float-reduction", "float-reduction-widen"}:
        groups = ((base[0], 1.0), (base[1], lmul), (base[2], 1.0))
        _validate_groups(insn, groups)
        return

    if kind in {"integer-reduction-widen"}:
        try:
            _widened_lmul(lmul, sew)
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        groups = ((base[0], 1.0), (base[1], lmul), (base[2], 1.0))
        widths = (1, int(lmul) if lmul >= 1 else 1, 1)
        if len(operands) != len(base):
            widths += (1,)
            groups += (("v0", 1.0),)
        _validate_groups(insn, groups, temp_widths=widths)
        return

    if kind in {"float-convert-widen", "float-widen"}:
        if kind == "float-widen":
            try:
                _sew, source_lmul, _token, result_lmul = _wide_result_shape(
                    context.state, insn.opcode
                )
            except ValueError as exc:
                raise InstructionValidationError(insn, str(exc)) from exc
        else:
            try:
                _float_shape(context.state)
            except ValueError as exc:
                raise InstructionValidationError(insn, str(exc)) from exc
            if sew not in (16, 32):
                raise InstructionValidationError(
                    insn,
                    f"{insn.opcode} 仅支持 e16->e32 或 e32->e64，当前为 e{sew}"
                )
            source_lmul = lmul
            result_lmul = lmul * 2.0
            if result_lmul not in _ALL_LMULS:
                raise InstructionValidationError(
                    insn,
                    f"{insn.opcode} 的宽目的 LMUL={result_lmul:g} 不可用"
                )
        groups = [(base[0], result_lmul)]
        groups.extend((token, source_lmul) for token in _vector_tokens(base[1:]))
        _validate_groups(insn, groups)
        return

    if kind in {"integer-widen", "integer-widen-immediate"}:
        try:
            result_lmul, _width = _widened_lmul(lmul, sew)
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        groups = [(base[0], result_lmul)]
        groups.extend((token, lmul) for token in _vector_tokens(base[1:]))
        if len(operands) != len(base):
            groups.append(("v0", 1.0))
        _validate_groups(insn, groups)
        return

    if kind == "integer-wide-narrow":
        try:
            wide_lmul, _width = _widened_lmul(lmul, sew)
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        groups = ((base[0], wide_lmul), (base[1], wide_lmul), (base[2], lmul))
        _validate_groups(insn, groups)
        return

    if kind.startswith("extend-"):
        factor = int(kind.split("-", 1)[1])
        source_lmul = lmul / factor
        try:
            _validate_lmul(source_lmul, "源")
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        _validate_groups(insn, ((base[0], lmul), (base[1], source_lmul)))
        return

    if kind in {"narrow", "narrow-immediate"}:
        if sew not in (8, 16, 32):
            raise InstructionValidationError(
                insn,
                f"{insn.opcode} 目的 SEW=e8/e16/e32，当前目的 SEW=e{sew}"
            )
        source_lmul = lmul * 2.0
        try:
            _validate_lmul(source_lmul, "宽源")
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        _validate_groups(insn, ((base[0], lmul), (base[1], source_lmul)))
        return

    if kind in {"gather", "gather-e16-index"}:
        index_lmul = lmul
        if kind == "gather-e16-index":
            try:
                index_lmul, _ = _index_e16_shape(lmul, sew)
            except ValueError as exc:
                raise InstructionValidationError(insn, str(exc)) from exc
        _validate_groups(
            insn,
            ((base[0], lmul), (base[1], lmul), (base[2], index_lmul)),
        )
        return

    if kind in {"slide", "slide-immediate", "slide-non-overlap"}:
        _validate_groups(insn, ((base[0], lmul), (base[1], lmul)))
        if kind == "slide-non-overlap" or insn.opcode == "vslideup.vi":
            try:
                _require_non_overlapping_groups(base[0], base[1], lmul, insn.opcode)
            except ValueError as exc:
                raise InstructionValidationError(insn, str(exc)) from exc
        return

    if kind in {"mask-single", "mask-all", "mask-scan"}:
        groups = [(token, 1.0) for token in _vector_tokens(base)]
        # mask 逻辑可按一个临时组顺序搬运；比较/merge 另行声明并行组。
        _validate_groups(insn, groups, temp_widths=(1,) * len(groups))
        return

    if kind == "mask-compare":
        if insn.opcode in {"vmfgt.vf", "vmfle.vf", "vmfne.vf"}:
            try:
                _require_float_sew(context.state)
            except ValueError as exc:
                raise InstructionValidationError(insn, str(exc)) from exc
        if insn.opcode in {
            "vmseq.vi", "vmsne.vi", "vmsle.vi", "vmsgtu.vi", "vmsleu.vi"
        }:
            try:
                _parse_simm5(base[2])
            except ValueError as exc:
                raise InstructionValidationError(insn, str(exc)) from exc
        groups = [(base[0], 1.0), (base[1], lmul)]
        if base[2].lower().startswith("v") and base[2][1:].isdigit():
            groups.append((base[2], lmul))
        _validate_groups(insn, groups)
        return

    if kind == "mask-merge":
        if base[3].lower() != "v0":
            raise InstructionValidationError(
                insn,
                f"{insn.opcode} 的 selector 必须是 v0，得到 {base[3]}"
            )
        if insn.opcode == "vmerge.vim":
            try:
                _parse_simm5(base[2])
            except ValueError as exc:
                raise InstructionValidationError(insn, str(exc)) from exc
        groups = [(base[0], lmul), (base[1], lmul), ("v0", 1.0)]
        if insn.opcode == "vmerge.vvm":
            groups.insert(2, (base[2], lmul))
        _validate_groups(insn, groups)
        return

    if kind in {"memory-unit", "memory-strided"}:
        try:
            emul, _width = _effective_lmul(lmul, sew, memory_eew[insn.opcode])
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        groups = [(base[0], emul)]
        if len(operands) != len(base):
            groups.append(("v0", 1.0))
        _validate_groups(insn, groups)
        return

    if kind == "memory-indexed":
        try:
            index_emul, _ = _effective_lmul(lmul, sew, index_eew[insn.opcode])
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        _validate_groups(insn, ((base[0], lmul), (base[2], index_emul)))
        return

    if kind == "memory-segment":
        eew, field_count, _is_load, _is_strided = segment_shapes[insn.opcode]
        try:
            emul, field_width = _effective_lmul(lmul, sew, eew)
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        if field_count * field_width > 8:
            raise InstructionValidationError(
                insn,
                f"NF={field_count} 与 EMUL={emul:g} 需要 "
                f"{field_count * field_width} 个物理寄存器，超出 RVV segment 上限"
            )
        try:
            fields = _segment_field_registers(base[0], field_width, field_count)
        except ValueError as exc:
            raise InstructionValidationError(insn, str(exc)) from exc
        groups = tuple((field, emul) for field in fields)
        _validate_groups(
            insn,
            groups,
            temp_widths=(field_width,) * field_count,
        )
        return

    raise RuntimeError(f"内部错误：未知 validation kind {kind!r}")


def _validator(seed: _Seed, memory_eew, index_eew, segment_shapes) -> Callable[[HandlerContext], tuple[str, ...]]:
    def validate(context: HandlerContext) -> tuple[str, ...]:
        operands = _normalized_operands(context, seed)
        if (
            seed.opcode in SCALAR_RESULT_OPCODES
            and operands
            and operands[0].lower() in {"sp", "x2"}
        ):
            raise InstructionValidationError(
                context.instruction,
                "RVV256->RVV1024 当前不能安全处理标量结果 rd=sp/x2；"
                f"wrapper 保护帧会丢失该语义结果: {context.instruction.op_str}",
            )
        if seed.validation_kind.startswith("config-"):
            _validate_config(context, seed, operands)
        elif seed.validation_kind.startswith("csr-"):
            _validate_csr(context, seed, operands)
        elif seed.vtype_independent and seed.validation_kind in {
            "whole-move", "whole-memory", "mask-single",
        }:
            # vtype-independent 指令仍需验证固定 raw 物理组；传入任意合法
            # source state 仅用于统一 helper 签名，规则不读取其 SEW/LMUL。
            base = _base_operands(operands)
            if seed.validation_kind == "mask-single":
                groups = [(token, 1.0) for token in _vector_tokens(base)]
                _validate_groups(context.instruction, groups, temp_widths=(1,) * len(groups))
            else:
                factor = _WHOLE_FACTORS[context.instruction.opcode]
                groups = tuple((token, float(factor)) for token in _vector_tokens(base))
                _validate_groups(
                    context.instruction,
                    groups,
                    temp_widths=(1 if factor <= 4 else 2,),
                )
        else:
            _validate_data_shape(context, seed, operands, memory_eew, index_eew, segment_shapes)
        validate_source_operands(context, operands)
        return operands

    return validate
