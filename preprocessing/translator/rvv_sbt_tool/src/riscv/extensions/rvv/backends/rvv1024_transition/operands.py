"""过渡后端操作数与配置形状校验；不生成汇编。"""

from __future__ import annotations

from typing import NoReturn
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.analysis.model import LMUL_TOKENS
from riscv.frontend.model import RVInstruction
from typing import Any
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.backends.rvv1024_transition.state_view import SOURCE_VLENB


_LEGAL_LMULS = frozenset(LMUL_TOKENS)
SUPPORTED_LMUL = _LEGAL_LMULS
SUPPORTED_SEW = frozenset({8, 16, 32, 64})


def _error(insn: RVInstruction, reason: str) -> NoReturn:
    """以结构化异常拒绝非法 form，禁止把错误伪装成汇编注释。

    各指令族仍复用这个集中出口，以确保真实降低阶段即使遇到遗漏的
    validator 边界，也会在任何半成品汇编离开后端之前原子失败。
    """
    raise InstructionValidationError(
        insn,
        "RVV256->RVV1024 过渡不支持 "
        f"{insn.opcode} at 0x{insn.address:x}: {reason}; operands={insn.op_str}",
    )


def _unmasked_operands(insn: RVInstruction, expected: int) -> list[str] | None:
    """
    提取无掩码操作数。

    ``v0.t`` 不能在一期被当成普通文本后缀丢弃。这样做会让关闭 lane 被错误写回，
    看似可汇编却破坏 RVV 的 mask-undisturbed 语义。因此只要发现任何 ``*.t``
    操作数便返回 ``None``，交由调用方生成明确错误。
    """
    operands = [str(operand).strip() for operand in insn.operands]
    if any(operand.endswith(".t") for operand in operands):
        return None
    if len(operands) != expected:
        return None
    return operands


def _data_operands_with_optional_v0_mask(
    insn: RVInstruction, expected: int
) -> tuple[list[str], str | None] | None:
    """提取普通数据指令的操作数及可选 ``v0.t`` 执行掩码。

    迁移入口的 raw state 只约定 ``v0`` 是执行掩码；即使汇编器接受其他
    ``vN.t``，本路径也不能猜测其与在线状态之间的 ABI。因此这里仅接受精确
    的 ``v0.t``，并把它作为单独的 Pack 源返回，保证在写回 ``vd`` 之前已
    经读取完整掩码。
    """
    operands = [str(operand).strip() for operand in insn.operands]
    if len(operands) == expected:
        if any(operand.endswith(".t") for operand in operands):
            return None
        return operands, None
    if len(operands) == expected + 1:
        mask = operands[-1].lower()
        if mask == "v0.t" and not any(
            operand.endswith(".t") for operand in operands[:-1]
        ):
            return operands[:-1], "v0"
    return None


def _source_shape(state: StateTracker) -> tuple[int, float, str, int]:
    """
    取得源 RVV256 的静态 vtype 形状。

    运行时 ``vl`` 不可信于 Python ``StateTracker.vl``，必须由生成代码从状态 CSR
    读取；但 SEW/LMUL 来自 CFG 注释或前序 vset* 的静态追踪，可用于选择指令编码和
    目标临时寄存器组宽度。
    """
    sew = int(state.sew)
    lmul = float(state.lmul)
    lmul_tokens = LMUL_TOKENS
    if sew not in (8, 16, 32, 64):
        raise ValueError(f"一期只支持 SEW=8/16/32/64，当前为 e{sew}")
    if lmul not in lmul_tokens:
        raise ValueError(f"一期不支持的 LMUL={lmul}")

    # RVV 的 m2/m4/m8 在目标机上分别需要连续的 2/4/8 个临时物理寄存器；
    # fractional LMUL 仍由一个物理寄存器承载，只使用其低位的一部分。
    group_width = int(lmul) if lmul >= 1.0 else 1
    return sew, lmul, lmul_tokens[lmul], group_width


def _require_float_sew(state: StateTracker) -> None:
    """浮点 move 仅接受 RVV 定义的浮点元素宽度。"""
    if int(state.sew) not in (16, 32, 64):
        raise ValueError(f"浮点向量移动不支持 e{state.sew}")


def _parse_simm5(value: str) -> int:
    """
    解析 RVV ``.vi`` / ``vmv.v.i`` 的有符号 5-bit 立即数。

    objdump 可能输出 ``-1``，也可能输出位模式形式 ``0x1f``。两者都应得到相同
    语义值；范围外的数字不能让汇编器悄悄截断。
    """
    raw = int(value, 0)
    if -16 <= raw <= 15:
        return raw
    if 16 <= raw <= 31:
        return raw - 32
    raise ValueError(f"有符号 5-bit 立即数超出范围: {value}")


def _parse_uimm5(value: str) -> int:
    """解析 shift immediate 的无符号 5-bit 编码。"""
    raw = int(value, 0)
    if not 0 <= raw <= 31:
        raise ValueError(f"无符号 5-bit shift immediate 超出范围: {value}")
    return raw


def _lmul_token_and_group_width(lmul: float) -> tuple[str, int]:
    """把一个已验证的 LMUL 转成汇编 token 和目标临时组宽度。

    普通算术的所有向量操作数都使用当前 ``state.lmul``；但 widening
    conversion（扩宽转换）的目的组是 ``2 * LMUL``。把这部分逻辑放在
    单独 helper 中，避免后续 handler 误把目的组仍按源 LMUL Pack/Unpack。
    """
    tokens = LMUL_TOKENS
    if lmul not in tokens:
        raise ValueError(f"不支持的 LMUL={lmul:g}")
    return tokens[lmul], int(lmul) if lmul >= 1 else 1


def _float_shape(state: StateTracker) -> tuple[int, float, str]:
    """取得普通浮点运算的源形状，并拒绝没有对应浮点格式的 e8。"""
    sew, lmul, lmul_token, _ = _source_shape(state)
    _require_float_sew(state)
    return sew, lmul, lmul_token


SOURCE_VLENB = 32


_VECTOR_CSR_ALIASES = {
    "0x008": "vstart",
    "0x009": "vxsat",
    "0x00a": "vxrm",
    "0x00f": "vcsr",
    "0xc20": "vl",
    "0xc21": "vtype",
    "0xc22": "vlenb",
}


_VECTOR_CSR_WRITE_OR_RMW_OPCODES = frozenset({
    "csrw", "csrwi",
    "csrs", "csrsi",
    "csrc", "csrci",
    "csrrw", "csrrwi",
    "csrrs", "csrrsi",
    "csrrc", "csrrci",
})


_VECTOR_CSR_RMW_OPCODES = frozenset({
    "csrrw", "csrrwi", "csrrs", "csrrsi", "csrrc", "csrrci",
})


_VECTOR_CSR_IMMEDIATE_OPCODES = frozenset({
    "csrwi", "csrsi", "csrci", "csrrwi", "csrrsi", "csrrci",
})


_WRITABLE_VECTOR_CSRS = frozenset({"vstart", "vxsat", "vxrm", "vcsr"})


_CSR_OPERAND_INDEX_BY_OPCODE = {
    "csrr": 1,
    "csrw": 0,
    "csrwi": 0,
    "csrs": 0,
    "csrsi": 0,
    "csrc": 0,
    "csrci": 0,
    "csrrw": 1,
    "csrrwi": 1,
    "csrrs": 1,
    "csrrsi": 1,
    "csrrc": 1,
    "csrrci": 1,
}


_CSR_VALUE_OPERAND_INDEX_BY_OPCODE = {
    "csrw": 1,
    "csrwi": 1,
    "csrs": 1,
    "csrsi": 1,
    "csrc": 1,
    "csrci": 1,
    "csrrw": 2,
    "csrrwi": 2,
    "csrrs": 2,
    "csrrsi": 2,
    "csrrc": 2,
    "csrrci": 2,
}


VECTOR_CSR_OFFSETS = {
    **CSR_OFFSETS,
    **{number: CSR_OFFSETS[name] for number, name in _VECTOR_CSR_ALIASES.items()},
}


def normalize_csr_operand(csr: Any) -> str:
    """统一 CSR 操作数字面量，支持别名、十进制和十六进制编号。"""
    text = str(csr).strip().lower()
    if text.startswith("0x"):
        try:
            return f"0x{int(text, 16):03x}"
        except ValueError:
            return text
    if text.isdigit():
        try:
            return f"0x{int(text, 10):03x}"
        except ValueError:
            return text
    return text


def is_vector_csr(csr: Any) -> bool:
    """判断一个 CSR 操作数是否属于需要由迁移状态模拟的向量 CSR。"""
    return normalize_csr_operand(csr) in VECTOR_CSR_OFFSETS


def vector_csr_from_instruction(insn) -> str | None:
    """返回 CSR 指令涉及的 vector CSR 名称；非 vector CSR 返回 ``None``。

    这个 helper 被 new_label、emitter 的 scalar 截获和预检共同使用，避免
    ``csrw vxrm, a0`` 一类 pseudo form 因 CSR 操作数位置不同而漏回普通
    标量 passthrough。
    """
    index = _CSR_OPERAND_INDEX_BY_OPCODE.get(insn.opcode)
    if index is None or len(insn.operands) <= index:
        return None
    normalized = normalize_csr_operand(insn.operands[index])
    if normalized not in VECTOR_CSR_OFFSETS:
        return None
    return _VECTOR_CSR_ALIASES.get(normalized, normalized)


def is_vector_csr_instruction(insn) -> bool:
    """供 new_label 截获全部涉及 vector CSR 的 CSR 读写/读改写 form。"""
    return vector_csr_from_instruction(insn) is not None


def _is_zero_gpr(operand: Any) -> bool:
    """判断 CSR 寄存器源是否为 x0/zero。

    对 ``CSRRS/CSRRC`` 而言，rs1=x0 不写 CSR；这一点不仅影响写回，也决定
    对只读 CSR 能否安全模拟为“读旧值”。
    """
    return str(operand).strip().lower() in {"zero", "x0"}


def _parse_zimm(operand: Any) -> int:
    """解析 CSR immediate 的 5-bit zimm，并在非法文本时给出明确错误。"""
    text = str(operand).strip().lower()
    try:
        value = int(text, 16) if text.startswith("0x") else int(text, 10)
    except ValueError as exc:
        raise ValueError(f"CSR zimm 非法: {operand!r}") from exc
    if not 0 <= value <= 31:
        raise ValueError(f"CSR zimm 超出 5-bit 范围: {operand!r}")
    return value


def _csr_operation_kind(opcode: str) -> str:
    """将 CSR 指令归一化为 write/set/clear 三种 source-state 操作。"""
    lowered = opcode.lower()
    if lowered in {"csrw", "csrwi", "csrrw", "csrrwi"}:
        return "write"
    if lowered in {"csrs", "csrsi", "csrrs", "csrrsi"}:
        return "set"
    if lowered in {"csrc", "csrci", "csrrc", "csrrci"}:
        return "clear"
    raise ValueError(f"未知 vector CSR 写操作: {opcode}")


def _is_rmw_opcode(opcode: str) -> bool:
    """返回该 form 是否把修改前 CSR 值写入 rd。"""
    return opcode.lower() in _VECTOR_CSR_RMW_OPCODES


def _validate_source_profile(state: StateTracker, insn: RVInstruction) -> None:
    """验证本 handler 的 RVV256 源端合同及当前静态 vtype。

    ``StateTracker`` 的 ``vlenb`` 是翻译期的源语义参数，不能默认为项目旧
    路径的 128B。这里显式检查能避免新 new_label 接线错误时，悄悄按
    RVV1024 的 VLMAX 生成错误代码。
    """
    if state.vlenb != SOURCE_VLENB:
        raise InstructionValidationError(
            insn,
            "RVV256->RVV1024 config handler requires "
            f"source vlenb={SOURCE_VLENB}, got {state.vlenb}: {insn.op_str}",
        )
    if state.sew not in SUPPORTED_SEW:
        raise InstructionValidationError(
            insn,
            "RVV256->RVV1024 backend supports "
            f"SEW=8/16/32/64 only: {insn.op_str}",
        )
    if state.lmul not in SUPPORTED_LMUL:
        raise InstructionValidationError(
            insn,
            f"invalid source LMUL for RVV256->RVV1024: {insn.op_str}",
        )


def _widened_lmul(source_lmul: float, sew: int) -> tuple[float, int]:
    """返回宽化目的组的 LMUL 与目标硬件物理组宽度。

RVV 宽化指令的目的 EMUL 是源 LMUL 的两倍。e64 再宽化为 e128 不属于本
路径的一期合同；LMUL=m8 再加倍会越过 RVV 合法 EMUL=m8，也必须在生成前
明确拒绝，而不是让汇编器或目标硬件给出难以定位的结果。
    """
    if sew not in (8, 16, 32):
        raise ValueError(f"宽化指令只支持源 SEW=e8/e16/e32，当前 e{sew}")
    widened = source_lmul * 2
    if widened not in (0.25, 0.5, 1.0, 2.0, 4.0, 8.0):
        raise ValueError(
            f"源 LMUL={source_lmul:g} 的宽化目的 EMUL={widened:g} 超出 m8"
        )
    return widened, int(widened) if widened >= 1 else 1


def _wide_result_shape(
    state: StateTracker,
    native_opcode: str,
) -> tuple[int, float, str, float]:
    """返回窄执行 vtype 与宽目的 LMUL，并拒绝不可验证的浮点宽度。

一期的目标 profile 只承诺 e16→e32 与 e32→e64。虽然 RVV 的抽象模型可以
表达 e64→e128，但当前目标汇编与运行时合同没有验证 e128，因此必须在预检
阶段明确拒绝。``_lmul_token_and_group_width`` 同时拒绝 ``2 * m8 = m16``，
避免把非法目的组留给汇编器才报错。
    """
    sew, source_lmul, source_lmul_token = _float_shape(state)
    if sew not in (16, 32):
        raise ValueError(
            f"{native_opcode} 仅支持 e16->e32 或 e32->e64，当前为 e{sew}"
        )
    result_lmul = source_lmul * 2.0
    try:
        _lmul_token_and_group_width(result_lmul)
    except ValueError as exc:
        raise ValueError(
            f"{native_opcode} 的宽目的 EMUL={result_lmul:g} 不可用: {exc}"
        ) from exc
    return sew, source_lmul, source_lmul_token, result_lmul


def _validate_lmul(value: float, role: str) -> tuple[str, int]:
    """验证某个源/目的 EMUL，并返回目标临时组需要的宽度。"""
    if value not in _LEGAL_LMULS:
        raise ValueError(f"{role} EMUL={value:g} 不是 RVV 合法 LMUL")
    return _lmul_token_and_group_width(value)


def _index_e16_shape(source_lmul: float, source_sew: int) -> tuple[float, int]:
    """返回 ``vrgatherei16`` 索引操作数的源 EMUL 与临时组宽度。

    ``vrgatherei16.vv`` 的 ``vs1`` 固定以 e16 解释，而数据 ``vd/vs2`` 仍按
    当前 SEW/LMUL 解释。因此其 EMUL 是 ``LMUL * 16 / SEW``。这和 indexed
    memory 的 offsets 规则相同，但不能偷用普通 gather 的 LMUL：例如 source
    e8,m1 时 index 是 m2（64B），source e32,m1 时则是 mf2（16B）。

    RVV 不允许得到 m16 或其它非法 EMUL。此处在翻译期拒绝，确保非法组既不
    访问 raw state，也不会在输出中留下逐指令 fallback。
    """
    index_lmul = source_lmul * 16 / source_sew
    if index_lmul not in _LEGAL_LMULS:
        raise ValueError(
            "vrgatherei16.vv 的 index EMUL="
            f"{index_lmul:g} 不在 mf8..m8 范围内 "
            f"(SEW=e{source_sew}, LMUL={source_lmul:g})"
        )
    return index_lmul, int(index_lmul) if index_lmul >= 1 else 1


def _parse_slide_uimm5(value: str, opcode: str) -> int:
    """解析 slide ``.vi`` 的无符号 5-bit offset。

    RVV 的 ``vslide*.vi`` offset 在编码中只有五位。objdump 既可能打印十进制，
    也可能打印 ``0x1f``，因此用 ``base=0`` 解析；范围外则 fail-closed，不能
    依赖目标汇编器截断或报错。
    """
    try:
        offset = int(str(value), 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{opcode} 的 uimm 必须是无符号整数: {value!r}") from exc
    if not 0 <= offset <= 31:
        raise ValueError(f"{opcode} 的 uimm 超出无符号 5-bit 范围: {value!r}")
    return offset


def _source_group_span(vreg: str, lmul: float) -> tuple[int, int]:
    """返回源 RVV256 逻辑组覆盖的物理 vreg 区间 ``[begin, end)``。

    该检查有两层用途：

    * 主动验证 ``m2/m4/m8`` 起始寄存器的对齐和 v31 边界，避免在 handler
      已发射部分文本后才由 Pack 层抛出异常；
    * 精确实施规范对 ``vslideup`` / ``vslide1up`` 的 non-overlap 限制。

    fractional LMUL 在物理寄存器层仍占一个寄存器，因此用宽度 1 表示；其有效
    raw byte 数由 state view 的 Pack/Unpack 决定，不在这里扩大。
    """
    text = str(vreg).strip().lower()
    if not text.startswith("v") or not text[1:].isdigit():
        raise ValueError(f"源向量寄存器必须为 v0..v31，得到 {vreg!r}")
    begin = int(text[1:])
    if not 0 <= begin <= 31:
        raise ValueError(f"源向量寄存器超出范围: {vreg}")

    width = int(lmul) if lmul >= 1.0 else 1
    if begin % width:
        raise ValueError(f"源 {vreg} 不是 m{width} 组对齐起点")
    end = begin + width
    if end > 32:
        raise ValueError(f"源 {vreg} 的 LMUL 组越过 v31")
    return begin, end


def _require_non_overlapping_groups(vd: str, vs2: str, lmul: float, opcode: str) -> None:
    """拒绝规范保留的 slide-up source/destination 重叠编码。"""
    vd_begin, vd_end = _source_group_span(vd, lmul)
    vs2_begin, vs2_end = _source_group_span(vs2, lmul)
    if max(vd_begin, vs2_begin) < min(vd_end, vs2_end):
        raise ValueError(
            f"{opcode} 的目的组 {vd} 与 source 组 {vs2} 重叠；"
            "RVV 规范将该编码保留，本过渡路径拒绝生成新语义"
        )


def _effective_lmul(source_lmul: float, source_sew: int, eew: int) -> tuple[float, int]:
    """返回内存操作数的 EMUL 数值及其硬件物理组宽度。"""
    emul = source_lmul * eew / source_sew
    if emul not in _LEGAL_LMULS:
        raise ValueError(
            f"EEW=e{eew} 与 SEW=e{source_sew}, LMUL={source_lmul:g} 的 EMUL={emul:g} 不合法"
        )
    return emul, int(emul) if emul >= 1 else 1


def _segment_field_registers(first_vreg: str, field_width: int, field_count: int) -> list[str]:
    """按 segment 的 EMUL 间距列出 source raw field group 的首寄存器。

    例如 e64,m2 的 ``vsseg4e64.v v8`` 的四个 field 分别从
    ``v8/v10/v12/v14`` 开始；e32,m1 的 ``vlseg2e32.v v8`` 则是 ``v8/v9``。
    每个 group 的精确对齐和越界检查仍交给 state_view 的 Pack/Unpack 完成，
    这里仅负责从 segment 基址推导其余 field 的名称。
    """
    text = str(first_vreg).strip().lower()
    if not text.startswith("v") or not text[1:].isdigit():
        raise ValueError(f"segment 首向量寄存器必须为 v0..v31，得到 {first_vreg!r}")
    base = int(text[1:])
    if not 0 <= base <= 31:
        raise ValueError(f"segment 首向量寄存器超出范围: {first_vreg}")
    if field_width < 1 or field_count < 1:
        raise ValueError("segment field 宽度和数量必须为正数")
    return [f"v{base + field * field_width}" for field in range(field_count)]
