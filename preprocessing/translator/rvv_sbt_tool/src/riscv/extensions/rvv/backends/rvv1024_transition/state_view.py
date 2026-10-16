"""RVV256 紧凑物理寄存器状态的汇编发射辅助函数。

``simulated_cpu_state`` 的缓冲区大小和 CSR 页沿用现有 ABI；但在线迁移入口
保存 RVV256 时，向量 payload 是 ``v0..v31`` 每个 32B 的连续原生布局。
本模块是新路径唯一允许计算该 payload 地址的地方，避免误用
``SimulatedStateLayout.get_offset('vN')`` 的 128B 旧槽位。
"""

from __future__ import annotations

from numbers import Real

from riscv.extensions.rvv.runtime.access import STATE_BASE_MARKER
from riscv.extensions.rvv.runtime.geometry import RVV256_TO_RVV1024_GEOMETRY
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.analysis.model import LMUL_TOKENS


# 方向常量从几何单一权威派生；state_view 是紧凑 payload 布局的唯一解释者，
# 但 32/128 本身属于翻译方向几何，不应在此重新定义。
SOURCE_VLENB = RVV256_TO_RVV1024_GEOMETRY.source_vlenb
TARGET_VLENB = RVV256_TO_RVV1024_GEOMETRY.target_vlenb
# 状态基址标记只在 riscv.extensions.rvv.runtime.access 定义；模块内沿用历史下划线名。
_STATE_BASE_MARKER = STATE_BASE_MARKER

# token→数值 的反向映射从 riscv.extensions.rvv.analysis.model 的唯一表派生，不再本地维护字面量。
_LMUL_TOKEN_TO_VALUE = {token: value for value, token in LMUL_TOKENS.items()}


def _normalize_lmul(lmul: str | Real) -> float:
    """把文本或数值 LMUL 归一化，并拒绝不能表示精确物理字节数的值。"""
    if isinstance(lmul, str):
        value = _LMUL_TOKEN_TO_VALUE.get(lmul.lower().strip())
        if value is None:
            raise ValueError(f"未知源 LMUL: {lmul}")
        return value
    value = float(lmul)
    if value not in _LMUL_TOKEN_TO_VALUE.values():
        raise ValueError(f"不支持的源 LMUL: {lmul}")
    return value


def _source_vreg_number(source_vreg: str) -> int:
    """解析源物理 vreg 名称，严格拒绝临时/掩码后缀等非寄存器文本。"""
    text = str(source_vreg).strip().lower()
    if not text.startswith("v") or not text[1:].isdigit():
        raise ValueError(f"源向量寄存器必须为 v0..v31，得到 {source_vreg!r}")
    number = int(text[1:])
    if not 0 <= number <= 31:
        raise ValueError(f"源向量寄存器超出范围: {source_vreg}")
    return number


def source_group_byte_size(lmul: str | Real) -> int:
    """返回一个 RVV256 逻辑寄存器组在 raw payload 中的精确字节数。"""
    result = SOURCE_VLENB * _normalize_lmul(lmul)
    if int(result) != result:
        raise ValueError(f"源 LMUL 不能得到整数 byte 数: {lmul}")
    return int(result)


def transfer_lmul_for_bytes(byte_count: int) -> str:
    """为精确字节搬运选择 RVV1024 e8 传输组。

    m1 容纳 128B；源 m8 的 256B 组需要 m2。传输配置仅用于 Pack/Unpack，
    绝不可和随后按源语义执行的 LMUL 混为一谈。
    """
    if not 1 <= byte_count <= SOURCE_VLENB * 8:
        raise ValueError(f"RVV256 源组字节数必须位于 1..256，得到 {byte_count}")
    return "m1" if byte_count <= TARGET_VLENB else "m2"


def validate_source_group(source_vreg: str, lmul: str | Real) -> tuple[int, int]:
    """验证源组边界并返回组起点和字节数，不生成任何汇编。

    prepare 与 Pack/Unpack 共用这个公开纯函数，避免为了验证物理组合法性
    调用 lowerer 后再丢弃生成文本。
    """
    number = _source_vreg_number(source_vreg)
    value = _normalize_lmul(lmul)
    width = int(value) if value >= 1 else 1
    if value >= 1 and number % width:
        raise ValueError(f"源 {source_vreg} 不是 m{width} 组对齐起点")
    if number + width > 32:
        raise ValueError(f"源 {source_vreg} 的 LMUL 组越过 v31")
    return number, source_group_byte_size(value)


def emit_source_vreg_address(
    lines: list[str],
    address_reg: str,
    source_vreg: str,
) -> None:
    """发射 ``address_reg = t6 + raw_offset``，其中 ``vN`` 位于 ``N*32``。"""
    number = _source_vreg_number(source_vreg)
    offset = number * SOURCE_VLENB
    if offset == 0:
        lines.append(f"    mv      {address_reg}, t6  # {_STATE_BASE_MARKER}")
    else:
        lines.append(
            f"    addi    {address_reg}, t6, {offset}  # {_STATE_BASE_MARKER}"
        )


def emit_pack_source_group(
    lines: list[str],
    target_vreg: str,
    address_reg: str,
    source_vreg: str,
    lmul: str | Real,
    avl_reg: str,
) -> None:
    """按精确字节数把一个源 RVV256 组 Pack 到目标 RVV1024 临时组。"""
    _, byte_count = validate_source_group(source_vreg, lmul)
    transfer_lmul = transfer_lmul_for_bytes(byte_count)
    emit_source_vreg_address(lines, address_reg, source_vreg)
    lines.append(f"    li      {avl_reg}, {byte_count}             # Pack 源组有效字节数")
    lines.append(f"    vsetvli zero, {avl_reg}, e8, {transfer_lmul}, tu, mu")
    lines.append(f"    vle8.v  {target_vreg}, ({address_reg})       # Pack 紧凑 RVV256 物理组")


def emit_unpack_source_group(
    lines: list[str],
    target_vreg: str,
    address_reg: str,
    source_vreg: str,
    lmul: str | Real,
    avl_reg: str,
) -> None:
    """将目标临时组的源有效字节精确 Unpack 回 RVV256 raw payload。"""
    _, byte_count = validate_source_group(source_vreg, lmul)
    transfer_lmul = transfer_lmul_for_bytes(byte_count)
    emit_source_vreg_address(lines, address_reg, source_vreg)
    lines.append(f"    li      {avl_reg}, {byte_count}             # Unpack 源组有效字节数")
    lines.append(f"    vsetvli zero, {avl_reg}, e8, {transfer_lmul}, tu, mu")
    lines.append(f"    vse8.v  {target_vreg}, ({address_reg})       # 写回紧凑 RVV256 物理组")


def emit_csr_address(lines: list[str], address_reg: str, csr: str) -> None:
    """取得状态块中固定 CSR 槽位地址。"""
    if csr not in CSR_OFFSETS:
        raise ValueError(f"未知模拟 RVV CSR: {csr}")
    offset = CSR_OFFSETS[csr]
    lines.append(f"    li      {address_reg}, {offset:#x}")
    lines.append(f"    add     {address_reg}, t6, {address_reg}  # {_STATE_BASE_MARKER}")


def emit_load_csr(lines: list[str], value_reg: str, address_reg: str, csr: str) -> None:
    """读取 CSR；不同于 value_reg 的 address_reg 保留 vstart 槽的地址。"""
    if csr not in CSR_OFFSETS:
        raise ValueError(f"未知模拟 RVV CSR: {csr}")
    emit_csr_address(lines, address_reg, "vstart")
    offset = CSR_OFFSETS[csr] - CSR_OFFSETS["vstart"]
    lines.append(f"    ld      {value_reg}, {offset}({address_reg})       # 源 CSR.{csr}")


def emit_store_csr(lines: list[str], value_reg: str, address_reg: str, csr: str) -> None:
    """向既有状态 ABI 写入一个 64-bit 向量 CSR。"""
    if csr not in CSR_OFFSETS:
        raise ValueError(f"未知模拟 RVV CSR: {csr}")
    emit_csr_address(lines, address_reg, "vstart")
    offset = CSR_OFFSETS[csr] - CSR_OFFSETS["vstart"]
    lines.append(f"    sd      {value_reg}, {offset}({address_reg})       # 源 CSR.{csr}")


def emit_clear_state_vstart(lines: list[str], address_reg: str) -> None:
    """正常完成的源向量指令必须把 state 中的 ``vstart`` 清零。"""
    emit_csr_address(lines, address_reg, "vstart")
    lines.append(f"    sd      zero, 0({address_reg})              # 源 CSR.vstart = 0")


def emit_profile_guard(
    lines: list[str],
    state_vlenb_reg: str,
    hardware_vlenb_reg: str,
    vstart_reg: str,
    scratch_reg: str,
    failure_label: str,
    *,
    require_zero_vstart: bool,
) -> None:
    """检查迁移前提，失败时跳到调用方的拒绝标签。

    三个值寄存器的生存期不重叠，可以互为别名；scratch_reg 必须与它们
    不同，成功后保留 t6 + CSR_OFFSETS["vstart"] 供调用方继续读取 CSR。
    """
    emit_load_csr(lines, state_vlenb_reg, scratch_reg, "vlenb")
    lines.append(f"    addi    {state_vlenb_reg}, {state_vlenb_reg}, {-SOURCE_VLENB}")
    lines.append(f"    bnez    {state_vlenb_reg}, {failure_label}")
    lines.append(f"    csrr    {hardware_vlenb_reg}, vlenb         # 真实 RVV1024 硬件 VLENB")
    lines.append(f"    addi    {hardware_vlenb_reg}, {hardware_vlenb_reg}, {-TARGET_VLENB}")
    lines.append(f"    bnez    {hardware_vlenb_reg}, {failure_label}")
    if require_zero_vstart:
        lines.append(f"    ld      {vstart_reg}, 0({scratch_reg})       # 源 CSR.vstart")
        lines.append(f"    bnez    {vstart_reg}, {failure_label}       # 一期不支持陷阱重启")



__all__ = [
    "SOURCE_VLENB",
    "TARGET_VLENB",
    "source_group_byte_size",
    "transfer_lmul_for_bytes",
    "validate_source_group",
    "emit_source_vreg_address",
    "emit_pack_source_group",
    "emit_unpack_source_group",
]
