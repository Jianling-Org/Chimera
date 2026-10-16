"""运行时 vtype CSR 解码与 VLMAX 计算的共享发射器。

RVV 1.0 规定：vill（bit 63）置位、vtype[XLEN-2:8] 保留位非零或保留
vlmul=100 编码的 vtype 都是非法配置，架构行为是 vill=1 且 vl=0。
此前 RVV256 与 RVV1024 过渡两个后端各自维护了一份近似实现，且前者
缺少保留位检查，导致同一架构规则出现两种行为。

本模块提供唯一的解码序列发射器；各后端只提供几何参数（源 VLENB）、
寄存器和失败标签。
"""

from __future__ import annotations


def emit_vlmax_from_vtype(
    lines: list[str],
    *,
    vtype_reg: str,
    out_reg: str,
    sew_reg: str,
    base_reg: str,
    lmul_reg: str,
    tmp_reg: str,
    source_vlenb: int,
    invalid_label: str,
    new_label,
    prefix: str,
) -> None:
    """生成从运行时 ``vtype`` 计算源语义 VLMAX 的标量代码。

    统一执行 RVV 1.0 的完整合法性检查：

    - ``vtype`` bit 63 (vill) 置位 → 非法；
    - ``vtype[62:8]`` 保留位非零 → 非法（corrupted/raw state 不能被
      截取低 8 位后当作可解释的形状继续执行）；
    - ``vsew > 3``（e128 及以上）→ 一期不支持；
    - ``vlmul == 0b100`` → 保留编码。

    合法时按 ``base = VLENB >> vsew``、整数 LMUL 左移 / 分数 LMUL 右移
    计算 VLMAX。调用方负责 ``invalid_label`` 的 vill 语义收尾。
    """

    frac_label = new_label(f"{prefix}_frac")
    done_label = new_label(f"{prefix}_done")

    lines.append(f"    bltz    {vtype_reg}, {invalid_label}        # vill 置位")
    # 保留位检查：先借用 tmp_reg，后续会覆盖，不影响 VLMAX 计算。
    lines.append(f"    srli    {tmp_reg}, {vtype_reg}, 8")
    lines.append(f"    bnez    {tmp_reg}, {invalid_label}        # vtype 保留位非零")
    lines.append(f"    srli    {sew_reg}, {vtype_reg}, 3")
    lines.append(f"    andi    {sew_reg}, {sew_reg}, 7            # vsew")
    lines.append(f"    li      {tmp_reg}, 3")
    lines.append(
        f"    bltu    {tmp_reg}, {sew_reg}, {invalid_label}  # 一期仅支持 e8..e64"
    )
    lines.append(f"    andi    {lmul_reg}, {vtype_reg}, 7         # vlmul")
    lines.append(f"    li      {tmp_reg}, 4")
    lines.append(f"    beq     {lmul_reg}, {tmp_reg}, {invalid_label}  # 100 为保留编码")
    lines.append(f"    li      {base_reg}, {source_vlenb}")
    lines.append(
        f"    srl     {base_reg}, {base_reg}, {sew_reg}  # m1 基数 = VLENB >> vsew"
    )
    lines.append(f"    andi    {tmp_reg}, {lmul_reg}, 4")
    lines.append(f"    bnez    {tmp_reg}, {frac_label}")
    lines.append(f"    sll     {out_reg}, {base_reg}, {lmul_reg}  # 整数 LMUL")
    lines.append(f"    j       {done_label}")
    lines.append(f"{frac_label}:")
    lines.append(f"    li      {tmp_reg}, 8")
    lines.append(f"    sub     {tmp_reg}, {tmp_reg}, {lmul_reg}")
    lines.append(f"    srl     {out_reg}, {base_reg}, {tmp_reg}   # 分数 LMUL")
    lines.append(f"{done_label}:")


__all__ = ["emit_vlmax_from_vtype"]
