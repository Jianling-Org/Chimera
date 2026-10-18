"""RVV256 后端的分块、访存和标量尾部执行支撑。"""

from __future__ import annotations

from typing import List
from riscv.extensions.rvv.runtime.access import STATE_BASE_MARKER
from riscv.extensions.rvv.runtime.geometry import RVV1024_TO_RVV256_GEOMETRY
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.translation.temps import record_vreg_group


_STATE_BASE_MARKER = STATE_BASE_MARKER


def _emit_state_ptr(lines: List[str], dst_reg: str, offset: int) -> None:
    """
    生成 ``dst_reg = t6 + offset``，并尽量减少实际执行指令数。

    ``t6`` 是单条翻译块内的 simulated_cpu_state 基址。低 12-bit 正偏移
    可以直接由 ``addi`` 编码；较大偏移继续让目标汇编器负责展开 ``li``，
    从而不在各 handler 中重复维护立即数拆分逻辑。

    该 helper 只写 ``dst_reg``，调用方必须保证它不是仍然活跃的语义输入。
    """
    if offset == 0:
        lines.append(f"    mv      {dst_reg}, t6  # {_STATE_BASE_MARKER}")
    elif 0 < offset <= 2047:
        lines.append(f"    addi    {dst_reg}, t6, {offset}  # {_STATE_BASE_MARKER}")
    else:
        lines.append(f"    li      {dst_reg}, {offset:#x}")
        lines.append(f"    add     {dst_reg}, t6, {dst_reg}  # {_STATE_BASE_MARKER}")


def _chunk_size(sew: int) -> int:
    """计算每个目标块中的元素数量（几何事实，不再内联 256//sew）。"""
    return RVV1024_TO_RVV256_GEOMETRY.elements_per_chunk(sew)


def _chunk_bytes() -> int:
    """返回一个目标块的字节数（恒为目标 VLENB=32）。"""
    return RVV1024_TO_RVV256_GEOMETRY.chunk_bytes()


def _emit_vsetvl_for_chunk(
    lines: List[str],
    chunk_n: int,
    sew: int,
    lmul: str = "m1",
    avl_reg: str = "t0",
    scratch_reg: str | None = None,
) -> None:
    """
    为一个 256-bit 块发出 vtype 设置。

    vsetivli 的 AVL 立即数只有 5 位 (最大 31)，因此 e8/m1 (32 元素)
    的块必须使用寄存器 AVL 形式的 vsetvli。
    """
    if chunk_n <= 31:
        lines.append(f"    vsetivli zero, {chunk_n}, e{sew}, {lmul}, ta, ma")
        return

    if scratch_reg is None:
        raise ValueError(
            f"_emit_vsetvl_for_chunk requires scratch_reg for AVL={chunk_n}"
        )

    lines.append(f"    li      {scratch_reg}, {chunk_n}")
    lines.append(f"    vsetvli zero, {scratch_reg}, e{sew}, {lmul}, ta, ma")


def _load_vl_from_csr(lines: List[str], vl_reg: str, addr_reg: str) -> None:
    """
    从 simulated_cpu_state 的 CSR 区域加载 vl 值

    :param lines: 输出行列表
    :param vl_reg: 目标寄存器 (存放 vl 值)
    :param addr_reg: 临时地址寄存器
    """
    vl_offset = CSR_OFFSETS['vl']
    csr_page = vl_offset & ~0xFFF
    csr_low = vl_offset - csr_page
    lines.append(f"    li      {addr_reg}, {csr_page:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(
        f"    ld      {vl_reg}, {csr_low}({addr_reg})"
        f"  # {vl_reg} = vl (from simulated CSR)"
    )


def _get_vle_instr(sew: int) -> str:
    """返回对应 SEW 的向量加载指令"""
    return {8: 'vle8.v', 16: 'vle16.v', 32: 'vle32.v', 64: 'vle64.v'}[sew]


def _get_vse_instr(sew: int) -> str:
    """返回对应 SEW 的向量存储指令"""
    return {8: 'vse8.v', 16: 'vse16.v', 32: 'vse32.v', 64: 'vse64.v'}[sew]


def _emit_mask_setup(lines: List[str], mask_bit_idx: str, v0_base: str, temp: str) -> None:
    """
    初始化掩码的全局索引和模拟 v0 的基址。

    ``v0`` 的状态槽偏移恒为零，因而只需复制块内 ``t6`` 状态基址。旧实现
    先 materialize（实体化）常数 0 再相加，既不增加语义信息，也会在每条
    masked 源指令多出一条无效 GPR 指令。保留 ``temp`` 参数是为了不破坏
    大量既有 handler 的调用签名；它不再被写入。
    """
    lines.append(f"    # --- Mask Setup ---")
    lines.append(f"    li      {mask_bit_idx}, 0                # 初始化全局元素掩码索引")
    # 必须通过统一 helper 生成状态基址标记。若源指令同时把 t6 用作访存
    # 基址，ProgramEmitter 会把“语义 t6”改写为别名，但这里仍必须指向 TLS 状态块。
    _emit_state_ptr(lines, v0_base, 0)
    lines.append(f"    # {v0_base} = &simulated_v0")
    lines.append("")


def _emit_mask_load_byte_aligned_chunk(
    lines: List[str],
    sew: int,
    mask_bit_idx: str,
    v0_base: str,
    scratch: str,
) -> None:
    """
    在当前目标 ``vset*`` 已建立后，直接将一整个 byte-aligned mask chunk
    载入硬件 ``v0``。

    m1 的 e8/e16/e32 完整块分别消耗 32/16/8 个 mask bit，块首均落在
    整字节边界。``vlm.v`` 会按当前 ``vl`` 解释 bit-packed（位压缩）布局，
    因而能替换旧路径的 GPR load、位移、e64 单元素 vset 和 ``vmv.v.x``。
    e64,m1 每块只有 4 bit，下一块从同一字节的高半部分开始，不能直接调用
    本 helper，必须继续使用显式右移重排逻辑。

    调用方负责确保：
    - 已为这一完整块设置正确的 eSEW,m1 vtype 和 VL；
    - ``mask_bit_idx`` 是当前块首的全局元素索引；
    - ``scratch`` 在当前循环体后不再保存活跃语义值。
    """
    if sew not in (8, 16, 32):
        raise ValueError(f"e{sew},m1 mask chunk 不是字节对齐直接 vlm 范围")
    lines.append("    # --- Direct byte-aligned mask chunk into v0 ---")
    lines.append(f"    srli    {scratch}, {mask_bit_idx}, 3")
    lines.append(f"    add     {scratch}, {v0_base}, {scratch}")
    record_vreg_group("v0", 1)
    lines.append(f"    vlm.v   v0, ({scratch})")
    lines.append("")


def _emit_mask_extraction_chunk(
    lines: List[str],
    sew: int,
    mask_bit_idx: str,
    v0_base: str,
    tmp1: str,
    tmp2: str,
) -> None:
    """提取一个 chunk_n 的掩码比特到真实硬件的 v0 寄存器，仅需两个临时寄存器"""
    lines.append(f"    # --- Extract mask chunk into v0 ---")
    lines.append(f"    srli    {tmp1}, {mask_bit_idx}, 3")
    lines.append(f"    add     {tmp1}, {v0_base}, {tmp1}           # {tmp1} = mask_addr")

    if sew == 8:
        lines.append(f"    lwu     {tmp2}, 0({tmp1})                  # {tmp2} = mask_val")
    elif sew == 16:
        lines.append(f"    lhu     {tmp2}, 0({tmp1})")
    elif sew in (32, 64):
        lines.append(f"    lbu     {tmp2}, 0({tmp1})")

    lines.append(f"    andi    {tmp1}, {mask_bit_idx}, 7           # {tmp1} = bit_offset")
    lines.append(f"    srl     {tmp2}, {tmp2}, {tmp1}")
    lines.append(f"    vsetivli zero, 1, e64, m1, ta, ma")
    record_vreg_group("v0", 1)
    lines.append(f"    vmv.v.x v0, {tmp2}")
    lines.append("")


def _emit_mask_extraction_tail(
    lines: List[str],
    mask_bit_idx: str,
    v0_base: str,
    tmp1: str,
    tmp2: str,
    skip_label: str,
) -> None:
    """为标量尾部循环提取 1 个掩码比特，若为 0 则跳转，仅需两个临时寄存器"""
    lines.append(f"    srli    {tmp1}, {mask_bit_idx}, 3")
    lines.append(f"    add     {tmp1}, {v0_base}, {tmp1}")
    lines.append(f"    lbu     {tmp2}, 0({tmp1})")
    lines.append(f"    andi    {tmp1}, {mask_bit_idx}, 7")
    lines.append(f"    srl     {tmp2}, {tmp2}, {tmp1}")
    lines.append(f"    andi    {tmp2}, {tmp2}, 1")
    lines.append(f"    beqz    {tmp2}, {skip_label}         # If mask is 0, skip element")


def _get_float_instr(suffix: str, sew: int) -> str:
    """
    根据 SEW 返回对应的标量浮点指令

    :param suffix: 指令类别 ('load', 'store', 'madd', 'add', 'mul')
    :param sew: 元素宽度 (32 或 64)
    :return: 指令助记符 (如 'fld', 'fmadd.d', 'fadd.s')
    """
    if sew == 16:
        instr_map = {
            'load': 'flh',
            'store': 'fsh',
            'madd': 'fmadd.h',
            'add': 'fadd.h',
            'sub': 'fsub.h',
            'mul': 'fmul.h',
            'abs': 'fabs.h',
            'neg': 'fneg.h',
            'nmsub': 'fnmsub.h',
            'nmsub': 'fnmsub.h',
        }
    elif sew == 32:
        instr_map = {
            'load': 'flw',
            'store': 'fsw',
            'madd': 'fmadd.s',
            'add': 'fadd.s',
            'sub': 'fsub.s',
            'mul': 'fmul.s',
            'abs': 'fabs.s',
            'neg': 'fneg.s',
            'nmsub': 'fnmsub.s',
            'nmsub': 'fnmsub.s',
        }
    elif sew == 64:
        instr_map = {
            'load': 'fld',
            'store': 'fsd',
            'madd': 'fmadd.d',
            'add': 'fadd.d',
            'sub': 'fsub.d',
            'mul': 'fmul.d',
            'abs': 'fabs.d',
            'neg': 'fneg.d',
            'nmsub': 'fnmsub.d',
            'nmsub': 'fnmsub.d',
        }
    else:
        return f".word 0x0 # ILLEGAL_FLOAT_SEW_{sew}_{suffix}"
    return instr_map[suffix]


def _get_int_load_unsigned(sew: int) -> str:
    """返回对应 SEW 的无符号整数加载指令。"""
    return {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[sew]


def _get_int_load_signed(sew: int) -> str:
    """返回对应 SEW 的有符号整数加载指令。"""
    return {8: 'lb', 16: 'lh', 32: 'lw', 64: 'ld'}[sew]


def _get_int_store(sew: int) -> str:
    """返回对应 SEW 的整数存储指令。"""
    return {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]


def _emit_scalar_tail_vf(
    lines: List[str],
    sew: int,
    tail_reg: str,
    vs2_ptr: str,
    vd_ptr: str,
    rs1: str,
    vs2_fpr: str,
    vd_fpr: str,
    tail_label: str,
    end_label: str,
    op_type: str = 'madd',
    is_masked: bool = False,
    mask_bit_idx: str = "",
    v0_base: str = "",
    mask_tmp1: str = "",
    mask_tmp2: str = "",
) -> None:
    store_instr = _get_float_instr('store', sew)
    load_instr = _get_float_instr('load', sew)
    elem_bytes = sew // 8

    lines.append(f"{tail_label}:                              # 标量尾部回退")
    lines.append(f"    beqz    {tail_reg}, {end_label}")

    skip_label = f"{tail_label}_skip"
    if is_masked:
        _emit_mask_extraction_tail(lines, mask_bit_idx, v0_base, mask_tmp1, mask_tmp2, skip_label)

    lines.append(f"    {load_instr:<8} {vs2_fpr}, 0({vs2_ptr})          # {vs2_fpr} = {vs2_ptr}[0]")
    lines.append(f"    {load_instr:<8} {vd_fpr}, 0({vd_ptr})           # {vd_fpr} = {vd_ptr}[0]")

    if op_type == 'madd':
        op_instr = _get_float_instr('madd', sew)
        lines.append(f"    {op_instr:<8} {vd_fpr}, {vs2_fpr}, {rs1}, {vd_fpr}           # {vd_fpr} = {vs2_fpr} * {rs1} + {vd_fpr}")
    elif op_type == 'nmsub':
        op_instr = _get_float_instr('nmsub', sew)
        lines.append(f"    {op_instr:<8} {vd_fpr}, {vs2_fpr}, {rs1}, {vd_fpr}           # {vd_fpr} = -({vs2_fpr} * {rs1}) + {vd_fpr}")
    elif op_type == 'add':
        op_instr = _get_float_instr('add', sew)
        lines.append(f"    {op_instr:<8} {vd_fpr}, {vs2_fpr}, {rs1}                # {vd_fpr} = {vs2_fpr} + {rs1}")
    elif op_type == 'mul':
        op_instr = _get_float_instr('mul', sew)
        lines.append(f"    {op_instr:<8} {vd_fpr}, {vs2_fpr}, {rs1}                # {vd_fpr} = {vs2_fpr} * {rs1}")
    else:
        raise ValueError(f"不支持的尾部操作类型: {op_type}")

    lines.append(f"    {store_instr:<8} {vd_fpr}, 0({vd_ptr})           # 写回 {vd_ptr}[0]")

    if is_masked:
        lines.append(f"{skip_label}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")

    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_reg}, {tail_reg}, -1")
    lines.append(f"    j       {tail_label}")
    lines.append(f"{end_label}:")


def _emit_scalar_tail_int_vv(
    lines: List[str],
    sew: int,
    tail_reg: str,
    vs2_ptr: str,
    vs1_ptr: str,
    vd_ptr: str,
    tmp0: str,
    tmp1: str,
    tail_label: str,
    end_label: str,
    op_type: str = 'add',
    is_masked: bool = False,
    mask_bit_idx: str = "",
    v0_base: str = "",
    mask_tmp1: str = "",
    mask_tmp2: str = "",
) -> None:
    store_instr = _get_int_store(sew)
    load_instr = _get_int_load_unsigned(sew)
    elem_bytes = sew // 8

    lines.append(f"{tail_label}:                              # 整数标量尾部回退")
    lines.append(f"    beqz    {tail_reg}, {end_label}")

    skip_label = f"{tail_label}_skip"
    if is_masked:
        _emit_mask_extraction_tail(lines, mask_bit_idx, v0_base, mask_tmp1, mask_tmp2, skip_label)

    lines.append(f"    {load_instr:<8} {tmp0}, 0({vs2_ptr})")
    lines.append(f"    {load_instr:<8} {tmp1}, 0({vs1_ptr})")

    if op_type == 'add':
        lines.append(f"    add     {tmp0}, {tmp0}, {tmp1}")
    elif op_type == 'sub':
        lines.append(f"    sub     {tmp0}, {tmp0}, {tmp1}")
    elif op_type in ('min', 'max', 'minu', 'maxu'):
        lines.append(f"    # {op_type} not natively single-instruction in base RV64I, using branch")
        lbl_skip = f"{tail_label}_{op_type}_skip"
        if op_type == 'min':
            lines.append(f"    blt     {tmp0}, {tmp1}, {lbl_skip}")
        elif op_type == 'max':
            lines.append(f"    bgt     {tmp0}, {tmp1}, {lbl_skip}")
        elif op_type == 'minu':
            lines.append(f"    bltu    {tmp0}, {tmp1}, {lbl_skip}")
        elif op_type == 'maxu':
            lines.append(f"    bgtu    {tmp0}, {tmp1}, {lbl_skip}")
        lines.append(f"    mv      {tmp0}, {tmp1}")
        lines.append(f"{lbl_skip}:")
    else:
        raise ValueError(f"不支持的整数尾部操作类型: {op_type}")

    # truncation
    if sew == 8:
        lines.append(f"    andi    {tmp0}, {tmp0}, 0xFF")
    elif sew == 16:
        lines.append(f"    li      {mask_tmp2}, 0xFFFF")
        lines.append(f"    and     {tmp0}, {tmp0}, {mask_tmp2}")
    elif sew == 32:
        lines.append(f"    slli    {tmp0}, {tmp0}, 32")
        lines.append(f"    srli    {tmp0}, {tmp0}, 32")

    lines.append(f"    {store_instr:<8} {tmp0}, 0({vd_ptr})")

    if is_masked:
        lines.append(f"{skip_label}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")

    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_reg}, {tail_reg}, -1")
    lines.append(f"    j       {tail_label}")
    lines.append(f"{end_label}:")


def _emit_scalar_tail_vv(
    lines: List[str],
    sew: int,
    tail_reg: str,
    vs2_ptr: str,
    vs1_ptr: str,
    vd_ptr: str,
    tail_label: str,
    end_label: str,
    op_type: str = 'madd',
    widen: bool = False,
    is_masked: bool = False,
    mask_bit_idx: str = "",
    v0_base: str = "",
    mask_tmp1: str = "",
    mask_tmp2: str = "",
) -> None:
    store_instr = _get_float_instr('store', sew if not widen else sew * 2)
    elem_bytes_in = sew // 8
    elem_bytes_out = (sew * 2) // 8 if widen else sew // 8

    lines.append(f"{tail_label}:                              # 标量尾部回退")
    lines.append(f"    beqz    {tail_reg}, {end_label}")

    skip_label = f"{tail_label}_skip"
    if is_masked:
        _emit_mask_extraction_tail(lines, mask_bit_idx, v0_base, mask_tmp1, mask_tmp2, skip_label)

    if widen:
        load_instr_in = _get_float_instr('load', sew)
        load_instr_out = _get_float_instr('load', sew * 2)

        lines.append(f"    {load_instr_in:<8} ft0, 0({vs2_ptr})         # ft0 = {vs2_ptr}[0]")
        lines.append(f"    {load_instr_in:<8} ft1, 0({vs1_ptr})         # ft1 = {vs1_ptr}[0]")
        if sew == 32:
            lines.append(f"    fcvt.d.s ft0, ft0                     # widen to 64-bit")
            lines.append(f"    fcvt.d.s ft1, ft1                     # widen to 64-bit")
            fma_instr = "fmadd.d"
        elif sew == 16:
            lines.append(f"    fcvt.s.h ft0, ft0                     # widen to 32-bit")
            lines.append(f"    fcvt.s.h ft1, ft1                     # widen to 32-bit")
            fma_instr = "fmadd.s"
        else:
            raise ValueError(f"宽化浮点尾部不支持 SEW={sew}")

        lines.append(f"    {load_instr_out:<8} ft2, 0({vd_ptr})          # ft2 = {vd_ptr}[0]")

        if op_type == 'madd':
            lines.append(f"    {fma_instr} ft2, ft0, ft1, ft2               # ft2 = ft0 * ft1 + ft2")
        else:
            lines.append(f"    {fma_instr} ft2, ft0, ft1, ft2               # ft2 = ft0 * ft1 + ft2")

        lines.append(f"    {store_instr:<8} ft2, 0({vd_ptr})           # 写回 {vd_ptr}[0]")
    else:
        load_instr = _get_float_instr('load', sew)

        lines.append(f"    {load_instr:<8} ft0, 0({vs2_ptr})          # ft0 = {vs2_ptr}[0]")
        lines.append(f"    {load_instr:<8} ft1, 0({vs1_ptr})          # ft1 = {vs1_ptr}[0]")

        if op_type == 'madd':
            lines.append(f"    {load_instr:<8} ft2, 0({vd_ptr})           # ft2 = {vd_ptr}[0]")
            op_instr = _get_float_instr('madd', sew)
            lines.append(f"    {op_instr:<8} ft2, ft0, ft1, ft2           # ft2 = ft0 * ft1 + ft2")
            lines.append(f"    {store_instr:<8} ft2, 0({vd_ptr})           # 写回 {vd_ptr}[0]")
        elif op_type == 'add':
            op_instr = _get_float_instr('add', sew)
            lines.append(f"    {op_instr:<8} ft2, ft1, ft0                # ft2 = ft1 + ft0")
            lines.append(f"    {store_instr:<8} ft2, 0({vd_ptr})           # 写回 {vd_ptr}[0]")
        elif op_type == 'sub':
            op_instr = _get_float_instr('sub', sew)
            lines.append(f"    {op_instr:<8} ft2, ft0, ft1                # ft2 = ft0 - ft1 = vs2[i] - vs1[i]")
            lines.append(f"    {store_instr:<8} ft2, 0({vd_ptr})           # 写回 {vd_ptr}[0]")
        elif op_type == 'mul':
            op_instr = _get_float_instr('mul', sew)
            lines.append(f"    {op_instr:<8} ft2, ft1, ft0                # ft2 = ft1 * ft0")
            lines.append(f"    {store_instr:<8} ft2, 0({vd_ptr})           # 写回 {vd_ptr}[0]")

    if is_masked:
        lines.append(f"{skip_label}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")

    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_reg}, {tail_reg}, -1")
    lines.append(f"    j       {tail_label}")
    lines.append(f"{end_label}:")


def _parse_int_operand(value: str) -> int:
    """Parse decimal/hex signed immediates."""
    return int(str(value), 0)
