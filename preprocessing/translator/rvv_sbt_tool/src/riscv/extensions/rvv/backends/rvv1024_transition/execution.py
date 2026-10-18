"""execution：后端内部职责。"""

from __future__ import annotations

from typing import Callable, List, Sequence
from riscv.extensions.rvv.analysis.model import LMUL_TOKENS
from riscv.extensions.rvv.translation.lowering import AssemblyFragments
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator, record_vreg_group
from riscv.extensions.rvv.backends.rvv1024_transition import state_view
from riscv.extensions.rvv.backends.rvv1024_transition.temp_regs import VRegTempAllocator
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _error,
    _source_shape,
    _lmul_token_and_group_width,
)


_ACTIVE_SAME_WIDTH_ARITHMETIC = frozenset({
    "vfmacc.vv", "vfadd.vv", "vmacc.vv",
    "vadd.vi", "vadd.vx", "vand.vv", "vand.vx", "vand.vi", "vor.vv",
    "vsll.vv", "vsll.vi", "vsrl.vv", "vsrl.vi", "vsra.vi",
})


def _tight_arithmetic_lmul_token(
    native_opcode: str,
    state: StateTracker,
    original_token: str,
    mask_source: str | None,
) -> str:
    if mask_source is not None:
        if native_opcode == "vadd.vi" and state.sew == 16 and state.lmul == 1:
            return LMUL_TOKENS[state.lmul * state_view.SOURCE_VLENB / state_view.TARGET_VLENB]
        return original_token
    same_width = (
        native_opcode in _ACTIVE_SAME_WIDTH_ARITHMETIC
        and state.sew == 32 and state.lmul in (2, 8)
    )
    widening = native_opcode == "vfwmacc.vv" and state.sew == 16 and state.lmul == 1
    macvx = native_opcode == "vmacc.vx" and state.sew == 16 and state.lmul == 1
    maskshift = native_opcode in {"vand.vi", "vsrl.vx"} and state.sew == 8 and state.lmul == 0.5
    if not (same_width or widening or macvx or maskshift):
        return original_token
    target_lmul = state.lmul * state_view.SOURCE_VLENB / state_view.TARGET_VLENB
    return LMUL_TOKENS[target_lmul]


def _emit_pack_group(
    lines: List[str],

    target_vreg: str,
    address_reg: str,
    source_vreg: str,
    lmul: float,
    avl_reg: str,
) -> None:
    """把一个源 RVV256 逻辑组精确 Pack 到目标临时组。"""
    state_view.emit_pack_source_group(
        lines,
        target_vreg,
        address_reg,
        source_vreg,
        lmul,
        avl_reg,
    )


def _emit_unpack_group(
    lines: List[str],

    target_vreg: str,
    address_reg: str,
    source_vreg: str,
    lmul: float,
    avl_reg: str,
) -> None:
    """把目标临时组的源有效字节精确 Unpack 回紧凑 RVV256 状态。"""
    state_view.emit_unpack_source_group(
        lines,
        target_vreg,
        address_reg,
        source_vreg,
        lmul,
        avl_reg,
    )


def _emit_load_source_vl(
    lines: List[str],  vl_reg: str, address_reg: str
) -> None:
    """
    从固定 CSR 页读取源 RVV256 的运行时 VL。

    CSR 偏移是 ``simulated_cpu_state`` ABI 的稳定部分；只有向量 payload 的解释
    是 32B 紧凑布局。这里显式计算 ``t6 + 0x1020``，并附上 state-base 标记，
    使 ProgramEmitter 在客户指令使用 t6/x31 时仍不会把该访问改写成语义输入。
    """
    state_view.emit_load_csr(lines, vl_reg, address_reg, "vl")


def _emit_execution_vsetvl(
    lines: List[str],
    vl_reg: str,
    sew: int,
    lmul_token: str,
) -> None:
    """
    恢复目标机执行所需 vtype。

    目标 VLEN=1024，故相同 SEW/LMUL 的目标 VLMAX 至少是源机的四倍。把源 VL
    作为 AVL 传给 ``vsetvli`` 后，实际 VL 与客户语义相同。强制 ``tu,mu`` 是
    过渡区的保守策略：未执行的 lane 保留 Pack 进来的旧目标值，随后准确写回；
    即使源 vtype 标为 ta/ma，这也是 RVV 允许的具体结果，且不会把无定义 lane
    随机扩散到紧凑状态。
    """
    lines.append(
        f"    vsetvli zero, {vl_reg}, e{sew}, {lmul_token}, tu, mu"
        "  # 以源 VL 在 RVV1024 临时组执行"
    )


def _emit_single_element_vset(lines: List[str], sew: int) -> None:
    """为只读/只写 element 0 的 move 设置最小、独立的 m1 配置。"""
    lines.append(f"    vsetivli zero, 1, e{sew}, m1, tu, mu")


def _allocate_vector_groups(widths: Sequence[int]) -> list[str]:
    """
    分配 RVV1024 临时组。

    这里故意不把客户 ``insn`` 传给分配器：客户 vN 仅是 state 中的源物理寄存器
    编号，不是当前硬件寄存器占用。若因 ``v8`` 出现在客户操作数中而排除硬件 v8，
    ``m8`` 三操作数组将无法获得所需的 v8/v16/v24 三个连续组。
    """
    vtemps = VRegTempAllocator()
    return [vtemps.alloc_vreg_group(width) for width in widths]


def _emit_vector_write(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
    vd: str,
    vector_sources: Sequence[str],
    scalar_operand: str | None = None,
    immediate: int | None = None,
    mask_source: str | None = None,
    reads_old_vd: bool = True,
) -> List[str]:
    """
    发射所有“写一个普通向量组”的一期指令。

    默认路径先 Pack 旧 vd 和全部向量输入，保留完整组 Unpack 所需的 tail。
    无掩码同宽热点只读取活动输入；旧 vd 是否作为输入由指令规格决定。全部
    输入仍在执行和活动元素写回前读取，state 中的未执行字节保持原值。
    """
    try:
        sew, lmul, lmul_token, group_width = _source_shape(state)
        lmul_token = _tight_arithmetic_lmul_token(native_opcode, state, lmul_token, mask_source)
        requested_widths = [group_width] * (1 + len(vector_sources))
        allocated = _allocate_vector_groups(requested_widths)
        temp_vd, *remaining_temps = allocated
        temp_sources = remaining_temps[:len(vector_sources)]
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = (
            vl_reg if native_opcode == "vadd.vi" and mask_source is not None
            and sew == 16 and lmul == 1 else temps.alloc_gpr()
        )
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    active_commit = (
        mask_source is None
        and (
            (native_opcode in _ACTIVE_SAME_WIDTH_ARITHMETIC and sew == 32 and lmul == 2)
            or (native_opcode in {"vand.vi", "vsrl.vx"} and sew == 8 and lmul == 0.5)
        )
    )
    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 -> RVV1024 过渡)",
        "# 同宽热点读取全部活动输入后执行，并立即提交活动元素。" if active_commit
        else "# 先 Pack 旧 vd 与全部向量源；写回前不再读取紧凑状态。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    if native_opcode == "vadd.vi" and mask_source is not None and sew == 16 and lmul == 1:
        # Load old vd for inactive lanes; alias inputs reuse that same snapshot.
        _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
        state_view.emit_source_vreg_address(lines, address_reg, mask_source)
        record_vreg_group("v0", 1)
        lines.append(f"    vlm.v v0, ({address_reg})  # Load only ceil(VL / 8) mask bytes")
        state_view.emit_source_vreg_address(lines, address_reg, vd)
        lines.append(f"    vle{sew}.v {temp_vd}, ({address_reg})")
        inputs = []
        for source_vreg, temp_source in zip(vector_sources, temp_sources):
            if source_vreg == vd:
                inputs.append(temp_vd)
                continue
            inputs.append(temp_source)
            state_view.emit_source_vreg_address(lines, address_reg, source_vreg)
            lines.append(f"    vle{sew}.v {temp_source}, ({address_reg})")
        lines.append(f"    {native_opcode} {temp_vd}, {', '.join(inputs)}, {immediate}, v0.t")
        state_view.emit_source_vreg_address(lines, address_reg, vd)
        lines.append(f"    vse{sew}.v {temp_vd}, ({address_reg})")
        return lines


    if active_commit:
        _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
        if reads_old_vd:
            state_view.emit_source_vreg_address(lines, address_reg, vd)
            lines.append(f"    vle{sew}.v {temp_vd}, ({address_reg})")
        for source_vreg, temp_source in zip(vector_sources, temp_sources):
            state_view.emit_source_vreg_address(lines, address_reg, source_vreg)
            lines.append(f"    vle{sew}.v {temp_source}, ({address_reg})")
    else:
        # Pack 顺序不影响语义，因为此阶段只读 state；显式先放 vd 使 tu 的来源清晰。
        _emit_pack_group(
            lines,  temp_vd, address_reg, vd, lmul,
            transfer_avl_reg,
        )
        for source_vreg, temp_source in zip(vector_sources, temp_sources):
            _emit_pack_group(
                lines,  temp_source, address_reg, source_vreg, lmul,
                transfer_avl_reg,
            )

    if not active_commit:
        _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    if mask_source is not None:
        # The packed sources remain live; load the execution mask directly so
        # three m8 operands fit the v8..v31 temporary pool.
        state_view.emit_source_vreg_address(lines, address_reg, mask_source)
        record_vreg_group("v0", 1)
        lines.append(f"    vlm.v v0, ({address_reg})  # 载入源 v0.t 执行掩码")

    native_operands = [temp_vd, *temp_sources]
    if scalar_operand is not None:
        native_operands.append(scalar_operand)
    elif immediate is not None:
        native_operands.append(str(immediate))
    mask_suffix = ", v0.t" if mask_source is not None else ""
    lines.append(
        f"    {native_opcode:<10} {', '.join(native_operands)}{mask_suffix}"
    )

    if active_commit:
        state_view.emit_source_vreg_address(lines, address_reg, vd)
        lines.append(f"    vse{sew}.v {temp_vd}, ({address_reg})")
    else:
        _emit_unpack_group(
            lines, temp_vd, address_reg, vd, lmul,
            transfer_avl_reg,
        )
    lines.append("    # 完成后 vd 已按 RVV256 紧凑物理布局立即写回")
    return lines


def _emit_packed_vector_write(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
    vd: str,
    result_lmul: float,
    vector_sources: Sequence[tuple[str, float]],
    execution_sew: int,
    execution_lmul_token: str,
    operand_order: Sequence[str],
    scalar_operand: str | None = None,
    mask_source: str | None = None,
    reads_old_vd: bool = True,
    native_lines_builder: Callable[[dict[str, str]], Sequence[str]] | None = None,
) -> List[str]:
    """发射可显式指定 RVV 原生操作数顺序的 Pack/执行/Unpack 闭环。

    一期的 ``_emit_vector_write`` 覆盖了 ``vd, vs2, vs1`` 与
    ``vd, vs2, rs1`` 这类常规顺序。但 FMA 的 ``.vf`` 编码是
    ``vd, rs1, vs2``：若简单复用“所有 vector source 后接 scalar”的
    拼接规则，会生成可汇编却改变 operand role 的错误代码。

    此 helper 还被 widening conversion 使用。它允许目的组和输入组拥有
    不同 LMUL，默认先 Pack 旧目的组和所有输入组，再执行和 Unpack。
    同宽无掩码热点只读取活动输入，由 ``reads_old_vd`` 指定是否读取旧目的。
    所有输入仍在状态提交前读取，保持 ``vd == vs2`` 和源组重叠的安全边界。

    ``operand_order`` 的 token 只能是：

    * ``vd``：目标临时组；
    * ``vs0``、``vs1``……：按 ``vector_sources`` 顺序分配的临时组；
    * ``scalar``：显式传入的 GPR/FPR 标量操作数。

    若提供 ``mask_source``，它会在所有数据源之后直接载入目标硬件 ``v0``，
    并把 ``v0.t`` 接到原生指令末尾。这样关闭 lane 的
    old ``vd`` 在固定 ``tu,mu`` 下仍由 Pack 进来的旧值提供。

    对不能由单条目标指令直接覆盖、但仍只依赖同一组已 Pack 输入的简单
    lowering，``native_lines_builder`` 可以基于这些 token 发射一小段原生
    RVV 指令。例如 ``vandn.vv`` 在不假定 Zvkb 扩展时可降为
    ``vxor.vi -1`` 加 ``vand.vv``。builder 在目标 ``vsetvli`` 之后、
    Unpack 之前运行，不能再访问紧凑 state。
    """
    try:
        _source_shape(state)  # 同时验证源 SEW/LMUL 属于一期可解释范围。
        execution_lmul_token = _tight_arithmetic_lmul_token(
            native_opcode, state, execution_lmul_token, mask_source,
        )
        _, result_group_width = _lmul_token_and_group_width(result_lmul)
        source_group_widths = [
            _lmul_token_and_group_width(source_lmul)[1]
            for _, source_lmul in vector_sources
        ]
        requested_widths = [result_group_width, *source_group_widths]
        allocated = _allocate_vector_groups(requested_widths)
        temp_vd = allocated[0]
        temp_sources = allocated[1:1 + len(vector_sources)]
        if mask_source is not None and native_lines_builder is not None:
            return _error(insn, "带掩码的 packed lowering 不支持自定义多指令 builder")
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = (vl_reg if native_opcode == "vmacc.vx"
                            and mask_source is None and state.sew == 16 and state.lmul == 1
                            else temps.alloc_gpr())
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    values: dict[str, str] = {"vd": temp_vd}
    values.update({f"vs{index}": temp for index, temp in enumerate(temp_sources)})
    if scalar_operand is not None:
        values["scalar"] = scalar_operand

    try:
        native_operands = [values[token] for token in operand_order]
    except KeyError as exc:
        return _error(insn, f"内部 operand_order 缺少 {exc.args[0]!r}")

    active_commit = (
        mask_source is None
        and (
            (native_opcode in _ACTIVE_SAME_WIDTH_ARITHMETIC and state.sew == 32 and state.lmul == 2)
            or (native_opcode == "vmacc.vx" and state.sew == 16 and state.lmul == 1)
        )
        and native_lines_builder is None
        and execution_sew == state.sew
        and result_lmul == state.lmul
        and all(source_lmul == state.lmul for _, source_lmul in vector_sources)
    )
    # VL is dead after the execution vset; retain vd's pointer there until commit.
    keep_vd_address = (
        active_commit and native_opcode == "vmacc.vx"
        and state.sew == 16 and state.lmul == 1
    )
    destination_address = vl_reg if keep_vd_address else address_reg
    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 -> RVV1024 过渡)",
        "# 同宽热点读取全部活动输入后执行，并立即提交活动元素。" if active_commit
        else "# 先 Pack 旧 vd 与全部向量输入；写回前不再读取紧凑状态。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    if active_commit:
        _emit_execution_vsetvl(lines, vl_reg, execution_sew, execution_lmul_token)
        if reads_old_vd:
            state_view.emit_source_vreg_address(lines, destination_address, vd)
            lines.append(f"    vle{execution_sew}.v {temp_vd}, ({destination_address})")
        for (source_vreg, _source_lmul), temp_source in zip(vector_sources, temp_sources):
            state_view.emit_source_vreg_address(lines, address_reg, source_vreg)
            lines.append(f"    vle{execution_sew}.v {temp_source}, ({address_reg})")
    else:
        _emit_pack_group(
            lines,

            temp_vd,
            address_reg,
            vd,
            result_lmul,
            transfer_avl_reg,
        )
        for (source_vreg, source_lmul), temp_source in zip(vector_sources, temp_sources):
            _emit_pack_group(
                lines,

                temp_source,
                address_reg,
                source_vreg,
                source_lmul,
                transfer_avl_reg,
            )

    if not active_commit:
        _emit_execution_vsetvl(
            lines,
            vl_reg,
            execution_sew,
            execution_lmul_token,
        )
    if mask_source is not None:
        state_view.emit_source_vreg_address(lines, address_reg, mask_source)
        record_vreg_group("v0", 1)
        lines.append(f"    vlm.v v0, ({address_reg})  # 载入源 v0.t 执行掩码")
    mask_suffix = ", v0.t" if mask_source is not None else ""
    if native_lines_builder is None:
        lines.append(
            f"    {native_opcode:<14} {', '.join(native_operands)}{mask_suffix}"
        )
    else:
        lines.extend(str(line) for line in native_lines_builder(values))
    if active_commit:
        if not keep_vd_address:
            state_view.emit_source_vreg_address(lines, destination_address, vd)
        lines.append(f"    vse{execution_sew}.v {temp_vd}, ({destination_address})")
    else:
        _emit_unpack_group(
            lines,
            temp_vd,
            address_reg,
            vd,
            result_lmul,
            transfer_avl_reg,
        )
    lines.append("    # 完成后目的组已按 RVV256 紧凑物理布局立即写回")
    return lines


def _emit_scalar_insert(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
    vd: str,
    scalar: str,
    new_label,
) -> List[str]:
    """
    发射 ``vmv.s.x`` / ``vfmv.s.f``。

    源 VL=0 时不更新目的寄存器；否则以 vl=1 执行，保留其余源字节。
    """
    try:
        sew, _, _, _ = _source_shape(state)
        (temp_vd,) = _allocate_vector_groups([1])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (单元素 RVV256 -> RVV1024 过渡)",
        "# Source VL=0 preserves the complete destination register.",
    ]
    done = new_label("scalar_insert_done")
    _emit_load_source_vl(lines, transfer_avl_reg, address_reg)
    lines.append(f"    beqz    {transfer_avl_reg}, {done}")
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    _emit_single_element_vset(lines, sew)
    lines.append(f"    {native_opcode:<10} {temp_vd}, {scalar}")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    lines.append(f"{done}:")
    return lines


def _emit_scalar_extract(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
    rd: str,
    vs2: str,
) -> List[str] | AssemblyFragments:
    """发射 ``vmv.x.s`` / ``vfmv.f.s``，仅读取源物理寄存器的 element 0。"""
    try:
        sew, _, _, _ = _source_shape(state)
        (temp_vs2,) = _allocate_vector_groups([1])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (单元素提取 RVV256 -> RVV1024)",
        "# 只 Pack vs2 的首个源物理寄存器；本指令不写向量 state。",
    ]
    _emit_pack_group(
        lines,  temp_vs2, address_reg, vs2, 1.0,
        transfer_avl_reg,
    )
    _emit_single_element_vset(lines, sew)
    # lowerer 在 handler 后还需以 t6 作为 source-state 基址写回 vcsr 和
    # vstart。若客户把标量结果写入 t6/x31，必须把该 native 写入延后到
    # postamble；否则结果会先覆盖状态基址，后续 sd 落到任意地址。
    result_line = f"    {native_opcode:<10} {rd}, {temp_vs2}"
    if str(rd).strip().lower() in {"t6", "x31"}:
        return AssemblyFragments(tuple(lines), (result_line,))
    lines.append(result_line)
    return lines
