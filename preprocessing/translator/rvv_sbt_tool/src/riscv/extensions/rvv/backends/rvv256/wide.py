"""
RVV-1024 到 RVV-256 的宽 LMUL 热点翻译路径。

该模块只处理显式白名单中的逐元素指令，包括显式 ``v0.t`` masked form
（掩码形式）。每条源指令仍然从
``simulated_cpu_state`` 读取操作数并在结束前写回结果，因此不会引入跨源
指令的 dirty（脏）状态。源寄存器名描述的是 128B/vreg 的模拟内存布局；
本模块使用的 v8-v31 则只是当前翻译块内的目标硬件临时寄存器组。
"""

from __future__ import annotations

from fractions import Fraction
import math
import re
from typing import Callable, Iterable, NoReturn

from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS, SimulatedStateLayout
from riscv.extensions.rvv.runtime.geometry import RVV1024_TO_RVV256_GEOMETRY
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.translation.lowering import AssemblyFragments
from riscv.extensions.rvv.translation.contracts import InstructionSpec, InstructionValidationError
from riscv.extensions.rvv.translation.temps import (
    TempRegisterAllocator, TempRegisterAllocationError, record_vreg_group,
)
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.backends.rvv256.support import _emit_state_ptr, _load_vl_from_csr
from riscv.extensions.rvv.backends.rvv256.lowering_metadata import (
    RVV256SameWidthSpec,
    lowering_metadata,
)
from riscv.frontend.model import RVInstruction

from riscv.extensions.rvv.backends.rvv256.planning import (
    _VREG_RE,
    WideChunkPlan,
    WideVRegGroupAllocator,
    _as_fraction,
    _validate_source_group,
    plan_wide_chunk,
    plan_wide_operands,
)
















def _split_mask_operand(insn: RVInstruction) -> tuple[bool, list[object]] | None:
    """
    分离末尾的显式 mask operand（掩码操作数）。

    当前 ABI 只把模拟 ``v0`` 作为执行 mask；其他 ``vN.t`` 不能静默按
    ``v0.t`` 执行。返回 ``None`` 让结构化 lowerer 继续选择规格表绑定的
    builder；若该 form 没有合法实现，最终由统一 fallback 策略明确拒绝。
    """
    operands = list(insn.operands)
    if not operands or not str(operands[-1]).strip().endswith(".t"):
        return False, operands
    if str(operands[-1]).strip() != "v0.t":
        return None
    return True, operands[:-1]


def _reject_shape(insn: RVInstruction, message: str) -> NoReturn:
    """拒绝非法形态；单纯不适用的宽路径候选仍直接返回 None。"""
    raise InstructionValidationError(insn, message)


def _emit_vtype(
    lines: list[str],
    avl_reg: str,
    plan: WideChunkPlan,
    *,
    mask_policy: str = "ma",
) -> None:
    """
    设置当前宽块的目标 vtype。

    非累加 masked 指令可以采用 ``ma`` 并在最终状态写回时带 ``v0.t``：
    被屏蔽元素根本不会碰 simulated_cpu_state，因而不需要先读旧 ``vd``。
    只有读取旧目标作为输入的累加类指令才需要 ``mu``，随后可将完整目标块
    写回。该区分仅在一条源指令内部发生，不会放宽迁移状态同步边界。
    """
    if mask_policy not in {"ma", "mu"}:
        raise ValueError(f"非法目标 mask policy: {mask_policy}")
    lines.append(
        f"    vsetvli zero, {avl_reg}, e{plan.target_vtype_sew}, "
        f"{plan.target_lmul_text}, ta, {mask_policy}"
    )


def _emit_wide_loop(
    *,
    lines: list[str],
    insn: RVInstruction,
    new_label,
    plan: WideChunkPlan,
    temps: TempRegisterAllocator,
    state_ptrs: list[str],
    mask_ptr: str | None,
    mem_ptr: str | None,
    stride_reg: str | None,
    emit_body: Callable[[], None],
    state_ptr_steps: list[tuple[str, int]] | None = None,
    mask_policy: str = "ma",
) -> None:
    """
    生成 one-shot 或“固定完整块 + 单个向量尾部”控制流。

    完整块的目标 vtype 位于循环回边之外；目标 VLEN=256 是该计算成立的
    部署合同。状态指针按紧凑 data_sew 字节前进，strided 内存指针按
    ``elements_per_chunk * stride`` 前进。
    """
    vl_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    _load_vl_from_csr(lines, vl_reg, addr_reg)

    if plan.one_shot:
        _emit_vtype(lines, vl_reg, plan, mask_policy=mask_policy)
        emit_body()
        return

    full_count = addr_reg
    tail_count = temps.alloc_gpr()
    # full/tail 已经从 vl 计算完成，原 vl_reg 的 live range 到此结束；复用它
    # 装固定 AVL 可少写一个 GPR，并直接减少 wrapper 的 spill/reload。
    avl_scratch = vl_reg
    shift = int(math.log2(plan.elements_per_chunk))
    lines.append(f"    srli    {full_count}, {vl_reg}, {shift}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {plan.elements_per_chunk - 1}")

    step_reg = None
    if mem_ptr is not None and stride_reg is not None:
        step_reg = temps.alloc_gpr()
        lines.append(f"    li      {step_reg}, {plan.elements_per_chunk}")
        lines.append(f"    mul     {step_reg}, {step_reg}, {stride_reg}")

    loop_label = new_label(f"wide_{insn.opcode.replace('.', '_')}_full")
    after_full = new_label(f"wide_{insn.opcode.replace('.', '_')}_after_full")
    end_label = new_label(f"wide_{insn.opcode.replace('.', '_')}_end")

    lines.append(f"    beqz    {full_count}, {after_full}")
    lines.append(f"    li      {avl_scratch}, {plan.elements_per_chunk}")
    _emit_vtype(lines, avl_scratch, plan, mask_policy=mask_policy)
    lines.append(f"{loop_label}:")
    emit_body()
    pointer_steps = state_ptr_steps or [
        (pointer, plan.bytes_per_chunk) for pointer in state_ptrs
    ]
    for pointer, step in pointer_steps:
        lines.append(f"    addi    {pointer}, {pointer}, {step}")
    if mask_ptr is not None:
        # 目标完整宽块在所有已支持 SEW 下均为 8 的整数倍，因此每轮恰好
        # 消耗 elements_per_chunk / 8 个 bit-packed mask 字节。
        lines.append(
            f"    addi    {mask_ptr}, {mask_ptr}, {plan.elements_per_chunk // 8}"
        )
    if mem_ptr is not None:
        if step_reg is None:
            lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {plan.bytes_per_chunk}")
        else:
            lines.append(f"    add     {mem_ptr}, {mem_ptr}, {step_reg}")
    lines.append(f"    addi    {full_count}, {full_count}, -1")
    lines.append(f"    bnez    {full_count}, {loop_label}")
    lines.append(f"{after_full}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    _emit_vtype(lines, tail_count, plan, mask_policy=mask_policy)
    emit_body()
    lines.append(f"{end_label}:")


_ARITHMETIC_GROUPS = {
    "vfmacc.vf": 2,
    "vfmacc.vv": 3,
    "vfmul.vf": 1,
    "vfnmsac.vf": 2,
    "vadd.vv": 2,
}


def _emit_wide_same_width_arithmetic(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    instruction_spec: InstructionSpec,
    spec: RVV256SameWidthSpec,
) -> list[str] | None:
    """
    发射首期 33 条同宽逐元素指令的 RVV256 宽路径。

    这条路径只接受无掩码形式。显式 ``v0.t`` 会返回 ``None``，由外层
    new_label 继续选择已有 masked handler 或按现有合同 fail-fast；这样
    首期不会扩大 masked 白名单，也不会把未实现掩码误当作无掩码执行。

    源 ``vd``、``vs1``、``vs2`` 仍表示 128B simulated_cpu_state 槽位，
    目标 ``v8-v31`` 只是当前翻译块的临时物理寄存器组。对于不读取旧 ``vd``
    的同宽操作，结果组可以复用第一个输入组；所有输入先加载完成后才执行
    运算，因此 ``vd`` 与任意输入别名时仍保持源值语义。
    """

    split = _split_mask_operand(insn)
    if split is None:
        return None
    is_masked, operands = split
    # 只有在 registry 中显式携带 same_width 描述的非累加族才能进入本
    # helper；mask 支持不会被误解释为“无掩码时读取旧 vd”。
    if is_masked:
        return None

    if state.sew not in (8, 16, 32, 64):
        return None
    if spec.allowed_sews and state.sew not in spec.allowed_sews:
        return None

    if not spec.vector_operand_positions:
        return _reject_shape(insn,
            f"同宽宽路径缺少向量操作数位置: {insn.op_str}"
        )
    positions = (0, *spec.vector_operand_positions)
    if spec.scalar_operand_position is not None:
        positions = (*positions, spec.scalar_operand_position)
    expected_operands = max(positions) + 1
    if len(operands) != expected_operands:
        return _reject_shape(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = str(operands[0])
    vector_operands = tuple(
        str(operands[position]) for position in spec.vector_operand_positions
    )

    unique_vector_operands = tuple(dict.fromkeys(vector_operands))
    source_regs = tuple(dict.fromkeys((vd, *vector_operands)))
    try:
        plan = plan_wide_chunk(
            source_lmul=state.lmul,
            source_sew=state.sew,
            data_sew=state.sew,
            source_regs=source_regs,
            # 结果不读取旧 vd，所以只需为不同的输入值分配目标组；
            # 输出直接复用第一个输入组，避免无意义的旧 vd 加载。
            target_group_count=len(unique_vector_operands),
        )
    except ValueError as exc:
        return _reject_shape(insn, str(exc))
    if plan is None:
        return None

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    lines = [
        f"# RVV256-WIDE: {instruction_spec.opcode}, source LMUL={state.lmul:g}, "
        f"target={plan.target_lmul_text}, chunk={plan.elements_per_chunk} elements",
    ]

    pointers: dict[str, str] = {}
    for reg in source_regs:
        pointer = temps.alloc_gpr()
        _emit_state_ptr(lines, pointer, allocator.get_offset(reg))
        pointers[reg] = pointer

    group_by_reg = dict(zip(unique_vector_operands, plan.group_bases))
    result_group = group_by_reg[vector_operands[0]]

    def emit_body() -> None:
        # 先把所有不同的输入槽加载到目标组，再发射算术操作；这个顺序同时
        # 覆盖 vd==vs1、vd==vs2 以及 vs1==vs2，避免写回提前破坏输入。
        for reg in unique_vector_operands:
            lines.append(f"    vle{state.sew}.v {group_by_reg[reg]}, ({pointers[reg]})")

        if spec.lowering == "not_base_v":
            # vnot.v 在 LLVM 中可能被识别为 Zvkb 伪指令。基础 V 已经提供
            # vxor.vi，因此显式用 -1 合成按位取反，避免把目标扩展要求
            # 从源 opcode 意外传播到 RVV256 目标机。
            operation = f"vxor.vi {result_group}, {result_group}, -1"
        elif spec.lowering == "and_not_base_v":
            lhs_group = group_by_reg[vector_operands[0]]
            rhs_group = group_by_reg[vector_operands[1]]
            if lhs_group == rhs_group:
                operation = f"vmv.v.i {result_group}, 0"
            else:
                lines.append(f"    vxor.vi {rhs_group}, {rhs_group}, -1")
                operation = f"vand.vv {result_group}, {lhs_group}, {rhs_group}"
        elif spec.operand_form == "unary":
            operation = (
                f"{instruction_spec.target_mnemonic} {result_group}, {result_group}"
            )
        elif spec.operand_form == "vv":
            lhs_group = group_by_reg[vector_operands[0]]
            rhs_group = group_by_reg[vector_operands[1]]
            operation = (
                f"{instruction_spec.target_mnemonic} {result_group}, "
                f"{lhs_group}, {rhs_group}"
            )
        else:
            # vx/vi/vf 的标量寄存器或立即数位置由描述表提供，不属于模拟
            # 向量状态槽，也不能交给 source group planner 当作 vreg 校验。
            if spec.scalar_operand_position is None:
                return _reject_shape(insn,
                    f"同宽宽路径缺少标量操作数位置: {insn.op_str}"
                )
            scalar_or_immediate = str(operands[spec.scalar_operand_position])
            operation = (
                f"{instruction_spec.target_mnemonic} {result_group}, {result_group}, "
                f"{scalar_or_immediate}"
            )
        lines.append(f"    {operation}")
        lines.append(f"    vse{state.sew}.v {result_group}, ({pointers[vd]})")

    _emit_wide_loop(
        lines=lines,
        insn=insn,
        new_label=new_label,
        plan=plan,
        temps=temps,
        state_ptrs=list(dict.fromkeys(pointers.values())),
        mask_ptr=None,
        mem_ptr=None,
        stride_reg=None,
        emit_body=emit_body,
        # 无掩码形式也保持 ma，与现有宽路径的目标 vtype 合同一致；
        # masked 形式本轮不会进入此 helper。
        mask_policy="ma",
    )
    return lines


def emit_wide_arithmetic(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    instruction_spec: InstructionSpec,
) -> list[str] | None:
    """尝试生成同宽、累加和既有首批算术宽路径。"""
    same_width_spec = (
        lowering_metadata(instruction_spec).same_width
        if instruction_spec is not None
        else None
    )
    if same_width_spec is not None:
        return _emit_wide_same_width_arithmetic(
            insn,
            state,
            allocator,
            new_label,
            instruction_spec,
            same_width_spec,
        )

    # 以下分支保留既有 vfmacc/vfnmsac/vfmul/vadd 实现及其 masked 语义，
    # 首期同宽扩展不改变这些已经验证过的代码形状。
    split = _split_mask_operand(insn)
    if insn.opcode not in _ARITHMETIC_GROUPS or split is None:
        return None
    is_masked, operands = split
    if len(operands) < 3:
        return _reject_shape(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")
    if insn.opcode.startswith("vf") and state.sew not in (32, 64):
        return None
    if state.sew not in (8, 16, 32, 64):
        return None

    vd = str(operands[0])
    if insn.opcode.endswith(".vf"):
        # GNU RVV 语法中 vfmul.vf 为 ``vd, vs2, rs1``；累加类 .vf
        # 为 ``vd, rs1, vs2``。不能用统一位置解释，否则会把 fa0 当 vreg。
        if insn.opcode == "vfmul.vf":
            vs2 = str(operands[1])
            scalar = str(operands[2])
        else:
            scalar = str(operands[1])
            vs2 = str(operands[2])
        source_regs = (vd, vs2)
    else:
        vs1 = str(operands[1])
        vs2 = str(operands[2])
        source_regs = (vd, vs1, vs2)

    try:
        plan = plan_wide_chunk(
            source_lmul=state.lmul,
            source_sew=state.sew,
            data_sew=state.sew,
            source_regs=source_regs,
            # 非累加 masked form 采用 ma + masked state store；未命中元素不
            # 写状态槽，因此不需要为了 mu 预装旧 vd，也无需额外目标组。
            target_group_count=_ARITHMETIC_GROUPS[insn.opcode],
            max_target_lmul=(
                4 if insn.opcode == "vfmacc.vv" and not is_masked
                and state.sew == 32 and state.lmul == 8 else 8
            ),
        )
    except ValueError as exc:
        return _reject_shape(insn, str(exc))
    if plan is None:
        return None

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    lines = [
        f"# RVV256-WIDE{'-MASKED' if is_masked else ''}: {insn.opcode}, source LMUL={state.lmul:g}, "
        f"target={plan.target_lmul_text}, chunk={plan.elements_per_chunk} elements"
    ]
    if is_masked and insn.opcode in {"vfmul.vf", "vadd.vv"}:
        lines.append(
            "# RVV256-WIDE-MASKED-COMMIT: ma + masked state store, no old-vd preload"
        )
    pointers: dict[str, str] = {}
    pointer_offsets: dict[str, int] = {}
    relative_state_addresses = (
        insn.opcode == "vfmacc.vv" and not is_masked
        and state.sew == 32 and state.lmul == 8
    )
    for name in dict.fromkeys(source_regs):
        pointer = temps.alloc_gpr()
        offset = allocator.get_offset(name)
        relative_base = next((
            (pointers[previous], offset - previous_offset)
            for previous, previous_offset in pointer_offsets.items()
            if -2048 <= offset - previous_offset <= 2047
        ), None) if relative_state_addresses and offset > 2047 else None
        if relative_base is None:
            _emit_state_ptr(lines, pointer, offset)
        else:
            base_pointer, delta = relative_base
            lines.append(f"    addi    {pointer}, {base_pointer}, {delta}")
        pointers[name] = pointer
        pointer_offsets[name] = offset

    mask_ptr = None
    if is_masked:
        mask_ptr = temps.alloc_gpr()
        _emit_state_ptr(lines, mask_ptr, allocator.get_offset("v0"))

    def emit_mask_load() -> None:
        if mask_ptr is not None:
            record_vreg_group("v0", 1)
            lines.append(f"    vlm.v   v0, ({mask_ptr})")

    groups = plan.group_bases
    if insn.opcode == "vfmacc.vf":
        vd_group, vs2_group = groups
        def body() -> None:
            emit_mask_load()
            lines.append(f"    vle{state.sew}.v {vs2_group}, ({pointers[vs2]})")
            lines.append(f"    vle{state.sew}.v {vd_group}, ({pointers[vd]})")
            lines.append(f"    vfmacc.vf {vd_group}, {scalar}, {vs2_group}{', v0.t' if is_masked else ''}")
            lines.append(f"    vse{state.sew}.v {vd_group}, ({pointers[vd]})")
    elif insn.opcode == "vfnmsac.vf":
        vd_group, vs2_group = groups
        def body() -> None:
            emit_mask_load()
            lines.append(f"    vle{state.sew}.v {vs2_group}, ({pointers[vs2]})")
            lines.append(f"    vle{state.sew}.v {vd_group}, ({pointers[vd]})")
            lines.append(f"    vfnmsac.vf {vd_group}, {scalar}, {vs2_group}{', v0.t' if is_masked else ''}")
            lines.append(f"    vse{state.sew}.v {vd_group}, ({pointers[vd]})")
    elif insn.opcode == "vfmul.vf":
        # vfmul 不读取旧 vd。无论是否 masked，都复用 vs2 的物理组作为
        # 结果组；masked-off 元素通过最终 masked store 保留状态块旧值。
        (vd_group,) = groups
        vs2_group = vd_group
        def body() -> None:
            emit_mask_load()
            lines.append(f"    vle{state.sew}.v {vs2_group}, ({pointers[vs2]})")
            lines.append(f"    vfmul.vf {vd_group}, {vs2_group}, {scalar}{', v0.t' if is_masked else ''}")
            lines.append(
                f"    vse{state.sew}.v {vd_group}, ({pointers[vd]})"
                f"{', v0.t' if is_masked else ''}"
            )
    elif insn.opcode == "vfmacc.vv":
        vd_group, vs1_group, vs2_group = groups
        def body() -> None:
            emit_mask_load()
            lines.append(f"    vle{state.sew}.v {vs1_group}, ({pointers[vs1]})")
            lines.append(f"    vle{state.sew}.v {vs2_group}, ({pointers[vs2]})")
            lines.append(f"    vle{state.sew}.v {vd_group}, ({pointers[vd]})")
            lines.append(f"    vfmacc.vv {vd_group}, {vs1_group}, {vs2_group}{', v0.t' if is_masked else ''}")
            lines.append(f"    vse{state.sew}.v {vd_group}, ({pointers[vd]})")
    else:
        # vadd 不读取旧 vd；lhs 组可直接承载输出，不因 masked form 额外分配
        # 旧目标组。最终 masked state store 是迁移状态的唯一提交点。
        dst_group, rhs_group = groups
        lhs_group = dst_group
        def body() -> None:
            emit_mask_load()
            lines.append(f"    vle{state.sew}.v {lhs_group}, ({pointers[vs1]})")
            lines.append(f"    vle{state.sew}.v {rhs_group}, ({pointers[vs2]})")
            lines.append(f"    vadd.vv {dst_group}, {lhs_group}, {rhs_group}{', v0.t' if is_masked else ''}")
            lines.append(
                f"    vse{state.sew}.v {dst_group}, ({pointers[vd]})"
                f"{', v0.t' if is_masked else ''}"
            )

    _emit_wide_loop(
        lines=lines,
        insn=insn,
        new_label=new_label,
        plan=plan,
        temps=temps,
        state_ptrs=list(dict.fromkeys(pointers.values())),
        mask_ptr=mask_ptr,
        mem_ptr=None,
        stride_reg=None,
        emit_body=body,
        # only FMA/FNMSAC consume the old destination. vadd/vfmul commit
        # masked lanes directly to state and can therefore use ma.
        mask_policy=("mu" if insn.opcode in {"vfmacc.vf", "vfnmsac.vf", "vfmacc.vv"} else "ma"),
    )
    return lines


_HOT_SCALAR_OPS = {"vadd.vi", "vadd.vx", "vrsub.vi", "vor.vx"}


def emit_wide_hot_arithmetic(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
) -> list[str] | None:
    """
    生成真实 llama 热点的异构 widening 与 scalar/immediate 宽路径。

    该入口与旧 ``emit_wide_arithmetic`` 分离，避免把同宽 planner 的假设
    偷渡到宽目标。所有状态指针按自身 EEW 前进，仍在单条源指令内完成
    读取、计算和写回。
    """
    split = _split_mask_operand(insn)
    supported = _HOT_SCALAR_OPS | {"vmacc.vx", "vwmacc.vx", "vwmacc.vv", "vfwmacc.vv", "vfwmul.vf", "vwadd.wv"}
    if insn.opcode not in supported or split is None:
        return None
    is_masked, operands = split
    if len(operands) != 3 or state.sew not in (8, 16, 32, 64):
        return None
    if insn.opcode in {"vmacc.vx", "vwmacc.vv", "vfwmacc.vv", "vfwmul.vf", "vwadd.wv"} and is_masked:
        return None
    if insn.opcode in {"vmacc.vx", "vwmacc.vv"} and (state.sew != 16 or state.lmul != 1):
        return None

    sew = int(state.sew)
    vd = str(operands[0])
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    lines: list[str] = []
    mask_ptr = None
    if is_masked:
        mask_ptr = temps.alloc_gpr()
        _emit_state_ptr(lines, mask_ptr, allocator.get_offset("v0"))

    pointers: dict[str, str] = {}

    def state_pointer(name: str) -> str:
        if name not in pointers:
            pointers[name] = temps.alloc_gpr()
            _emit_state_ptr(lines, pointers[name], allocator.get_offset(name))
        return pointers[name]

    def unique_steps(items: Iterable[tuple[str, int]]) -> list[tuple[str, int]]:
        """合并寄存器别名产生的重复指针；不同 EEW 的冲突形态必须回落。"""
        merged: dict[str, int] = {}
        for pointer, step in items:
            if pointer in merged and merged[pointer] != step:
                raise ValueError("同一模拟寄存器以不同 EEW 参与宽路径，无法安全推进指针")
            merged[pointer] = step
        return list(merged.items())

    if insn.opcode in _HOT_SCALAR_OPS:
        vs2 = str(operands[1])
        scalar_or_imm = str(operands[2])
        try:
            plan = plan_wide_operands(
                source_lmul=state.lmul,
                source_sew=sew,
                source_operands=((vd, sew), (vs2, sew)),
                target_vtype_sew=sew,
                # 此类 scalar/immediate 算术不读取旧 vd。masked form 用 ma
                # 配合 masked state store，不再为旧目标分配/加载额外组。
                target_operand_eews=(sew,),
            )
        except ValueError:
            return None
        if plan is None:
            return None
        dst_ptr = state_pointer(vd)
        src_ptr = state_pointer(vs2)
        groups = plan.group_bases
        (dst_group,) = groups
        src_group = dst_group

        def body() -> None:
            if mask_ptr is not None:
                record_vreg_group("v0", 1)
                lines.append(f"    vlm.v   v0, ({mask_ptr})")
            lines.append(f"    vle{sew}.v {src_group}, ({src_ptr})")
            lines.append(
                f"    {insn.opcode} {dst_group}, {src_group}, {scalar_or_imm}"
                f"{', v0.t' if is_masked else ''}"
            )
            lines.append(
                f"    vse{sew}.v {dst_group}, ({dst_ptr})"
                f"{', v0.t' if is_masked else ''}"
            )

        steps = unique_steps(
            (pointer, plan.elements_per_chunk * (sew // 8))
            for pointer in pointers.values()
        )

    elif insn.opcode == "vmacc.vx":
        scalar = str(operands[1])
        vs2 = str(operands[2])
        try:
            plan = plan_wide_operands(
                source_lmul=state.lmul,
                source_sew=sew,
                source_operands=((vd, sew), (vs2, sew)),
                target_vtype_sew=sew,
                target_operand_eews=(sew, sew),
            )
        except ValueError:
            return None
        if plan is None:
            return None
        dst_group, src_group = plan.group_bases
        dst_ptr, src_ptr = state_pointer(vd), state_pointer(vs2)
        remaining = temps.alloc_gpr()
        start = temps.alloc_gpr()
        _load_vl_from_csr(lines, remaining, start)
        _emit_state_ptr(lines, start, CSR_OFFSETS["vstart"])
        lines.append(f"    ld      {start}, 0({start})")
        end = new_label("wide_vmacc_vx_end")
        lines.append(f"    bgeu    {start}, {remaining}, {end}")
        lines.append(f"    sub     {remaining}, {remaining}, {start}")
        lines.append(f"    slli    {start}, {start}, 1")
        # Source e16/m1 has at most 64 lanes; preserve only the unfinished suffix.
        for pointer in pointers.values():
            lines.append(f"    add     {pointer}, {pointer}, {start}")
        _emit_vtype(lines, remaining, plan)
        lines.append(f"    vle16.v {dst_group}, ({dst_ptr})")
        lines.append(f"    vle16.v {src_group}, ({src_ptr})")
        lines.append(f"    vmacc.vx {dst_group}, {scalar}, {src_group}")
        lines.append(f"    vse16.v {dst_group}, ({dst_ptr})")
        lines.append(f"{end}:")
        lines.insert(
            0,
            f"# RVV256-WIDE: {insn.opcode}, source LMUL={state.lmul:g}, "
            f"target={plan.target_lmul_text}, chunk={plan.elements_per_chunk} elements, "
            "architectural vstart suffix",
        )
        return lines

    elif insn.opcode == "vwmacc.vx":
        if sew not in (8, 16, 32):
            return None
        scalar_reg = str(operands[1])
        vs2 = str(operands[2])
        output_sew = sew * 2
        try:
            plan = plan_wide_operands(
                source_lmul=state.lmul,
                source_sew=sew,
                source_operands=((vd, output_sew), (vs2, sew)),
                target_vtype_sew=sew,
                target_operand_eews=(output_sew, sew),
            )
        except ValueError:
            return None
        if plan is None:
            return None
        dst_group, src_group = plan.group_bases
        dst_ptr = state_pointer(vd)
        src_ptr = state_pointer(vs2)
        scalar = temps.alloc_gpr()
        lines.append(f"    slli    {scalar}, {scalar_reg}, {64 - sew}")
        lines.append(f"    srai    {scalar}, {scalar}, {64 - sew}")

        def body() -> None:
            if mask_ptr is not None:
                record_vreg_group("v0", 1)
                lines.append(f"    vlm.v   v0, ({mask_ptr})")
            lines.append(f"    vle{output_sew}.v {dst_group}, ({dst_ptr})")
            lines.append(f"    vle{sew}.v {src_group}, ({src_ptr})")
            lines.append(
                f"    vwmacc.vx {dst_group}, {scalar}, {src_group}"
                f"{', v0.t' if is_masked else ''}"
            )
            lines.append(f"    vse{output_sew}.v {dst_group}, ({dst_ptr})")

        try:
            steps = unique_steps([
                (dst_ptr, plan.elements_per_chunk * (output_sew // 8)),
                (src_ptr, plan.elements_per_chunk * (sew // 8)),
            ])
        except ValueError:
            return None

    elif insn.opcode in {"vwmacc.vv", "vfwmacc.vv"}:
        if sew not in (16, 32):
            return None
        vs1, vs2 = (str(operand) for operand in operands[1:])
        output_sew = sew * 2
        try:
            plan = plan_wide_operands(
                source_lmul=state.lmul,
                source_sew=sew,
                source_operands=((vd, output_sew), (vs1, sew), (vs2, sew)),
                target_vtype_sew=sew,
                target_operand_eews=(output_sew, sew, sew),
            )
        except ValueError:
            return None
        if plan is None:
            return None
        dst_group, lhs_group, rhs_group = plan.group_bases
        dst_ptr, lhs_ptr, rhs_ptr = (state_pointer(reg) for reg in (vd, vs1, vs2))

        def body() -> None:
            lines.append(f"    vle{output_sew}.v {dst_group}, ({dst_ptr})")
            lines.append(f"    vle{sew}.v {lhs_group}, ({lhs_ptr})")
            lines.append(f"    vle{sew}.v {rhs_group}, ({rhs_ptr})")
            lines.append(f"    {insn.opcode} {dst_group}, {lhs_group}, {rhs_group}")
            lines.append(f"    vse{output_sew}.v {dst_group}, ({dst_ptr})")

        try:
            steps = unique_steps([
                (dst_ptr, plan.elements_per_chunk * (output_sew // 8)),
                (lhs_ptr, plan.elements_per_chunk * (sew // 8)),
                (rhs_ptr, plan.elements_per_chunk * (sew // 8)),
            ])
        except ValueError:
            return None

    elif insn.opcode == "vfwmul.vf":
        if sew != 16 or float(state.lmul) != 1.0:
            return None
        vs2 = str(operands[1])
        scalar = str(operands[2])
        output_sew = 32
        try:
            plan = plan_wide_operands(
                source_lmul=state.lmul,
                source_sew=sew,
                source_operands=((vd, output_sew), (vs2, sew)),
                target_vtype_sew=sew,
                target_operand_eews=(output_sew, sew),
            )
        except ValueError:
            return None
        if plan is None:
            return None
        dst_group, src_group = plan.group_bases
        dst_ptr = state_pointer(vd)
        src_ptr = state_pointer(vs2)

        def body() -> None:
            lines.append(f"    vle16.v {src_group}, ({src_ptr})")
            lines.append(f"    vfwmul.vf {dst_group}, {src_group}, {scalar}")
            lines.append(f"    vse32.v {dst_group}, ({dst_ptr})")

        try:
            steps = unique_steps([
                (dst_ptr, plan.elements_per_chunk * 4),
                (src_ptr, plan.elements_per_chunk * 2),
            ])
        except ValueError:
            return None

    else:  # vwadd.wv
        if sew != 16 or float(state.lmul) != 1.0:
            return None
        wide_vs2 = str(operands[1])
        narrow_vs1 = str(operands[2])
        output_sew = sew * 2
        try:
            plan = plan_wide_operands(
                source_lmul=state.lmul,
                source_sew=sew,
                source_operands=((vd, output_sew), (wide_vs2, output_sew), (narrow_vs1, sew)),
                target_vtype_sew=sew,
                target_operand_eews=(output_sew, output_sew, sew),
            )
        except ValueError:
            return None
        if plan is None:
            return None
        dst_group, wide_group, narrow_group = plan.group_bases
        dst_ptr = state_pointer(vd)
        wide_ptr = state_pointer(wide_vs2)
        narrow_ptr = state_pointer(narrow_vs1)

        def body() -> None:
            lines.append(f"    vle{output_sew}.v {wide_group}, ({wide_ptr})")
            lines.append(f"    vle{sew}.v {narrow_group}, ({narrow_ptr})")
            lines.append(f"    vwadd.wv {dst_group}, {wide_group}, {narrow_group}")
            lines.append(f"    vse{output_sew}.v {dst_group}, ({dst_ptr})")

        try:
            steps = unique_steps([
                (dst_ptr, plan.elements_per_chunk * (output_sew // 8)),
                (wide_ptr, plan.elements_per_chunk * (output_sew // 8)),
                (narrow_ptr, plan.elements_per_chunk * (sew // 8)),
            ])
        except ValueError:
            return None

    lines.insert(
        0,
        f"# RVV256-WIDE{'-MASKED' if is_masked else ''}: {insn.opcode}, "
        f"source LMUL={state.lmul:g}, target={plan.target_lmul_text}, "
        f"chunk={plan.elements_per_chunk} elements",
    )
    if is_masked and insn.opcode in _HOT_SCALAR_OPS:
        lines.insert(
            1,
            "# RVV256-WIDE-MASKED-COMMIT: ma + masked state store, no old-vd preload",
        )
    _emit_wide_loop(
        lines=lines,
        insn=insn,
        new_label=new_label,
        plan=plan,
        temps=temps,
        state_ptrs=[],
        state_ptr_steps=steps,
        mask_ptr=mask_ptr,
        mem_ptr=None,
        stride_reg=None,
        emit_body=body,
        # widening MAC 读取旧累加器；其余本入口指令不读取旧 vd，masked
        # form 通过 masked state store 保留未命中元素的模拟状态。
        mask_policy=("mu" if insn.opcode == "vwmacc.vx" else "ma"),
    )
    return lines


def emit_wide_reduction(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
) -> list[str] | None:
    """使用真实 ``vwredsum.vs`` 取代栈 spill 后的逐元素标量规约。"""
    if insn.opcode != "vwredsum.vs":
        return None
    split = _split_mask_operand(insn)
    if split is None:
        return None
    is_masked, operands = split
    if len(operands) != 3 or state.sew not in (8, 16, 32):
        return None
    vd, vs2, vs1 = map(str, operands)
    sew = int(state.sew)
    output_sew = sew * 2
    try:
        plan = plan_wide_operands(
            source_lmul=state.lmul,
            source_sew=sew,
            # RVV reduction 的 vd/vs1 是 scalar register operand，不按源 LMUL
            # 形成寄存器组；只有待规约的 vs2 需要普通组对齐检查。
            source_operands=((vs2, sew),),
            target_vtype_sew=sew,
            target_operand_eews=(sew,),
        )
    except ValueError:
        return None
    if plan is None:
        return None

    allocated = WideVRegGroupAllocator().allocate((Fraction(1), plan.target_lmul))
    if allocated is None:
        return None
    acc_group, src_group = allocated
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    remaining = temps.alloc_gpr()
    actual_vl = temps.alloc_gpr()
    src_ptr = temps.alloc_gpr()
    seed_ptr = temps.alloc_gpr()
    dst_ptr = temps.alloc_gpr()
    scratch = temps.alloc_gpr()
    mask_ptr = temps.alloc_gpr() if is_masked else None
    loop = new_label("wide_vwredsum_loop")
    end = new_label("wide_vwredsum_end")

    lines = [
        f"# RVV256-WIDE{'-MASKED' if is_masked else ''}-REDUCTION: vwredsum.vs, "
        f"source LMUL={state.lmul:g}, target={plan.target_lmul_text}, "
        f"chunk={plan.elements_per_chunk} elements",
    ]
    _load_vl_from_csr(lines, remaining, scratch)
    lines.append(f"    beqz    {remaining}, {end}        # vl=0 时 vd 保持不变")
    _emit_state_ptr(lines, src_ptr, allocator.get_offset(vs2))
    _emit_state_ptr(lines, seed_ptr, allocator.get_offset(vs1))
    _emit_state_ptr(lines, dst_ptr, allocator.get_offset(vd))
    if mask_ptr is not None:
        _emit_state_ptr(lines, mask_ptr, allocator.get_offset("v0"))

    # reduction 的宽 seed/result 是单寄存器 scalar operand。先切换到
    # e(2*SEW),m1 装载 element 0，再切回窄 SEW 进行硬件 widening reduction，
    # 可避免错误地把 seed 当成 2*LMUL 寄存器组。
    lines.append(f"    vsetivli zero, 1, e{output_sew}, m1, ta, ma")
    lines.append(f"    vle{output_sew}.v {acc_group}, ({seed_ptr})")
    lines.append(f"{loop}:")
    lines.append(
        f"    vsetvli {actual_vl}, {remaining}, e{sew}, {plan.target_lmul_text}, ta, "
        f"{'mu' if is_masked else 'ma'}"
    )
    if mask_ptr is not None:
        record_vreg_group("v0", 1)
        lines.append(f"    vlm.v   v0, ({mask_ptr})")
    lines.append(f"    vle{sew}.v {src_group}, ({src_ptr})")
    lines.append(
        f"    vwredsum.vs {acc_group}, {src_group}, {acc_group}"
        f"{', v0.t' if is_masked else ''}"
    )
    lines.append(f"    addi    {src_ptr}, {src_ptr}, {plan.elements_per_chunk * (sew // 8)}")
    if mask_ptr is not None:
        lines.append(f"    addi    {mask_ptr}, {mask_ptr}, {plan.elements_per_chunk // 8}")
    lines.append(f"    sub     {remaining}, {remaining}, {actual_vl}")
    lines.append(f"    bnez    {remaining}, {loop}")
    # 规约只定义 vd[0]；只写一个宽元素可保留 vd 的其余迁移状态。
    lines.append(f"    vsetivli zero, 1, e{output_sew}, m1, ta, ma")
    lines.append(f"    vse{output_sew}.v {acc_group}, ({dst_ptr})")
    lines.append(f"{end}:")
    return lines


def _prepare_partial_mask_byte_merge(
    lines: list[str],
    *,
    actual_vl: str,
    dst_ptr: str,
    temps: TempRegisterAllocator,
    new_label,
    prefix: str,
) -> tuple[str, str, str, str, str]:
    """
    在 ``vsm.v`` 前保存最后一个不完整 mask byte 的旧值。

    RVV mask-producing 指令的 tail bit 可以采用 agnostic 值，不能只依赖
    ``tu``。返回的寄存器/标签由对应 finish helper 在 ``vsm.v`` 后合并，
    从而保证 ``vl`` 之外的 bit 对迁移状态完全透明。
    """
    tail_bits = temps.alloc_gpr()
    last_addr = temps.alloc_gpr()
    old_byte = temps.alloc_gpr()
    merge_tmp = temps.alloc_gpr()
    prepared = new_label(f"{prefix}_partial_prepared")
    lines.append(f"    andi    {tail_bits}, {actual_vl}, 7")
    lines.append(f"    beqz    {tail_bits}, {prepared}")
    lines.append(f"    addi    {last_addr}, {actual_vl}, -1")
    lines.append(f"    srli    {last_addr}, {last_addr}, 3")
    lines.append(f"    add     {last_addr}, {dst_ptr}, {last_addr}")
    lines.append(f"    lbu     {old_byte}, 0({last_addr})")
    lines.append(f"{prepared}:")
    return (
        tail_bits,
        last_addr,
        old_byte,
        merge_tmp,
        new_label(f"{prefix}_partial_done"),
    )


def _finish_partial_mask_byte_merge(
    lines: list[str],
    *,
    merge_state: tuple[str, str, str, str, str],
) -> None:
    """在 ``vsm.v`` 后恢复最后一字节中 ``vl`` 之外的旧 bit。"""
    tail_bits, last_addr, old_byte, tmp, done = merge_state
    lines.append(f"    beqz    {tail_bits}, {done}")
    # tmp_mask = (1 << tail_bits) - 1。生成 mask 后，tail_bits 已无须保留，
    # 可复用来装新 byte，从而不增加第五个 GPR live range。
    lines.append(f"    li      {tmp}, 1")
    lines.append(f"    sll     {tmp}, {tmp}, {tail_bits}")
    lines.append(f"    addi    {tmp}, {tmp}, -1")
    lines.append(f"    lbu     {tail_bits}, 0({last_addr})")
    lines.append(f"    and     {tail_bits}, {tail_bits}, {tmp}")
    lines.append(f"    not     {tmp}, {tmp}")
    lines.append(f"    and     {old_byte}, {old_byte}, {tmp}")
    lines.append(f"    or      {tail_bits}, {tail_bits}, {old_byte}")
    lines.append(f"    sb      {tail_bits}, 0({last_addr})")
    lines.append(f"{done}:")


def _allocate_native_mask_groups(
    insn: RVInstruction,
    emuls: Iterable[Fraction],
    *,
    wide_lmul: bool,
) -> tuple[str, ...] | None:
    """
    为原生 mask 路径分配临时向量寄存器。

    默认宽 profile 保留原来的 v8-v31 宽组约束；``--conservative`` 只能
    使用既有 ``VRegTempAllocator`` 的 v24-v31 池。分数 EMUL 仍占一个
    物理寄存器。
    """
    emuls = tuple(emuls)
    if wide_lmul:
        return WideVRegGroupAllocator().allocate(emuls)

    allocator = VRegTempAllocator(insn)
    groups: list[str] = []
    try:
        for emul in emuls:
            width = int(emul) if emul >= 1 else 1
            groups.append(allocator.alloc_vreg_group(width))
    except TempRegisterAllocationError:
        return None
    return tuple(groups)


def _vreg_index(reg: str) -> int | None:
    """返回规范向量寄存器编号；非 v0-v31 token 返回 ``None``。"""
    match = _VREG_RE.match(str(reg).strip().lower())
    return int(match.group(1)) if match else None


def _vmseq_output_overlaps_unread_source(
    *,
    vd: str,
    vs2: str,
    source_lmul: float | int | Fraction,
) -> bool:
    """
    判断 vmseq 输出 mask 会否覆盖同一源组中尚未读取的后续状态槽。

    ``vd == vs2`` 是安全别名：当前数据 chunk 已先完整装入目标硬件临时组，
    而输出只覆盖源状态起始槽，后续 chunk 不会再读取这段字节。若 ``vd`` 是
    整数 LMUL 源组内部的其他寄存器（如 source m4 的 v8 与 mask v9），第一
    次 ``vsm.v`` 会破坏后续尚未加载的源数据，必须回退规格表绑定的保守
    builder。
    """
    vd_index = _vreg_index(vd)
    vs2_index = _vreg_index(vs2)
    if vd_index is None or vs2_index is None or vd_index == vs2_index:
        return False
    lmul = _as_fraction(source_lmul)
    if lmul < 1 or lmul.denominator != 1:
        return False
    return vs2_index < vd_index < vs2_index + int(lmul)


def emit_wide_mask(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    wide_lmul: bool = True,
) -> list[str] | AssemblyFragments | None:
    """
    生成 llama 高频 mask compare/logic/scan 的真实 RVV 路径。

    名称为兼容既有调用保留 ``wide``，但它同时服务两种 profile（配置）：
    ``--conservative`` 只使用 v24-v31 与 m1/m2 小块；默认宽 profile 使用
    v8-v31 和尽可能大的 LMUL。两种模式都在单条源指令内完成状态块读写，
    因而不要求修改迁移协议。
    """
    opcode = insn.opcode
    if opcode not in {"vmseq.vi", "vmor.mm", "vfirst.m", "vcpop.m"}:
        return None
    operands = list(insn.operands)
    if any(str(op).strip().endswith(".t") for op in operands):
        # 本轮这些 mask-producing/scanning 指令只实现 unmasked form；显式
        # execution mask 继续交给统一规格 validator/lowerer 产生明确错误。
        return None

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    profile = "wide-lmul" if wide_lmul else "default"
    lines: list[str] = [f"# RVV256-NATIVE-MASK: {opcode} ({profile})"]

    if opcode == "vmseq.vi":
        if len(operands) != 3 or state.sew not in (8, 16, 32, 64):
            return None
        vd, vs2, immediate = map(str, operands)
        try:
            imm_value = int(immediate, 0)
        except ValueError:
            return _reject_shape(insn, f"vmseq.vi 非法立即数: {immediate}")
        if imm_value < -16 or imm_value > 15:
            return _reject_shape(insn, f"vmseq.vi 立即数超出 signed 5-bit: {immediate}")
        sew = int(state.sew)
        if _vmseq_output_overlaps_unread_source(
            vd=vd,
            vs2=vs2,
            source_lmul=state.lmul,
        ):
            return None

        max_target_lmul = Fraction(8) if wide_lmul else Fraction(1)
        try:
            plan = plan_wide_operands(
                source_lmul=state.lmul,
                source_sew=sew,
                source_operands=((vs2, sew),),
                target_vtype_sew=sew,
                target_operand_eews=(sew,),
                max_target_lmul=max_target_lmul,
            )
        except ValueError:
            return None
        if plan is None:
            return None

        # 保守 e64,m1 每块只有 4 个 mask bit，连续块会从同一字节的高半部
        # 开始，不能按 byte pointer 前进。对多块形态提升到 m2（8 bit/块）；
        # 若资源不足则回退规格 builder，而非生成错误的 addi ..., 0。
        if (
            not wide_lmul
            and not plan.one_shot
            and plan.elements_per_chunk % 8
        ):
            try:
                plan = plan_wide_operands(
                    source_lmul=state.lmul,
                    source_sew=sew,
                    source_operands=((vs2, sew),),
                    target_vtype_sew=sew,
                    target_operand_eews=(sew,),
                    max_target_lmul=Fraction(2),
                )
            except ValueError:
                return None
            if plan is None or (not plan.one_shot and plan.elements_per_chunk % 8):
                return None

        allocated = _allocate_native_mask_groups(
            insn,
            (plan.target_lmul, Fraction(1)),
            wide_lmul=wide_lmul,
        )
        if allocated is None:
            return None
        data_group, mask_group = allocated
        remaining = temps.alloc_gpr()
        actual_vl = temps.alloc_gpr()
        src_ptr = temps.alloc_gpr()
        dst_ptr = temps.alloc_gpr()
        scratch = temps.alloc_gpr()
        loop = new_label("native_vmseq_vi_loop")
        end = new_label("native_vmseq_vi_end")
        _load_vl_from_csr(lines, remaining, scratch)
        _emit_state_ptr(lines, src_ptr, allocator.get_offset(vs2))
        _emit_state_ptr(lines, dst_ptr, allocator.get_offset(vd))
        lines.append(f"{loop}:")
        lines.append(f"    beqz    {remaining}, {end}")
        # vsm.v 的最后不完整 byte 由 merge helper 保护；结果 mask 本身无需
        # 预装旧目标，也不需要 tu。删除这次状态块读取是该路径的核心优化。
        lines.append(
            f"    vsetvli {actual_vl}, {remaining}, e{sew}, "
            f"{plan.target_lmul_text}, ta, ma"
        )
        merge_state = _prepare_partial_mask_byte_merge(
            lines,
            actual_vl=actual_vl,
            dst_ptr=dst_ptr,
            temps=temps,
            new_label=new_label,
            prefix="native_vmseq_vi",
        )
        lines.append(f"    vle{sew}.v {data_group}, ({src_ptr})")
        lines.append(f"    vmseq.vi {mask_group}, {data_group}, {immediate}")
        lines.append(f"    vsm.v   {mask_group}, ({dst_ptr})")
        _finish_partial_mask_byte_merge(lines, merge_state=merge_state)
        lines.append(f"    addi    {src_ptr}, {src_ptr}, {plan.elements_per_chunk * (sew // 8)}")
        if plan.elements_per_chunk // 8:
            lines.append(f"    addi    {dst_ptr}, {dst_ptr}, {plan.elements_per_chunk // 8}")
        lines.append(f"    sub     {remaining}, {remaining}, {actual_vl}")
        lines.append(f"    j       {loop}")
        lines.append(f"{end}:")
        return lines

    # mask-mask 操作与 scan 的元素本身就是 bit。宽 profile 使用 e8,m8，一次
    # 覆盖 256 bit；保守 profile 使用 e8,m1，仅使用已有 v24-v31 临时池。
    if opcode == "vmor.mm":
        if len(operands) != 3:
            return None
        vd, vs2, vs1 = map(str, operands)
        remaining = temps.alloc_gpr()
        actual_vl = temps.alloc_gpr()
        unique_regs = list(dict.fromkeys((vd, vs2, vs1)))
        groups = _allocate_native_mask_groups(
            insn,
            (Fraction(1),) * len(unique_regs),
            wide_lmul=wide_lmul,
        )
        if groups is None:
            return None
        group_by_reg = dict(zip(unique_regs, groups))
        out_group = group_by_reg[vd]
        src2_group = group_by_reg[vs2]
        src1_group = group_by_reg[vs1]

        pointers: dict[str, str] = {}

        def state_pointer(reg: str) -> str:
            if reg not in pointers:
                pointer = temps.alloc_gpr()
                _emit_state_ptr(lines, pointer, allocator.get_offset(reg))
                pointers[reg] = pointer
            return pointers[reg]

        dst_ptr = state_pointer(vd)
        src2_ptr = state_pointer(vs2)
        src1_ptr = state_pointer(vs1)
        scratch = temps.alloc_gpr()
        loop = new_label("native_vmor_loop")
        end = new_label("native_vmor_end")
        _load_vl_from_csr(lines, remaining, scratch)
        target_lmul = "m8" if wide_lmul else "m1"
        chunk_bytes = 32 if wide_lmul else 4
        lines.append(f"{loop}:")
        lines.append(f"    beqz    {remaining}, {end}")
        lines.append(f"    vsetvli {actual_vl}, {remaining}, e8, {target_lmul}, ta, ma")
        merge_state = _prepare_partial_mask_byte_merge(
            lines,
            actual_vl=actual_vl,
            dst_ptr=dst_ptr,
            temps=temps,
            new_label=new_label,
            prefix="native_vmor",
        )
        # group_by_reg 自动覆盖 vd==vs1/vs2 与 vs1==vs2：只有真正作为输入的
        # 槽才会读取。无别名时 vd 是纯输出，绝不能为了 tu/mu 预装目标 mask；
        # 所有输入都在 vsm.v 覆盖状态前完成读取。
        input_regs = list(dict.fromkeys((vs2, vs1)))
        for reg in input_regs:
            lines.append(f"    vlm.v   {group_by_reg[reg]}, ({pointers[reg]})")
        lines.append(f"    vmor.mm {out_group}, {src2_group}, {src1_group}")
        lines.append(f"    vsm.v   {out_group}, ({dst_ptr})")
        _finish_partial_mask_byte_merge(lines, merge_state=merge_state)
        for pointer in dict.fromkeys(pointers.values()):
            lines.append(f"    addi    {pointer}, {pointer}, {chunk_bytes}")
        lines.append(f"    sub     {remaining}, {remaining}, {actual_vl}")
        lines.append(f"    j       {loop}")
        lines.append(f"{end}:")
        return lines

    if len(operands) != 2:
        return None
    rd, vs2 = map(str, operands)
    # VectorBlockEmitter 需要临时移动 sp 来保存 caller-saved 寄存器；若把
    # vfirst/vcpop 的标量结果直接写到 sp/x2，现有 ABI wrapper 无法同时完成
    # 自身栈帧恢复和保留该源语义输出。比起静默丢失结果，明确 fail-fast，等待
    # 专门的无栈 wrapper/控制流改造后再扩展这一个罕见形态。
    if rd.strip().lower() in {"sp", "x2"}:
        return _reject_shape(insn, f"{opcode} 暂不支持把标量结果写入 sp/x2: {insn.op_str}")

    # t6/x31 在翻译块内固定充当 simulated_cpu_state 基址。结果必须先在普通
    # 临时 GPR 中累计，清零 vstart 后才写回 t6；否则 new_label 的统一
    # vstart 写回会把已覆盖的 t6 当成状态地址，造成错误访问甚至越界。
    writes_semantic_t6 = rd.strip().lower() in {"t6", "x31"}
    mask_group = _allocate_native_mask_groups(
        insn,
        (Fraction(1),),
        wide_lmul=wide_lmul,
    )
    if mask_group is None:
        return None
    (mask_group,) = mask_group
    remaining = temps.alloc_gpr()
    actual_vl = temps.alloc_gpr()
    src_ptr = temps.alloc_gpr()
    chunk_value = temps.alloc_gpr()
    scratch = temps.alloc_gpr()
    _load_vl_from_csr(lines, remaining, scratch)
    _emit_state_ptr(lines, src_ptr, allocator.get_offset(vs2))
    target_lmul = "m8" if wide_lmul else "m1"
    chunk_bytes = 32 if wide_lmul else 4

    if opcode == "vcpop.m":
        result_reg = temps.alloc_gpr() if writes_semantic_t6 else rd
        loop = new_label("native_vcpop_loop")
        end = new_label("native_vcpop_end")
        lines.append(f"    li      {result_reg}, 0")
        lines.append(f"{loop}:")
        lines.append(f"    beqz    {remaining}, {end}")
        lines.append(f"    vsetvli {actual_vl}, {remaining}, e8, {target_lmul}, ta, ma")
        lines.append(f"    vlm.v   {mask_group}, ({src_ptr})")
        lines.append(f"    vcpop.m {chunk_value}, {mask_group}")
        lines.append(f"    add     {result_reg}, {result_reg}, {chunk_value}")
        lines.append(f"    addi    {src_ptr}, {src_ptr}, {chunk_bytes}")
        lines.append(f"    sub     {remaining}, {remaining}, {actual_vl}")
        lines.append(f"    j       {loop}")
        lines.append(f"{end}:")
        if writes_semantic_t6:
            return AssemblyFragments(
                tuple(lines),
                (f"    mv      {rd}, {result_reg}",),
            )
        return lines

    # vfirst.m：chunk_value 是块内 bit 下标，需要叠加已经扫描的元素数。
    result_reg = temps.alloc_gpr() if writes_semantic_t6 else rd
    base_index = temps.alloc_gpr()
    loop = new_label("native_vfirst_loop")
    found = new_label("native_vfirst_found")
    end = new_label("native_vfirst_end")
    lines.append(f"    li      {result_reg}, -1")
    lines.append(f"    li      {base_index}, 0")
    lines.append(f"{loop}:")
    lines.append(f"    beqz    {remaining}, {end}")
    lines.append(f"    vsetvli {actual_vl}, {remaining}, e8, {target_lmul}, ta, ma")
    lines.append(f"    vlm.v   {mask_group}, ({src_ptr})")
    lines.append(f"    vfirst.m {chunk_value}, {mask_group}")
    lines.append(f"    bgez    {chunk_value}, {found}")
    lines.append(f"    add     {base_index}, {base_index}, {actual_vl}")
    lines.append(f"    addi    {src_ptr}, {src_ptr}, {chunk_bytes}")
    lines.append(f"    sub     {remaining}, {remaining}, {actual_vl}")
    lines.append(f"    j       {loop}")
    lines.append(f"{found}:")
    lines.append(f"    add     {result_reg}, {base_index}, {chunk_value}")
    lines.append(f"{end}:")
    if writes_semantic_t6:
        return AssemblyFragments(
            tuple(lines),
            (f"    mv      {rd}, {result_reg}",),
        )
    return lines


_MEMORY_RE = re.compile(r"^(vle|vse|vlse|vsse)(8|16|32|64)\.v$")


def emit_wide_memory(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
) -> list[str] | None:
    """尝试生成首批 unit/strided 访存宽路径；支持显式 ``v0.t``。"""
    split = _split_mask_operand(insn)
    if split is None:
        return None
    is_masked, operands = split
    match = _MEMORY_RE.match(insn.opcode)
    if not match:
        return None
    kind, eew_text = match.groups()
    # vsse32/vsse64 都遵循同一条“从状态块紧凑加载、再按 byte stride
    # 写入真实内存”的宽路径。其余 EEW 的 strided store 仍交给 legacy
    # handler，避免在没有对应状态/掩码证明前扩大白名单。
    if kind == "vsse" and insn.opcode not in {"vsse32.v", "vsse64.v"}:
        return None
    eew = int(eew_text)
    expected = 3 if kind in ("vlse", "vsse") else 2
    if len(operands) < expected:
        return _reject_shape(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")
    vector_reg = str(operands[0])
    base_reg = str(operands[1]).strip("()")
    stride_reg = str(operands[2]) if expected == 3 else None

    try:
        plan = plan_wide_chunk(
            source_lmul=state.lmul,
            source_sew=state.sew,
            data_sew=eew,
            source_regs=(vector_reg,),
            target_group_count=1,
            max_target_lmul=(
                4 if kind == "vle" and not is_masked
                and eew == state.sew == 32 and state.lmul == 8 else 8
            ),
        )
    except ValueError as exc:
        return _reject_shape(insn, str(exc))
    if plan is None:
        return None

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    lines = [
        f"# RVV256-WIDE{'-MASKED' if is_masked else ''}: {insn.opcode}, source LMUL={state.lmul:g}, "
        f"target=e{eew},{plan.target_lmul_text}, chunk={plan.elements_per_chunk} elements"
    ]
    if is_masked and kind in ("vle", "vlse"):
        lines.append(
            "# RVV256-WIDE-MASKED-COMMIT: ma + masked state store, no old-vd preload"
        )
    state_ptr = temps.alloc_gpr()
    # one-shot 不前移真实内存指针，直接读取原始 ABI 输入可避免一次 mv 和
    # 一个被写 GPR；多块路径才需要独立可修改的 mem_ptr。
    mem_ptr = base_reg if plan.one_shot else temps.alloc_gpr()
    _emit_state_ptr(lines, state_ptr, allocator.get_offset(vector_reg))
    if not plan.one_shot:
        lines.append(f"    mv      {mem_ptr}, {base_reg}")
    (group,) = plan.group_bases

    mask_ptr = None
    if is_masked:
        mask_ptr = temps.alloc_gpr()
        _emit_state_ptr(lines, mask_ptr, allocator.get_offset("v0"))

    def emit_mask_load() -> None:
        if mask_ptr is not None:
            record_vreg_group("v0", 1)
            lines.append(f"    vlm.v   v0, ({mask_ptr})")

    if kind in ("vle", "vlse"):
        load_opcode = f"{kind}{eew}.v"
        def body() -> None:
            emit_mask_load()
            suffix = f", {stride_reg}" if stride_reg is not None else ""
            lines.append(f"    {load_opcode} {group}, ({mem_ptr}){suffix}{', v0.t' if is_masked else ''}")
            lines.append(
                f"    vse{eew}.v {group}, ({state_ptr})"
                f"{', v0.t' if is_masked else ''}"
            )
    else:
        store_opcode = f"{kind}{eew}.v"
        def body() -> None:
            emit_mask_load()
            suffix = f", {stride_reg}" if stride_reg is not None else ""
            lines.append(f"    vle{eew}.v {group}, ({state_ptr})")
            lines.append(f"    {store_opcode} {group}, ({mem_ptr}){suffix}{', v0.t' if is_masked else ''}")

    _emit_wide_loop(
        lines=lines,
        insn=insn,
        new_label=new_label,
        plan=plan,
        temps=temps,
        state_ptrs=[state_ptr],
        mask_ptr=mask_ptr,
        mem_ptr=mem_ptr,
        stride_reg=stride_reg,
        emit_body=body,
        # 访存 load/store 不把旧 vd 作为算术输入。masked load 通过 masked
        # state store 提交，masked store 只影响 guest memory，因此均可 ma。
        mask_policy="ma",
    )
    return lines


def emit_wide_whole_register_move(
    insn: RVInstruction,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    wide_lmul: bool = True,
) -> list[str] | None:
    """
    用目标 whole-register（整寄存器）搬运指令实现 ``vmvNr.v``。

    源 RVV-1024 的一个模拟向量寄存器槽固定为 128B，而 RVV-256 目标的
    ``vl4r.v`` / ``vs4r.v`` 恰好搬运 4 * 32B = 128B；``vl8r.v`` /
    ``vs8r.v`` 则恰好搬运 256B。它们不读取 ``vl`` 或 ``vtype``，所以
    既能用于保守路径，也能用于默认宽 profile，且不会改变迁移时状态块
    立即可见的约束。

    与旧 e8,m4/m8 + 普通 ``vle8/vse8`` 方案相比，这里不再写目标 vtype，
    不再维护运行时 AVL，也不需要循环计数器；最大 1024B 组仅展开为四个
    256B 的静态搬运。
    """
    match = re.match(r"^vmv([1248])r\.v$", insn.opcode)
    if not match or len(insn.operands) != 2:
        if match:
            return _reject_shape(insn, f"{insn.opcode} 不接受 execution mask 或额外操作数: {insn.op_str}")
        return None
    nf = int(match.group(1))
    vd, vs2 = map(str, insn.operands[:2])
    try:
        _validate_source_group(vd, Fraction(nf))
        _validate_source_group(vs2, Fraction(nf))
    except ValueError as exc:
        return _reject_shape(insn, str(exc))

    total_bytes = nf * allocator.vreg_size

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    lines = [
        f"# RVV256-NATIVE-WHOLE: {insn.opcode}, {total_bytes} bytes, "
        "state ABI fixed-slot copy"
    ]

    # 同一完整寄存器组的 move 没有数据副作用；new_label 仍会在外层清零
    # simulated vstart，因此不能把整条源指令直接省略。
    if vd == vs2:
        lines.append("    # source and destination are the same whole-register group")
        return lines

    src_ptr = temps.alloc_gpr()
    dst_ptr = temps.alloc_gpr()
    _emit_state_ptr(lines, src_ptr, allocator.get_offset(vs2))
    _emit_state_ptr(lines, dst_ptr, allocator.get_offset(vd))

    # 保守 profile 不得因这一优化触及默认宽 profile 的 v8-v23；既有
    # legacy 临时池 v24-v31 恰好也满足 m4/m8 对齐。默认宽路径仍从 v8
    # 开始，以保留原有宽临时量布局。搬运宽度由方向几何推导：源状态槽
    # 128B 需要目标 4 个物理寄存器，256B 组需要 8 个；每段都完全覆盖其
    # 对应的模拟状态字节范围。
    geometry = RVV1024_TO_RVV256_GEOMETRY
    one_slot_bytes = allocator.vreg_size
    one_slot_regs = geometry.whole_register_transfer_lmul(one_slot_bytes)
    two_slot_regs = geometry.whole_register_transfer_lmul(one_slot_bytes * 2)
    temp_group = "v8" if wide_lmul else "v24"
    remaining = total_bytes
    while remaining:
        if remaining >= one_slot_bytes * 2:
            chunk_bytes, whole_width = one_slot_bytes * 2, two_slot_regs
        else:
            chunk_bytes, whole_width = one_slot_bytes, one_slot_regs
        lines.append(f"    vl{whole_width}r.v {temp_group}, ({src_ptr})")
        lines.append(f"    vs{whole_width}r.v {temp_group}, ({dst_ptr})")
        remaining -= chunk_bytes
        if remaining:
            lines.append(f"    addi    {src_ptr}, {src_ptr}, {chunk_bytes}")
            lines.append(f"    addi    {dst_ptr}, {dst_ptr}, {chunk_bytes}")
    return lines


def emit_wide_whole_register_memory(
    insn: RVInstruction,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    wide_lmul: bool = True,
) -> list[str] | None:
    """
    用目标 whole-register 指令实现已注册的 whole-register load/store。

    源语义与当前 ``vl/vtype`` 无关，每个模拟 vreg 恒为 128B；因此这里统一
    使用固定大小的 ``vl4r/vs4r`` 或 ``vl8r/vs8r`` 数据搬运，而不从 opcode
    的 re16/re32/re64 后缀推导元素个数。目标指令同样与当前 vtype/vl 无关。
    """
    load_match = re.match(r"^vl([1248])(r|re(?:16|32|64))\.v$", insn.opcode)
    store_match = re.match(r"^vs([1248])r\.v$", insn.opcode)
    if not load_match and not store_match:
        return None
    if len(insn.operands) != 2:
        return _reject_shape(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    nf = int((load_match or store_match).group(1))
    vector_reg = str(insn.operands[0])
    base_reg = str(insn.operands[1]).strip("()")
    try:
        _validate_source_group(vector_reg, Fraction(nf))
    except ValueError as exc:
        return _reject_shape(insn, str(exc))

    total_bytes = nf * allocator.vreg_size

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    state_ptr = temps.alloc_gpr()
    lines = [
        f"# RVV256-NATIVE-WHOLE-MEM: {insn.opcode}, {total_bytes} bytes, "
        "state ABI fixed-slot transfer"
    ]
    _emit_state_ptr(lines, state_ptr, allocator.get_offset(vector_reg))

    # 单段直接使用源程序的基址寄存器，避免无意义的 mv；多段才复制，以免
    # 前移语义寄存器。state_ptr 始终是本翻译块私有临时值。
    geometry = RVV1024_TO_RVV256_GEOMETRY
    one_slot_bytes = allocator.vreg_size
    one_slot_regs = geometry.whole_register_transfer_lmul(one_slot_bytes)
    two_slot_bytes = one_slot_bytes * 2
    two_slot_regs = geometry.whole_register_transfer_lmul(two_slot_bytes)
    remaining = total_bytes
    mem_ptr = base_reg
    if remaining > two_slot_bytes:
        mem_ptr = temps.alloc_gpr()
        lines.append(f"    mv      {mem_ptr}, {base_reg}")

    # 与 vmvNr.v 一致，保守 profile 只使用 v24-v31；默认宽 profile 可使用
    # 宽路径既有的 v8-v15。whole-register 指令不读 vtype，但目标物理寄存器
    # 的临时占用范围仍是部署合同的一部分。
    temp_group = "v8" if wide_lmul else "v24"
    while remaining:
        if remaining >= two_slot_bytes:
            chunk_bytes, whole_width = two_slot_bytes, two_slot_regs
        else:
            chunk_bytes, whole_width = one_slot_bytes, one_slot_regs
        if load_match:
            # ``vlNreEEW`` 的 EEW 也描述访存的对齐/异常属性。虽然搬运的
            # 总字节数只由 N 和 VLEN 决定，仍必须保留 re16/re32/re64 编码，
            # 不能一律降成 e8 的 vlNr.v；否则可能改变原程序可观察到的
            # misaligned-access（非对齐访问）行为。
            load_kind = load_match.group(2)
            lines.append(f"    vl{whole_width}{load_kind}.v {temp_group}, ({mem_ptr})")
            lines.append(f"    vs{whole_width}r.v {temp_group}, ({state_ptr})")
        else:
            lines.append(f"    vl{whole_width}r.v {temp_group}, ({state_ptr})")
            lines.append(f"    vs{whole_width}r.v {temp_group}, ({mem_ptr})")
        remaining -= chunk_bytes
        if remaining:
            lines.append(f"    addi    {state_ptr}, {state_ptr}, {chunk_bytes}")
            lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {chunk_bytes}")
    return lines
