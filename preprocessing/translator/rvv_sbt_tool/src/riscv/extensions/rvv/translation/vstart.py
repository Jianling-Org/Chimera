"""Enforce restart policies for the shared simulated-state ABI."""

from __future__ import annotations

from riscv.extensions.rvv.runtime.access import STATE_BASE_MARKER
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.translation.contracts import HandlerContext, LoweringPlan, VStartPolicy
from riscv.extensions.rvv.translation.lowering import AssemblyFragments
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator


def apply_vstart_policy(
    context: HandlerContext, plan: LoweringPlan, fragments: AssemblyFragments,
) -> AssemblyFragments:
    policy = plan.spec.vstart_policy
    if policy is VStartPolicy.NOT_APPLICABLE or not (
        fragments.body_lines or fragments.post_state_lines
    ):
        return fragments

    temp = TempRegisterAllocator(context.instruction, reserved_gprs=("t6",)).alloc_gpr()
    prefix: tuple[str, ...] = ()
    if policy is VStartPolicy.REQUIRE_ZERO:
        ready = context.new_label("vstart_zero")
        prefix = (
            f"    li      {temp}, {CSR_OFFSETS['vstart']:#x}",
            f"    add     {temp}, t6, {temp}  # {STATE_BASE_MARKER}",
            f"    ld      {temp}, 0({temp})",
            f"    beqz    {temp}, {ready}",
            "    ebreak                          # unsupported nonzero source vstart",
            f"{ready}:",
        )
    clear = (
        f"    li      {temp}, {CSR_OFFSETS['vstart']:#x}",
        f"    add     {temp}, t6, {temp}  # {STATE_BASE_MARKER}",
        f"    sd      zero, 0({temp})              # CSR.vstart = 0 after vector completion",
    )
    # A deferred guest result may overwrite t6, so clear state before committing it.
    return AssemblyFragments(
        prefix + fragments.body_lines + clear, fragments.post_state_lines,
    )
