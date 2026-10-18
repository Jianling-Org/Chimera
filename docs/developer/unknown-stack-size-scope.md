# Explicit scope for unknown scalar stack sizes

The default `conservative` policy treats an unproven scalar stack-pointer adjustment as possibly VLEN-dependent. Profiles can opt into a narrower, explicitly conditional report by adding this parameter to the `safety` workflow step:

```toml
[[profile.workflow.steps]]
step = "safety"
parameters = { min_vlen_bits = 256, compiler_metadata = [], unknown_stack_size_policy = "assume-scalar-independent" }
```

With `assume-scalar-independent`, the analyzer omits only an allocation whose register dependency analysis reaches a fixed point and whose size remains `UNKNOWN` after the existing expression and origin-proof checks. Those checks may report missing evidence or an origin-proof budget gap; the policy assumes the remaining unknown scalar sizes are independent of hardware VLEN. It does not waive an incomplete register fixed-point analysis. This includes values supplied by callers, memory loads and external calls. The assumption is not an independence proof. Reports identify the policy and assumption, set `conditional: true` even when there are no excluded allocations, and list each excluded allocation separately from active frame origins.

Known VLEN evidence remains active, including a direct `vlenb` value, VLEN evidence retained through a join or origin-proof chain, and scalar constants selected by a known `vlenb` branch. A selected value remains tainted across a join, while the structural control region ends at a reliable CFG postdominator. An unrelated value written after that join does not inherit the old branch's VLEN evidence.

The policy does not remove vector stack loads/stores, compiler or binary stack-object sources, conservative markers, irreducible-loop degradation, or findings already active for another reason. A later unknown adjustment also does not release an already-active VLEN frame.

The reverse postdominator graph models explicit returns and conservative divergence exits for unresolved terminals or reachable regions with no return, which prevents a missing path from creating a false join. If a conditional still has no reliable boundary, or the bounded control-dependence budget is exhausted, the analysis propagates its known-VLEN control conservatively along reachable successors. `FunctionDependencyState.known_control_fallback` records these explicit precision fallbacks; it does not flag every divergence exit and does not prove that a particular size is VLEN-derived. Selected-value provenance remains separate from this structural fallback.

Register dependency solving has a separate update budget. If it expires before a fixed point, partial register and selected-value states are discarded and certified dependency queries return `UNKNOWN`. Stack adjustments whose status depends on that incomplete analysis remain active even under the opt-in policy, and their allocation origins carry a `register-dependency-budget-exhausted` gap with a matching warning. This status is distinct from structural `known_control_fallback` and from the whole-program origin-proof budget.

The shared profile parameter reaches prepare and `check-elf`; it is part of the version-32 check fingerprint. Version 31 avoided synthetic all-cache uses at completely resolved internal ABI exits while preserving actual target, SP and continuation uses and open-transfer guards. Version 32 adds a separate unsafe origin for control regions selected by a known live VLEN-derived value, so overwriting the old scalar copy does not make the selected path safe; the region ends at a reliably computed CFG join, otherwise reachable code remains conservatively unsafe with a warning. It also binds the standard libc `memcpy` interface as having no application callback contract, without claiming that the provider implementation is a scalar leaf. Existing dependency-budget, active external-boundary and content-pinned external scalar-leaf rules remain. Return and memory-write dependencies stay separate. Version 30 introduced actual local width copies, width conversions and private spills; selection influence and confirmed non-stack writes remain informational warnings. Cache analysis does not import ABI argument/return taint or require the bounded internal leaf-effect proof. This scope does not relax the existing stack-size proof engine. Credentials from earlier versions require a fresh check. A credential produced under one policy cannot authorize a workflow using the other policy. Cached safety reports retain and validate their policy before replay; opted-in external leaf proofs require fresh binding. See [static external-call gating](static-external-call-gate.md) and [scalar width liveness](scalar-vlen-liveness.md).

## Application and validation

Choose the policy explicitly in the application's `safety` step; preserve the exact profile with the ELF and check report. The same profile and policy must be used for subsequent prepare. Use the formal CLI with a fresh output directory:

```bash
chimera-pkg check-elf --strict --profile "$PROFILE" --strategy gate \
    --input "$ELF" --json "$OUT/check.json" \
    --inheritance-report "$OUT/inheritance.json"
```

The profile, ELF and output paths belong to the current machine and run. The removed gate4 scope-test driver is not needed. Exit 0 is necessary but the report must also contain all requested checks, `passed=true` and no actionable findings. A conditional scope is still a conditional scope when no findings remain. Reports retaining origin-proof gaps or exhausted proof budgets must not be described as unconditional size proofs.

The GCC integration workflow is documented in [the GCC guide](gcc-workflow.md). Historical measurements and intermediate plans are retained separately from the product documentation; each new binary requires fresh checks and target validation.
