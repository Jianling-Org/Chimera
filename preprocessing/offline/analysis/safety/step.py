"""Run the complete safety analysis once for the input ELF."""

from __future__ import annotations

from collections import Counter
import json
import sys

from chimera.runtime.manifest import ArtifactRecord

from ..core.contracts import AnalysisContext, ElfModuleServices, VectorExtensionServices
from ..core.monitor import local, monitored, returned
from .classifier import classify_liveness
from .result import SafetyPipelineResult
from .external_leaf import (
    CONTRACT_CAPABILITY, ExternalLeafBindings, bind_external_scalar_leaves, normalize_leaf_contracts,
)
from .stack_liveness import ChimeraMetadata, StackLivenessAnalyzer
from .stack_liveness.model import ACTIVE_EXTERNAL_CALL, ACTIONABLE_CALL_WARNINGS, UNRESOLVED_ACTIVE_CALL
from .stack_liveness.scope import (
    CONSERVATIVE,
    assumption_for_policy,
    is_conditional_policy,
    normalize_unknown_stack_size_policy,
)
from .exporters import (
    SAFETY_ABI_VERSION,
    export_asm_table,
    export_inheritance_trace,
    export_json,
)
from ..core.workspace import sha256_file


def _compute_summary(
    *,
    module_id: str,
    config_functions: int,
    vector,
    stack,
    safety,
    warnings,
) -> dict[str, object]:
    records = safety.records
    safe = sum(record.safe for record in records.values())
    warning_counts = Counter(warning.code for warning in warnings)
    return {
        "module_id": module_id,
        "instructions": {
            "total": len(records),
            "safe": safe,
            "unsafe": len(records) - safe,
        },
        "functions": {
            "vector_config": config_functions,
            "vector_liveness": len(vector.by_function),
            "stack": len(stack.by_function),
        },
        "calls": {
            "inherited_functions": len(stack.inherited_functions),
            "unresolved_active_calls": len(
                stack.unresolved_live_calls
            ),
            "active_external_calls": len(getattr(stack, "active_external_calls", ())),
            "closed_external_calls": len(getattr(stack, "closed_external_calls", {})),
            "seed_edges": len(stack.inheritance_trace.seed_edges),
            "max_inheritance_depth": stack.inheritance_trace.max_depth,
        },
        "warnings": {
            "total": len(warnings),
            "by_code": dict(sorted(warning_counts.items())),
        },
        "unknown_stack_size_policy": getattr(stack, "unknown_stack_size_policy", CONSERVATIVE),
        "assumption": getattr(
            stack,
            "assumption",
            assumption_for_policy(
                getattr(stack, "unknown_stack_size_policy", CONSERVATIVE)
            ),
        ),
        "conditional": bool(
            getattr(
                stack,
                "conditional",
                is_conditional_policy(
                    getattr(stack, "unknown_stack_size_policy", CONSERVATIVE)
                ),
            )
        ),
        "scope_exclusion_count": sum(
            len(getattr(local, "scope_exclusions", ()))
            for local in stack.by_function.values()
        ),
        "external_scalar_leaves": {
            "proofs": list(getattr(stack, "external_leaf_proofs", ())),
            "rejections": list(getattr(stack, "external_leaf_rejections", ())),
        },
    }


def _safety_summary(context: AnalysisContext) -> dict[str, object]:
    return dict(context.require_global("safety_analysis").summary)


def _emit_stack_warnings(warnings, function_names) -> None:
    """Print stack-analysis warnings to stderr.

    Kept for direct callers that want the legacy console form (tests, and
    ad-hoc debugging). ``chimera-pkg prepare`` no longer invokes this function:
    per-site diagnostics moved to ``chimera-pkg check-elf``, whose report carries
    the same information plus cause attribution and a compile decision block.
    The aggregate remedy line below still names the SVF-enabled variants for
    users who choose the metadata route instead of de-vectorization.
    """
    unresolved_active = 0
    external_active = 0
    for warning in warnings:
        if warning.code == "empty-call-target-set":
            print(
                f"chimera: error: [{warning.code}] {warning.message}",
                file=sys.stderr,
            )
        elif warning.code in ACTIONABLE_CALL_WARNINGS:
            if warning.code == ACTIVE_EXTERNAL_CALL:
                external_active += 1
            elif warning.code == UNRESOLVED_ACTIVE_CALL:
                unresolved_active += 1
            name = function_names.get(warning.function_start, "<unknown>")
            print(
                f"chimera: warning: [{warning.code}] {warning.message} "
                f"(function={name})",
                file=sys.stderr,
            )
            for detail in warning.details:
                print(
                    f"    stack-active because: {detail}",
                    file=sys.stderr,
                )
    if unresolved_active:
        print(
            f"chimera: warning: {unresolved_active} active indirect call(s) "
            "lack compiler function-pointer metadata "
            "(.chimera.function_pointer); caller stack state was not "
            "propagated and safepoint coverage is reduced. Rebuild with an "
            "SVF-enabled variant (svf/full) to generate compiler metadata "
            "for these sites.",
            file=sys.stderr,
        )
    if external_active:
        print(
            f"chimera: warning: {external_active} active external boundary(s) "
            "carry local or inherited stack state beyond this Program. Trace "
            "the source, gate implicit vectorization where applicable, and "
            "strictly recheck the rebuilt ELF; known external targets cannot "
            "be closed by function-pointer metadata alone.",
            file=sys.stderr,
        )


class SafetyStep:
    name = "safety"

    def __init__(
        self,
        *,
        min_vlen_bits: int,
        compiler_metadata: tuple[str, ...],
        unknown_stack_size_policy: str = CONSERVATIVE,
        external_scalar_leaf_contracts=(),
    ) -> None:
        self.min_vlen_bits = min_vlen_bits
        self.compiler_metadata = frozenset(compiler_metadata)
        self.external_scalar_leaf_contracts = normalize_leaf_contracts(external_scalar_leaf_contracts)
        self.unknown_stack_size_policy = normalize_unknown_stack_size_policy(
            unknown_stack_size_policy
        )

    @monitored(
        "offline.safety",
        variables=(
            local("main", label="main_module", path=("module_id",)),
            local("actual_metadata", label="compiler_metadata"),
            local("configs", label="vector_config_functions", transform=len),
            local(
                "vector",
                label="vector_liveness_functions",
                path=("by_function",),
                transform=len,
            ),
            local("stack", label="stack_warnings", path=("warnings",), transform=len),
            returned(label="summary", transform=_safety_summary),
        ),
    )
    def run(self, context: AnalysisContext) -> AnalysisContext:
        if not isinstance(context.platform, ElfModuleServices):
            raise TypeError(
                "safety requires ElfModuleServices for ELF analysis artifacts"
            )
        emitter = getattr(context.toolchain, "artifact_emitter", None)
        if emitter is None or not callable(getattr(emitter, "emit_u64_table", None)):
            raise TypeError(
                "safety requires toolchain ArtifactEmitter capability "
                "before invoking the compiler"
            )
        extension = context.architecture.extension
        if not isinstance(extension, VectorExtensionServices):
            raise TypeError(
                "safety step requires a VectorExtensionServices extension "
                f"(got {type(extension).__name__}); register an extension that "
                "implements vector_configs/vector_liveness/vtype_annotations."
            )
        main = next(
            module
            for module in context.require_global("modules")
            if module.is_main
        )
        program = context.require_global("programs")[main.module_id]
        leaf_bindings = bind_external_scalar_leaves(main.selected_path, program,
            context.require_global("modules"), self.external_scalar_leaf_contracts,
            objdump=context.config.tools.objdump) if self.external_scalar_leaf_contracts else ExternalLeafBindings()
        if self.external_scalar_leaf_contracts and leaf_bindings.rejections:
            raise ValueError("external scalar leaf contract could not be rebound during prepare: "
                             + str(leaf_bindings.rejections))
        metadata = ChimeraMetadata.from_elf(main.selected_path)
        actual_metadata = metadata.capabilities
        if not self.compiler_metadata <= actual_metadata:
            missing = sorted(self.compiler_metadata - actual_metadata)
            raise ValueError(
                "compiler_metadata does not match input ELF (missing: "
                + ", ".join(missing)
                + ")"
            )
        unexpected = sorted(actual_metadata - self.compiler_metadata)
        if unexpected:
            # 编译器嵌入的元数据超出 profile 声明：安全分析按 ELF 实际携带
            # 的能力运行（按函数核对覆盖后选择有效模式），是可接受
            # 情形——仅缺声明时才需要大声失败（那意味着分析会静默退化）。
            print(
                "safety step: note: ELF carries undeclared compiler metadata"
                " (accepted): " + ", ".join(unexpected)
            )

        configs = context.architecture.extension.vector_configs(program)
        config_functions = len(configs)
        vector = context.architecture.extension.vector_liveness(program)
        stack = StackLivenessAnalyzer(
            min_vlen_bits=self.min_vlen_bits,
            semantics=context.architecture.extension.stack_semantics,
            # Irreducible-loop degradation is reported by `chimera-pkg check-elf`;
            # keep prepare's console quiet (the structured warning still
            # lands in stack.warnings / the summary counts).
            emit_warnings=False,
            unknown_stack_size_policy=self.unknown_stack_size_policy,
        ).analyze_program(program, metadata=metadata, config_results=configs,
                          external_leaf_bindings=leaf_bindings)
        # configs' last consumer is the stack analysis; release before the
        # classifier allocates its own per-instruction records.
        # Diagnostics moved to `chimera-pkg check-elf`; prepare stays quiet so the
        # state machine (check-elf → llvm → prepare) owns all user-facing
        # reporting. The summary JSON below still carries machine-readable
        # counts for tooling and rebuild replay.
        del configs
        safety = classify_liveness(
            program,
            vector,
            stack,
            vector_classifier=extension.classify_vector_liveness,
        )
        # Downstream steps consume only safety.records (rebuild replay
        # reconstructs the result with the intermediates set to None), so
        # precompute the monitoring summary and let the per-instruction
        # configs/liveness be reclaimed when this step returns.
        result = SafetyPipelineResult(
            module_id=main.module_id,
            vector_configs=None,
            vector_liveness=None,
            stack_liveness=None,
            safety=safety,
            warnings=stack.warnings,
            summary=_compute_summary(
                module_id=main.module_id,
                config_functions=config_functions,
                vector=vector,
                stack=stack,
                safety=safety,
                warnings=stack.warnings,
            ),
        )
        generated = context.stage / "generated"
        artifacts = context.stage / "artifacts"
        generated.mkdir(parents=True, exist_ok=True)
        artifacts.mkdir(parents=True, exist_ok=True)
        original_base = context.platform.load_base(main.selected_path)
        assembly = generated / f"{main.module_id}.safety.S"
        document = generated / f"{main.module_id}.safety.json"
        trace_document = generated / f"{main.module_id}.inheritance.json"
        library = artifacts / f"libsafety_{main.module_id}.so"
        export_asm_table(
            safety,
            assembly,
            main.module_id,
            original_base=original_base,
            emitter=emitter,
        )
        export_json(
            program,
            safety,
            document,
            original_base=original_base,
            module_id=main.module_id,
        )
        export_inheritance_trace(
            stack.inheritance_trace,
            trace_document,
            original_base=original_base,
            module_id=main.module_id,
        )
        context.platform.runner.run(
            context.toolchain.compiler.compile([assembly], library)
        )
        session = context.require_global("workspace_session")
        if stack.closed_external_calls:
            contract_document = artifacts / f"{main.module_id}.external-leaves.json"
            payload = leaf_bindings.payload()
            payload["elf_sha256"] = sha256_file(main.selected_path)
            payload["closed_calls"] = {str(site): list(targets)
                for site, targets in stack.closed_external_calls.items()}
            contract_document.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            session.registry.register_artifact(ArtifactRecord(
                artifact_id=f"external-leaves-{main.module_id}", owner_kind="module",
                owner_id=main.module_id, capability=CONTRACT_CAPABILITY,
                representation="json", abi=1, required_by=frozenset({"launch"}),
                path=contract_document.relative_to(context.stage).as_posix(),
                sha256=sha256_file(contract_document)))
        session.registry.register_artifact(ArtifactRecord(
            artifact_id=f"safety-{main.module_id}-elf",
            owner_kind="module",
            owner_id=main.module_id,
            capability="safety",
            representation="elf",
            abi=SAFETY_ABI_VERSION,
            required_by=frozenset({"runtime"}),
            path=library.relative_to(context.stage).as_posix(),
            sha256=sha256_file(library),
        ))
        # The safety JSON stays a prepare-internal product (consumed by
        # patch-safepoints and rebuild replay); it is not published as a
        # manifest artifact.
        return context.put_global("safety_analysis", result)
