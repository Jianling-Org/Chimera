"""Build architecture-neutral program models from disassembly input."""

from __future__ import annotations

from ..core.contracts import AnalysisContext
from ..core.monitor import local, monitored, returned
from .parser import parse_dump


def _program_summary(programs) -> dict[str, object]:
    return {
        module_id: {
            "functions": len(program.functions),
            "instructions": len(program.instructions),
        }
        for module_id, program in programs.items()
    }


def _result_keys(context: AnalysisContext) -> list[str]:
    return sorted(context.global_results)


class BuildProgramModelStep:
    name = "build-program-model"

    @monitored(
        "offline.build-program-model",
        variables=(
            local("programs", transform=_program_summary),
            returned(label="results", transform=_result_keys),
        ),
    )
    def run(self, context: AnalysisContext) -> AnalysisContext:
        programs = {
            module_id: context.architecture.build_cfg(
                parse_dump(
                    path,
                    context.toolchain.disassembler.parse_format,
                    is_external_trampoline=getattr(
                        context.toolchain.disassembler,
                        "is_external_trampoline",
                        None,
                    ),
                    # dump_lines only fed the parser; nothing reads it once
                    # the CFG exists, so never materialise the second copy.
                    retain_dump_lines=False,
                )
            )
            for module_id, path in context.require_global("native_dumps").items()
        }
        return context.put_global("programs", programs)
