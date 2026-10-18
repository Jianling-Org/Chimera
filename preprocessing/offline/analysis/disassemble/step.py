"""Create one architecture input dump per local module."""

from __future__ import annotations

from pathlib import Path

from ..core.contracts import AnalysisContext
from ..core.monitor import local, monitored, returned


def _dump_summary(dumps: dict[str, Path]) -> dict[str, object]:
    return {"count": len(dumps), "files": dumps}


def _result_keys(context: AnalysisContext) -> list[str]:
    return sorted(context.global_results)


class DisassembleStep:
    name = "disassemble"

    @monitored(
        "offline.disassemble",
        variables=(
            local("dump_dir"),
            local("dumps", transform=_dump_summary),
            returned(label="results", transform=_result_keys),
        ),
    )
    def run(self, context: AnalysisContext) -> AnalysisContext:
        if context.stage is None:
            raise RuntimeError("disassemble requires a staging workspace")
        if "capabilities" not in context.global_results:
            context = context.put_global("capabilities", context.platform.validate_capabilities(context.config))
        dump_dir = context.stage / "dump"
        dump_dir.mkdir(parents=True, exist_ok=True)
        dumps: dict[str, Path] = {}
        for module in context.require_global("modules"):
            destination = dump_dir / f"{module.module_id}.dump"
            context.platform.runner.run(
                context.toolchain.disassembler.command(module.selected_path),
                stdout_path=destination,
            )
            dumps[module.module_id] = destination
        return context.put_global("native_dumps", dumps)
