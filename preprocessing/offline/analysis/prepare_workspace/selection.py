"""Choose the file each module is taken from, and fingerprint that choice.

One place owns the selection rule -- "prefer the scalar build, fall back to the
untouched original, never scalarise the main program" -- so that the step which
materializes modules and the caller which decides whether an existing Workspace
may be reused can never disagree about what was selected.

The same module also derives the prepare-input fingerprint.  Identity alone
cannot answer "may this Workspace be reused?": the input ELF can be untouched
while a dependency, the scalar base or the target routing changes, and then the
recorded artifacts describe inputs that no longer exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..core.data_model import (
    DELIVERY_PACKAGE,
    DELIVERY_TARGET,
    module_id,
)
from ..core.workspace import identity_digest, input_fingerprint


@dataclass(frozen=True)
class SelectedModule:
    """One module and the file it is taken from."""

    module_id: str
    #: Where the module was found on this machine (the original file).
    source: Path
    #: The file whose bytes the analysis consumes.  Equals ``source`` unless a
    #: scalar build of the same basename exists in the scalar base.
    selected_path: Path
    is_scalar: bool
    is_main: bool
    #: Where the selected file travels at run time; see ``data_model.module``.
    delivery: str


def select_modules(
    input_elf: Path,
    dependencies: Iterable[Path],
    scalar_root: Path,
) -> tuple[SelectedModule, ...]:
    """Resolve every module's selected file.

    ``dependencies`` is the already-resolved module list in the platform's
    order; ordering is preserved because the module records follow it.
    """

    input_elf = Path(input_elf)
    scalar_root = Path(scalar_root)
    selected: list[SelectedModule] = []
    for source in dependencies:
        source = Path(source)
        scalar = scalar_root / source.name
        use_scalar = source != input_elf and scalar.is_file()
        selected.append(
            SelectedModule(
                module_id=module_id(source.name),
                source=source,
                selected_path=scalar if use_scalar else source,
                is_scalar=use_scalar,
                is_main=source == input_elf,
                # D2: the scalar base travels with the package, everything
                # taken from the application's own installation does not.
                delivery=DELIVERY_PACKAGE if use_scalar else DELIVERY_TARGET,
            )
        )
    return tuple(selected)


def target_label(
    target_os: str,
    target_arch: str,
    target_arch_extension: str,
    runtime_scene: str,
    runtime_abi: int,
) -> str:
    """Return the target identity the produced artifacts are shaped by."""

    return (
        f"{target_os};{target_arch};{target_arch_extension};"
        f"{runtime_scene};runtime-abi={runtime_abi}"
    )


def prepare_input_items(
    input_elf: Path,
    modules: Iterable[SelectedModule],
    target: str,
) -> tuple[tuple[str, str], ...]:
    """Return ``(label, digest)`` for every input a prepare run consumes."""

    items: list[tuple[str, str]] = [
        ("input-elf", identity_digest(input_elf)),
        ("target", target),
    ]
    for module in modules:
        items.append(
            (
                f"module:{module.module_id}:{module.delivery}",
                identity_digest(module.selected_path),
            )
        )
    return tuple(items)


def prepare_input_fingerprint(
    input_elf: Path,
    modules: Iterable[SelectedModule],
    target: str,
) -> str:
    """Return the cache-validity fingerprint of a prepare run."""

    return input_fingerprint(prepare_input_items(input_elf, modules, target))


__all__ = [
    "SelectedModule",
    "prepare_input_fingerprint",
    "prepare_input_items",
    "select_modules",
    "target_label",
]
