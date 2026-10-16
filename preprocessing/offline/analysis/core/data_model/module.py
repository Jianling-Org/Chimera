"""Module records and deterministic identifiers shared by workflow steps.

A module has exactly **one** file.  There is no staging copy of a module and no
"analysis input versus delivered payload" split: ``selected_path`` is the file
every step reads *and* the file that travels inside the package when the module
is package-delivered.  Two files could drift apart; one cannot.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#: The module's file travels inside the Workspace and is resolved there at run
#: time.  Only modules whose selected file came from ``scalar_root`` take this
#: route, because a target machine is not required to have a scalar base.
DELIVERY_PACKAGE = "package"

#: The module's file is resolved on the target machine at run time, from the
#: application's own installation.  The main program always takes this route:
#: it must run from its real location so that path derivation keeps working.
DELIVERY_TARGET = "target"

DELIVERIES = frozenset({DELIVERY_PACKAGE, DELIVERY_TARGET})


@dataclass(frozen=True)
class AnalysisModule:
    module_id: str
    #: Where the module was found on this machine.  Provenance only: a
    #: build-machine path never becomes cross-machine identity.
    source: Path
    #: The file every analysis step consumes, and the payload that is packaged
    #: when ``delivery`` is :data:`DELIVERY_PACKAGE`.
    selected_path: Path
    is_scalar: bool
    is_main: bool
    #: :data:`DELIVERY_PACKAGE` or :data:`DELIVERY_TARGET`.  Recorded rather
    #: than recomputed from ``is_scalar`` so the delivery decision has exactly
    #: one home and cannot be re-derived differently somewhere else.
    delivery: str

    def __post_init__(self) -> None:
        if self.delivery not in DELIVERIES:
            raise ValueError(f"invalid delivery: {self.delivery!r}")

    @property
    def is_packaged(self) -> bool:
        return self.delivery == DELIVERY_PACKAGE


def module_id(filename: str) -> str:
    identifier = "".join(character if character.isalnum() or character == "_" else "_" for character in filename).strip("_")
    if not identifier:
        raise ValueError(f"cannot derive module ID from {filename!r}")
    return identifier if not identifier[0].isdigit() else f"module_{identifier}"


__all__ = [
    "DELIVERIES",
    "DELIVERY_PACKAGE",
    "DELIVERY_TARGET",
    "AnalysisModule",
    "module_id",
]
