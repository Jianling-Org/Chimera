"""Self-contained A/B regression fixture for the ``layout`` source chain.

Both dumps are built from the *field-captured* gate-2 ``xgcc`` disassembly
bundled in :mod:`xgcc_stack_fixture` (instruction addresses, encodings and
function boundaries verbatim; only DWARF comments and the build path were
stripped upstream).  Nothing here reads a desktop evidence archive, a build
directory or a K3 machine: the fixture runs anywhere the package is
importable.

* **A** -- the field disassembly plus one sink stub (see below).  ``layout``
  keeps its vector stack traffic, so it keeps its local sources.
* **B** -- the same dump with every ``v*`` instruction *inside* ``layout``
  replaced by ``c.nop``. This synthetic control isolates removal of vector
  accesses while preserving addresses, CFG and the sink call. It retains CSR
  reads and scalar hardware-width caches, so it is not a complete recompiled
  gate output and cannot establish that all local sources have disappeared.

The sink stub is *not* evidence.  It is a two-instruction body (one
unresolved indirect ``jalr`` plus a ``ret``) placed at the ``xrealloc`` target
address that the real ``layout`` calls.  It exists so that the real call site
has an internal target: the local sources then propagate into it through the
production caller-context propagation, its unresolved call reproduces the
exact finding shape a real unresolved callee produces, and the gate-list logic
can be exercised end to end -- the source host enters the candidate list,
while the stub, which only inherits, never replaces it.
"""

from __future__ import annotations

import re

from xgcc_stack_fixture import (
    FIXED_FRAME_FUNCTIONS,
    STACK_FUNCTIONS_DUMP,
)

#: The experiment target: the ``layout`` constructor of the gate-2 ``xgcc``.
LAYOUT = FIXED_FRAME_FUNCTIONS[2]

#: The real ``layout`` call target the sink body is placed at.
SINK_ADDRESS = 0xA1B36
SINK_NAME = "xrealloc"

#: Two-instruction body: an unresolved indirect call and a return.  Same shape
#: as the existing ``_fixture_concat_stub`` of :mod:`xgcc_stack_fixture`.
SINK_STUB_DUMP = r"""\
00000000000a1b36 <xrealloc>:
    a1b36:	9682                	jalr	a3
    a1b38:	8082                	ret
"""

_FUNCTION_HEADER = re.compile(r"^[0-9a-f]{16} <(?P<name>[^>]+)>:$")
_INSTRUCTION = re.compile(
    r"^\s*(?P<address>[0-9a-f]+):\s+(?P<encoding>\S+)(?P<tail>\s+.*)$"
)


def a_dump() -> str:
    """The field disassembly of ``layout`` with the sink stub attached."""

    return STACK_FUNCTIONS_DUMP + SINK_STUB_DUMP


def _devectorize(text: str, function_name: str) -> str:
    """Replace every ``v*`` instruction of one function with ``c.nop``.

    The replacement keeps the address, the instruction count and therefore the
    whole CFG: only the vector instruction is gone, which is what the gate
    does to the target function.  Returns the text unchanged when the function
    is not present, so a caller can rely on either outcome being explicit.
    """

    lines = text.splitlines()
    inside = False
    replaced = 0
    for index, line in enumerate(lines):
        header = _FUNCTION_HEADER.match(line)
        if header is not None:
            inside = header.group("name") == function_name
            continue
        if not inside:
            continue
        match = _INSTRUCTION.match(line)
        if match is None:
            continue
        tail = match.group("tail").lstrip()
        if not tail.startswith("v"):
            continue
        lines[index] = (
            f"   {match.group('address')}:\t0001                \tc.nop"
        )
        replaced += 1
    if replaced == 0:
        raise ValueError(f"no vector instruction found in {function_name}")
    return "\n".join(lines) + "\n"


def b_dump() -> str:
    """A with the target function's vector instructions removed."""

    return _devectorize(a_dump(), LAYOUT)


def sink_call_sites(dump: str, function_name: str = LAYOUT) -> tuple[int, ...]:
    """Addresses at which ``function_name`` calls the sink stub."""

    sites: list[int] = []
    inside = False
    for line in dump.splitlines():
        header = _FUNCTION_HEADER.match(line)
        if header is not None:
            inside = header.group("name") == function_name
            continue
        if not inside:
            continue
        match = _INSTRUCTION.match(line)
        if match is None:
            continue
        tail = match.group("tail").lstrip()
        if tail.startswith("jal") and f"<{SINK_NAME}>" in tail:
            sites.append(int(match.group("address"), 16))
    return tuple(sites)
