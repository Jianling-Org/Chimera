"""Parse disassembly text into the architecture-neutral program model."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Callable

from ..core.data_model.program import Function, Instruction, Program
from ..core.monitor import current_session
from ..core.monitor.render import render_line

_PROGRESS_EVERY = 100_000
_STATUS_PATH = "/proc/self/status"
_STATUS_KEYS = ("VmRSS", "VmHWM", "VmSwap")


def _memory_fields() -> dict[str, int]:
    """Read VmRSS/VmHWM/VmSwap (kB) from /proc; empty dict when unavailable.

    Monitoring must never break the analysis: any read failure simply
    omits the memory fields from the progress line.
    """

    try:
        fields: dict[str, int] = {}
        with open(_STATUS_PATH, encoding="ascii") as status:
            for line in status:
                name, _, rest = line.partition(":")
                if name in _STATUS_KEYS:
                    fields[name.lower()] = int(rest.strip().split()[0])
                if len(fields) == len(_STATUS_KEYS):
                    break
        return fields
    except (OSError, ValueError, IndexError):
        return {}


def _emit_progress(instruction_count: int) -> None:
    session = current_session()
    if not session.enabled or session.stream is None:
        return
    try:
        values: dict[str, object] = {"instructions": instruction_count}
        values.update(_memory_fields())
        print(
            render_line("offline.parse-dump.progress", values),
            file=session.stream,
            flush=True,
        )
    except BaseException:
        return


def parse_dump(
    path: str | Path,
    parse_format,
    *,
    is_external_trampoline: Callable[[str], bool] | None = None,
    retain_dump_lines: bool = True,
) -> Program:
    """Parse an objdump-style disassembly file into a ``Program``.

    Lines are consumed one at a time so the full text never materialises
    as a second copy next to the instruction objects.  ``retain_dump_lines``
    keeps the historical behaviour of storing every line on
    ``Program.dump_lines``; production callers (check-elf, workflow model
    builds) pass ``False`` because nothing reads that list after parsing.
    Diagnostics are unchanged either way: each ``Instruction`` still
    carries its original text and ``line_index``.
    """

    trampoline_detector = is_external_trampoline or (lambda _name: False)
    instruction_pattern = re.compile(
        parse_format.instruction_pattern, re.IGNORECASE
    )
    function_pattern = re.compile(parse_format.function_pattern, re.IGNORECASE)
    fields = parse_format.field_map
    source_path = Path(path)
    functions: list[Function] = []
    instructions: list[Instruction] = []
    by_address: dict[int, Instruction] = {}
    dump_lines: list[str] = []
    current: Function | None = None
    index = -1
    with source_path.open(encoding="utf-8", errors="ignore") as source:
        for index, raw_line in enumerate(source):
            line = raw_line.rstrip("\n")
            if retain_dump_lines:
                dump_lines.append(line)
            function = function_pattern.match(line)
            if function:
                name = function.group(2)
                current = Function(
                    name=name,
                    start=int(function.group(1), 16),
                    is_external_trampoline=bool(trampoline_detector(name)),
                )
                functions.append(current)
                continue
            instruction = instruction_pattern.match(line)
            if instruction is None or current is None:
                continue
            operand = instruction.group(fields["operand"]).strip()
            parsed = Instruction(
                addr=int(instruction.group(fields["address"]), 16),
                size=len(instruction.group(fields["machine_code"])) // 2,
                # Intern the opcode: only a few dozen distinct mnemonics
                # exist, so this is a bounded reuse table — never a cache
                # over addresses, operands, or full lines.
                op=sys.intern(instruction.group(fields["opcode"]).lower()),
                # Tuple, not list: operand lists are read-only after
                # parsing, and tuples avoid the list header + growth
                # slack (~50 B/instruction saved on cc1-scale inputs).
                args=tuple(
                    part.strip() for part in operand.split(",") if part.strip()
                ),
                text=line,
                machine_code=instruction.group(fields["machine_code"]),
                operand=operand,
                line_index=index,
            )
            current.insts.append(parsed)
            instructions.append(parsed)
            by_address[parsed.addr] = parsed
            if len(instructions) % _PROGRESS_EVERY == 0:
                _emit_progress(len(instructions))
    return Program(dump_lines=dump_lines, functions=functions, instructions=instructions,
                   instruction_by_address=by_address, source_path=source_path)
