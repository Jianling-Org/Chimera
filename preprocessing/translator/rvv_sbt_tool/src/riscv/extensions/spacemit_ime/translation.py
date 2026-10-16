"""Native assembly adapter using the existing prepare/plan/session lifecycle.

Symbolic assembly retains its own labels and relocations: the assembler/linker
resolves moved code. This entry does not accept objdump or install a Runtime map.
"""

from dataclasses import dataclass
import re

from riscv.frontend.model import RVFunction, RVProgram
from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.translation.pipeline import TranslationPipeline
from .backend import NativeContext, PROFILE, REGISTRY


_LABEL = re.compile(r"^\s*([A-Za-z_.$][\w.$]*|[0-9]+):")
_ENCODING_DIRECTIVES = {
    ".insn", ".word", ".4byte", ".long", ".int", ".short", ".2byte", ".byte",
    ".quad", ".dword", ".8byte", ".hword", ".half", ".value", ".fill",
}
_EXPANSION_DIRECTIVES = {".macro", ".include", ".incbin", ".rept", ".irp", ".irpc"}
_BRANCHES = {"j", "jal", "beq", "bne", "blt", "bge", "bltu", "bgeu",
             "beqz", "bnez", "blez", "bgez", "bltz", "bgtz", "bgt", "ble", "bgtu", "bleu"}


@dataclass(frozen=True)
class SourceLine:
    original: str
    label_prefix: str
    address: int | None


def parse_source(source: str) -> tuple[RVProgram, tuple[SourceLine, ...]]:
    normalized = []
    lines = []
    address = 0
    for number, original in enumerate(source.splitlines(keepends=True), 1):
        code = original.split("#", 1)[0].strip()
        if ";" in code or "/*" in code or "*/" in code or "\\" in code:
            raise ValueError(f"line {number}: use one decoded instruction per line")
        if (AsmParser.OBJDUMP_LABEL_PATTERN.match(code)
                or re.match(r"^[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8})\s", code)):
            raise ValueError("IME native entry accepts symbolic assembly, not objdump")
        prefix = ""
        while match := _LABEL.match(code):
            label = match.group(1)
            prefix += f"{label}:\n"
            normalized.append(f"{label}:")
            code = code[match.end():].strip()
        if code.startswith(("Disassembly of section", "file format")):
            raise ValueError("IME native entry accepts symbolic assembly, not objdump")
        if code.startswith("."):
            directive = code.split()[0]
            if (directive in _ENCODING_DIRECTIVES | _EXPANSION_DIRECTIVES
                    or directive.startswith(".if") or directive in {".else", ".endif"}):
                raise ValueError(f"line {number}: {directive} requires decoded, pre-expanded input")
        is_instruction = bool(code and not code.startswith("."))
        if is_instruction:
            match = AsmParser.INSN_PATTERN.fullmatch(code)
            if not match:
                raise ValueError(f"line {number}: unsupported assembly syntax")
            opcode, operands = match.group(1), match.group(2) or ""
            if opcode in _BRANCHES and re.fullmatch(r"[-+]?(?:0x[0-9a-fA-F]+|[0-9]+)", operands.split(",")[-1].strip()):
                raise ValueError(f"line {number}: branch targets must use symbolic/local labels")
            if opcode == "auipc" and "%pcrel_hi(" not in operands and "%got_pcrel_hi(" not in operands:
                raise ValueError(f"line {number}: auipc requires a symbolic relocation")
            # Legacy names are deliberately not passed through as native RVV.
            if opcode.startswith(("vmadot", "vfwmadot", "vpack", "vupack", "vnpack", "vnspack")):
                raise ValueError(f"line {number}: use canonical smt.* spelling with an explicit data type")
            normalized.append(code)
        lines.append(SourceLine(original, prefix, address if is_instruction else None))
        if is_instruction:
            address += 4
    parser = AsmParser()
    instructions = parser.parse_lines(normalized)
    program = RVProgram(
        functions=[RVFunction("ime_native_source", 0, instructions)],
        symbols=dict(parser.labels), global_labels=dict(parser.labels),
    )
    return program, tuple(lines)


def preflight(program, _analysis):
    plans = []
    for instruction in program.instructions:
        if instruction.opcode.startswith("smt."):
            context = NativeContext(instruction, lambda _name: "")
            plans.append(REGISTRY.plan(context))
    return tuple(plans)


class NativeAssemblyEmitter:
    def __init__(self, source: str, lines: tuple[SourceLine, ...]):
        self.lines = lines
        self.prefix = ".L_chimera_ime_"
        while self.prefix in source:
            self.prefix += "_"

    def emit_function(self, *, context, function, state_factory, allocator_factory,
                      dispatcher_factory, text_only, func_name, raw, tls_state):
        def new_label(name):
            index = context.session.next_label_index("ime-native")
            return f"{self.prefix}{index}_{name}"

        plans = {plan.instruction.address: plan for plan in context.prepared.preflight_plans}
        output = []
        for line in self.lines:
            plan = plans.get(line.address)
            if plan is None:
                original = line.original
                if original.lstrip().startswith(".attribute"):
                    original = re.sub(r"_xsmtvdot(?:ii)?(?:[0-9]+p[0-9]+)?", "", original)
                output.append(original)
                continue
            result = REGISTRY.lower(NativeContext(plan.instruction, new_label), plan)
            output.append(line.label_prefix + "\n".join(result.assembly_lines) + "\n")
        return "".join(output)


def translate_assembly(source: str) -> str:
    program, lines = parse_source(source)
    emitter = NativeAssemblyEmitter(source, lines)
    pipeline = TranslationPipeline(emitter, preflight_planner=preflight)
    prepared = pipeline.prepare(program, backend_profile=PROFILE)
    return pipeline.emit_function(
        prepared, state_factory=lambda: None, allocator_factory=lambda: None,
        dispatcher_factory=lambda: None, tls_state=False,
    )
