"""Content-pinned, closed scalar leaves; no name-based library exemption."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

from ..arch.riscv.control_flow import CONDITIONAL_BRANCHES, direct_target
from ..core.data_model import Function
from ..program_model.parser import parse_dump
from ..toolchain.objdump import LinuxObjdump


CONTRACT_CAPABILITY = "external-scalar-leaf-contracts"
CONTRACT_FORMAT = "chimera-external-scalar-leaf-v1"
CONTRACT_FORMAT_V2 = "chimera-external-call-contracts-v2"
MEMCPY_NO_CALLBACK_BASIS = "standard-libc-memcpy-no-application-callback-v1"
# A deliberately small language: no vector, CSR, system, indirect jump or call.
_SCALAR = frozenset("""
    nop li mv lui auipc add addi addw addiw sub subw neg negw
    and andi or ori xor xori not sll slli sllw slliw srl srli srlw srliw
    sra srai sraw sraiw slt slti sltu sltiu seqz snez sltz sgtz
    mul mulh mulhu mulhsu mulw div divu divw divuw rem remu remw remuw
    lb lbu lh lhu lw lwu ld sb sh sw sd sext.b sext.h sext.w zext.b zext.h zext.w
""".split())
_RETURN_ARGS = {("ra",), ("x1",)}
_PROTECTED_REGISTER = re.compile(r"\b(?:ra|sp|x1|x2|gp|tp|x3|x4|s[0-9]+|x(?:8|9|1[89]|2[0-7]))\b")


def normalize_leaf_contracts(values=()) -> tuple[dict[str, str], ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError("external_scalar_leaf_contracts must be a sequence of records")
    result, seen = [], set()
    for item in values:
        if not isinstance(item, dict) or set(item) != {"symbol", "library", "sha256"}:
            raise ValueError("each scalar leaf contract requires symbol, library and sha256")
        symbol, library, digest = (item[key] for key in ("symbol", "library", "sha256"))
        if not isinstance(symbol, str) or not re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$]*", symbol):
            raise ValueError("invalid scalar leaf symbol")
        if not isinstance(library, str) or not re.fullmatch(r"[A-Za-z0-9_+.-]+", library) or library in {".", ".."}:
            raise ValueError("scalar leaf library must be a basename")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("scalar leaf provider requires a lowercase sha256")
        if symbol == "memcpy":
            raise ValueError("memcpy is handled by the automatic standard-interface contract")
        if symbol in seen:
            raise ValueError("duplicate scalar leaf symbol")
        seen.add(symbol)
        result.append(dict(symbol=symbol, library=library, sha256=digest))
    return tuple(sorted(result, key=lambda item: item["symbol"]))


@dataclass(frozen=True)
class ExternalLeafBindings:
    proofs: tuple[dict, ...] = ()
    rejections: tuple[dict, ...] = ()
    no_callback_interfaces: tuple[dict, ...] = ()
    interface_rejections: tuple[dict, ...] = ()

    @property
    def closed_targets(self) -> frozenset[int]:
        return frozenset(item["target"] for item in
                         (*self.proofs, *self.no_callback_interfaces))

    def payload(self) -> dict:
        if self.no_callback_interfaces or self.interface_rejections:
            return {"format": CONTRACT_FORMAT_V2, "proofs": list(self.proofs),
                    "rejections": list(self.rejections),
                    "no_callback_interfaces": list(self.no_callback_interfaces),
                    "interface_rejections": list(self.interface_rejections)}
        return {"format": CONTRACT_FORMAT, "proofs": list(self.proofs),
                "rejections": list(self.rejections)}


def verify_scalar_leaf(function: Function, size: int, code: bytes) -> tuple[str, ...]:
    """Validate the whole symbol extent, including unreachable bytes."""
    problems, cursor, returns = [], function.start, 0
    addresses = {instruction.addr for instruction in function.insts}
    if not function.insts or size <= 0 or size > 4096 or len(code) != size:
        return ("invalid-leaf-extent",)
    for instruction in function.insts:
        op, args = instruction.op, tuple(instruction.args)
        token = instruction.machine_code
        word = (bytes.fromhex(token)[::-1] if re.fullmatch(r"[0-9a-fA-F]{4}|[0-9a-fA-F]{8}", token) else b"")
        offset = instruction.addr - function.start
        if (instruction.addr != cursor or instruction.size not in (2, 4)
                or len(word) != instruction.size or word != code[offset:offset + instruction.size]):
            problems.append("incomplete-or-mismatched-leaf-bytes")
        cursor = instruction.addr + instruction.size
        is_return = op == "ret" or (op == "jr" and args in _RETURN_ARGS)
        if is_return:
            returns += 1
            continue
        if op not in _SCALAR | CONDITIONAL_BRANCHES | {"j"}:
            problems.append("unsupported-leaf-instruction:" + op)
        if _PROTECTED_REGISTER.search(",".join(args)):
            problems.append("leaf-touches-preserved-state")
        if op in CONDITIONAL_BRANCHES | {"j"}:
            if direct_target(instruction) not in addresses:
                problems.append("leaf-branch-outside-instruction-boundaries")
        if cursor == function.start + size and op != "j":
            problems.append("leaf-falls-through-extent")
    if cursor != function.start + size:
        problems.append("incomplete-leaf-extent")
    if not returns:
        problems.append("no-normal-leaf-return")
    return tuple(sorted(set(problems)))


def disassemble_leaf(path: Path, symbol: str, start: int, size: int, objdump: str) -> Function:
    """Bounded subprocess output; parser is the production objdump parser."""
    with tempfile.TemporaryDirectory(prefix="chimera-leaf-") as root:
        dump, errors = Path(root) / "leaf.dump", Path(root) / "stderr.txt"
        with dump.open("wb") as output, errors.open("wb") as stderr:
            process = subprocess.run([objdump, "-d", f"--start-address={start}",
                f"--stop-address={start + size}", str(path)], stdout=output, stderr=stderr,
                timeout=30, check=False)
        if process.returncode or dump.stat().st_size > 131072:
            raise ValueError("scalar leaf disassembly failed or exceeded its output budget")
        parsed = parse_dump(dump, LinuxObjdump(objdump).parse_format, retain_dump_lines=False)
        instructions = [item for item in parsed.instructions if start <= item.addr < start + size]
        return Function(symbol, start, instructions)


def file_sha256(path: Path) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bind_external_scalar_leaves(elf_path, program, modules, contracts, *, objdump) -> ExternalLeafBindings:
    from .external_leaf_binding import bind_leaves
    return bind_leaves(Path(elf_path), program, tuple(modules), normalize_leaf_contracts(contracts), objdump)


def selected_check_modules(elf_path, configuration):
    """Use prepare's exact module selection, rather than a second search rule."""
    from ..platform.linux.dependencies import collect_dependencies
    from ..prepare_workspace.selection import select_modules
    base = configuration.base
    return select_modules(Path(elf_path).resolve(), collect_dependencies(Path(elf_path),
                          base.target_files.library_roots), base.scalar_root)
