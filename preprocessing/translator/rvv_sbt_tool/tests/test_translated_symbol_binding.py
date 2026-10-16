"""ELF binding and offset-map contracts for translated function definitions."""

import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.translation import emitter
import rvv_sbt
import rvv_sbt_rvv
import rvv_sbt_rvv1024


TRANSLATORS = (rvv_sbt, rvv_sbt_rvv, rvv_sbt_rvv1024)
FUNCTIONS = {"caller_translated", "callee_translated", "tailer_translated"}
SOURCE = """
0000000000001000 <caller>:
    1000: 000000ef             jal ra, 2000 <callee>
    1004: 00008067             ret
0000000000002000 <callee>:
    2000: 00b00513             li a0, 11
    2004: 00008067             ret
0000000000003000 <tailer>:
    3000: 0000006f             j 2000 <callee>
"""

CROSS_JUMP_SOURCE = """
0000000000001000 <caller>:
    1000: 0000006f             j 2004 <callee+0x4>
    1004: 00008067             ret
0000000000002000 <callee>:
    2000: 00b00513             li a0, 11
    2004: 0000006f             jal zero, 3000 <tailer>
0000000000003000 <tailer>:
    3000: 0000006f             jal x0, 1004 <caller+0x4>
"""


def _tool(name):
    executable = shutil.which(name)
    if executable is None:
        pytest.skip(f"requires {name}")
    return executable


def _translate(translator, namespace="module_a", source=SOURCE):
    return translator.translate_program(
        AsmParser().parse_string_program(source), lib_name=namespace,
    )


def _run(*arguments):
    return subprocess.run(
        arguments, check=True, capture_output=True, text=True, timeout=30,
    ).stdout


def _assemble(tmp_path, output, *, keep_locals=False):
    source = tmp_path / "translated.S"
    source.write_text(output)
    obj = tmp_path / "translated.o"
    _run(
        _tool("riscv64-elf-gcc"), "-march=rv64gcv", "-mabi=lp64d", "-fPIC",
        *(("-Wa,-L",) if keep_locals else ()),
        "-c", str(source), "-o", str(obj),
    )
    return source, obj


def _symbols(obj):
    listing = _run(_tool("riscv64-elf-readelf"), "-Ws", str(obj))
    symbols = {}
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[0].rstrip(":").isdigit():
            symbols[fields[7]] = (int(fields[1], 16), *fields[3:7])
    return symbols


@pytest.mark.parametrize("translator", TRANSLATORS, ids=lambda item: item.__name__)
@pytest.mark.parametrize("namespace", ("module_a", "module_b"))
def test_generated_function_definitions_bind_inside_their_elf(tmp_path, translator, namespace):
    output = _translate(translator, namespace)
    _, obj = _assemble(tmp_path, output)
    symbols = _symbols(obj)
    for name in FUNCTIONS:
        assert symbols[name][1:4] == ("FUNC", "GLOBAL", "PROTECTED")
    assert re.search(r"\bcall\s+callee_translated\b", output)
    assert not re.search(r"\btail\s+callee_translated\b", output)
    assert re.search(r"\bj\s+branch_j_target_2000\b", output)
    assert symbols["query_original_translated_map"][3:] == ("DEFAULT", "UND")


@pytest.mark.parametrize("translator", TRANSLATORS, ids=lambda item: item.__name__)
@pytest.mark.parametrize("protected", (True, False), ids=("protected", "preemptible-control"))
@pytest.mark.parametrize("split_sections", (False, True), ids=("one-section", "split-sections"))
def test_rv64_shared_elf_binds_internal_calls_without_binding_runtime(
    tmp_path, monkeypatch, translator, protected, split_sections,
):
    if split_sections:
        monkeypatch.setattr(emitter, "_PROGRAM_SECTION_INSTRUCTIONS", 1)
    linker = _tool("ld.lld")
    output = _translate(translator)
    if not protected:
        output = re.sub(r"(?m)^\s*\.protected\s+\S+\n", "", output)
    _, obj = _assemble(tmp_path, output)
    library = tmp_path / "translated.so"
    _run(linker, "-shared", str(obj), "-o", str(library))
    symbols = _symbols(library)
    visibility = "PROTECTED" if protected else "DEFAULT"
    for name in FUNCTIONS:
        assert symbols[name][1:4] == ("FUNC", "GLOBAL", visibility)
    assert symbols["query_original_translated_map"][3:] == ("DEFAULT", "UND")
    relocations = _run(_tool("riscv64-elf-readelf"), "-Wr", str(library))
    jump_slots = set(re.findall(r"R_RISCV_JUMP_SLOT\s+[0-9a-f]+\s+(\S+)", relocations))
    assert "query_original_translated_map" in jump_slots
    assert ("callee_translated" in jump_slots) is not protected
    if protected:
        assert not any(name in relocations for name in FUNCTIONS)


@pytest.mark.parametrize("stream", (False, True), ids=("in-memory", "streamed-file"))
@pytest.mark.parametrize("split_sections", (False, True), ids=("one-section", "split-sections"))
@pytest.mark.parametrize("source_text", (SOURCE, CROSS_JUMP_SOURCE), ids=("backward-entry", "forward-and-interior"))
def test_jal_range_fixup_preserves_function_binding(tmp_path, monkeypatch, stream, split_sections, source_text):
    if split_sections:
        monkeypatch.setattr(emitter, "_PROGRAM_SECTION_INSTRUCTIONS", 1)
    output_path = tmp_path / "fixed.S"
    options = dict(
        lib_name="module_a",
        compiler=_tool("riscv64-elf-gcc"),
        readelf=_tool("riscv64-elf-readelf"),
        compiler_args=("-march=rv64gcv", "-mabi=lp64d", "-fPIC"),
        output_path=output_path,
    )
    if stream:
        source = tmp_path / "source.dump"
        source.write_text(source_text)
        result, sites = rvv_sbt_rvv.translate_file_with_jal_range_fixup(source, **options)
    else:
        result, sites = rvv_sbt_rvv.translate_program_with_jal_range_fixup(
            AsmParser().parse_string_program(source_text), **options,
        )
    assert result is None
    assert not sites
    output = output_path.read_text()
    assert output == _translate(rvv_sbt_rvv, source=source_text)
    assert ("@progbits,unique," in output) is split_sections
    _, obj = _assemble(tmp_path, output)
    symbols = _symbols(obj)
    for name in FUNCTIONS:
        assert symbols[name][1:4] == ("FUNC", "GLOBAL", "PROTECTED")


@pytest.mark.parametrize("translator", (rvv_sbt_rvv, rvv_sbt_rvv1024), ids=lambda item: item.__name__)
@pytest.mark.parametrize("entry_label", ("function", "branch"))
@pytest.mark.parametrize("split_sections", (False, True), ids=("one-section", "split-sections"))
@pytest.mark.parametrize("source_text", (SOURCE, CROSS_JUMP_SOURCE), ids=("backward-entry", "forward-and-interior"))
def test_offset_map_keeps_entries_and_excludes_internal_control_flow(
    tmp_path, monkeypatch, translator, entry_label, split_sections, source_text,
):
    if split_sections:
        monkeypatch.setattr(emitter, "_PROGRAM_SECTION_INSTRUCTIONS", 1)
    parser_path = (
        Path(__file__).resolve().parents[3]
        / "offline/analysis/offsetmap/codegen.py"
    )
    if not parser_path.is_file():
        pytest.skip("requires the adjacent offline offset-map implementation")
    spec = importlib.util.spec_from_file_location("binding_offsetmap_codegen", parser_path)
    codegen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codegen)
    translator_format = SimpleNamespace(
        target_label_prefix="branch_j_target_",
        entry_label_suffix="_translated",
        label_pattern=r"^\s*([A-Za-z_.$][A-Za-z0-9_.$]*):\s*(?:#.*)?$",
    )
    disassembly_format = SimpleNamespace(dump_label_pattern=r"([0-9a-fA-F]+)\s+<([^>]+)>")
    output = _translate(translator, source=source_text)
    source, obj = _assemble(tmp_path, output, keep_locals=True)
    library = tmp_path / "translated.so"
    _run(_tool("ld.lld"), "-shared", str(obj), "-o", str(library))
    symbols = _symbols(library)
    disassembly = _run(_tool("riscv64-elf-objdump"), "-d", str(library))
    labels_at_address = {}
    for name, address in (("caller", 0x1000), ("callee", 0x2000), ("tailer", 0x3000)):
        function = f"{name}_translated"
        branch = f"branch_j_target_{address:x}"
        assert symbols[function][0] == symbols[branch][0]
        labels_at_address[symbols[branch][0]] = function if entry_label == "function" else branch
    for address in (0x1004, 0x2004):
        branch = f"branch_j_target_{address:x}"
        labels_at_address[symbols[branch][0]] = branch
    # Objdump can choose any of the aliases at the same instruction address.
    for address, label in labels_at_address.items():
        disassembly = re.sub(
            rf"(?m)^(0*{address:x}) <[^>]+>:",
            rf"\1 <{label}>:",
            disassembly,
        )
    dump = tmp_path / "translated.dump"
    dump.write_text(disassembly)
    labels = codegen.parse_asm_source(source, translator_format)
    assert labels == {"caller_translated": 0x1000, "callee_translated": 0x2000, "tailer_translated": 0x3000}
    mapping = codegen.parse_translated_dump(dump, labels, translator_format, disassembly_format)
    expected_addresses = (0x1000, 0x1004, 0x2000, 0x2004, 0x3000)
    assert mapping == {
        address: symbols[f"branch_j_target_{address:x}"][0]
        for address in expected_addresses
    }
    trap_addresses = {
        int(match.group(1), 16)
        for match in re.finditer(r"(?m)^\s*([0-9a-f]+):\s+[0-9a-f]+\s+ebreak\b", disassembly)
    }
    assert len(trap_addresses) == (2 if source_text == SOURCE else 1)
    assert trap_addresses.isdisjoint(mapping.values())
    veneer_labels = set(re.findall(r"auipc\s+t0, %pcrel_hi\(([^)]+)\)", output))
    assert len(veneer_labels) == (1 if source_text == SOURCE else 3)
    instruction_addresses = sorted({
        int(match.group(1), 16)
        for match in re.finditer(r"(?m)^\s*([0-9a-f]+):\s+[0-9a-f]+\s+", disassembly)
    })
    for label in veneer_labels:
        start = instruction_addresses.index(symbols[label][0])
        veneer_addresses = instruction_addresses[start:start + 3]
        assert len(veneer_addresses) == 3
        assert set(veneer_addresses).isdisjoint(mapping.values())


@pytest.mark.skipif(sys.platform != "linux", reason="requires a Linux ELF dynamic loader")
@pytest.mark.parametrize("translators", (
    (rvv_sbt_rvv, rvv_sbt_rvv1024),
    (rvv_sbt_rvv, rvv_sbt_rvv),
    (rvv_sbt_rvv1024, rvv_sbt_rvv1024),
), ids=("bidirectional", "forward-modules", "reverse-modules"))
@pytest.mark.parametrize("load_order", ((0, 1), (1, 0)), ids=("A-first", "B-first"))
@pytest.mark.parametrize("protected", (True, False), ids=("protected", "preemptible-control"))
def test_rtld_global_cannot_redirect_internal_calls(tmp_path, translators, load_order, protected):
    compiler = _tool("cc")
    libraries = []
    for index, translator in enumerate(translators):
        output = _translate(translator, f"module_{index}")
        # Exercise the emitted ELF visibility using host code in each DSO.
        directives = [
            line.strip() for line in output.splitlines()
            if re.fullmatch(r"\s*\.(?:globl|protected)\s+(?:caller|callee|tailer)_translated", line)
            and (protected or ".protected" not in line)
        ]
        source = tmp_path / f"module_{index}.c"
        source.write_text(
            f"__asm__({json.dumps(chr(10).join(directives))});\n"
            f"int callee_translated(void) {{ return {index + 11}; }}\n"
            "int caller_translated(void) { return callee_translated(); }\n"
            "int tailer_translated(void) { return callee_translated(); }\n"
        )
        library = tmp_path / f"module_{index}.so"
        _run(compiler, "-shared", "-fPIC", "-O0", str(source), "-o", str(library))
        libraries.append(str(library))
    driver = """
import ctypes
import json
import os
import sys
paths, order = json.loads(sys.argv[1])
libraries = {}
for index in order:
    libraries[index] = ctypes.CDLL(paths[index], mode=os.RTLD_NOW | os.RTLD_GLOBAL)
results = []
for index in range(2):
    results.append([getattr(libraries[index], name)() for name in (
        "caller_translated", "tailer_translated",
    )])
print(json.dumps(results))
"""
    results = json.loads(_run(sys.executable, "-c", driver, json.dumps((libraries, load_order))))
    expected = [[11, 11], [12, 12]] if protected else [[11 + load_order[0]] * 2] * 2
    assert results == expected
