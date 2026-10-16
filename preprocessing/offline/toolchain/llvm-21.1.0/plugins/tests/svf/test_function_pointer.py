#!/usr/bin/env python3

from collections import Counter
import argparse
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile


sys.path.insert(
    0,
    str(pathlib.Path(__file__).resolve().parents[1] / "tools"),
)

from check_stackobj_map import parse_elf


FUNCTION_POINTER_SECTION = ".chimera.function_pointer"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(cmd, cwd=None, capture_output=False):
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=True,
        capture_output=capture_output,
        text=capture_output,
    )


def output(cmd, cwd=None):
    return subprocess.check_output(
        cmd,
        cwd=cwd,
        text=True,
    )


def compile_test(
    source: pathlib.Path,
    output_file: pathlib.Path,
    llvm_bin: pathlib.Path,
    plugin: pathlib.Path,
    extra_link_args=None,
    capture_link_output=False,
):
    if extra_link_args is None:
        extra_link_args = []

    obj = output_file.with_suffix(".o")

    run([
        llvm_bin / "clang",
        "-O2",
        "-flto",
        "-c",
        source,
        "-o",
        obj,
    ])

    return run([
        llvm_bin / "clang",
        "-O2",
        "-flto",
        f"--ld-path={llvm_bin / 'ld.lld'}",
        obj,
        f"-Wl,--load-pass-plugin={plugin}",
        *extra_link_args,
        "-o",
        output_file,
    ], capture_output=capture_link_output)


def parse_records(data: bytes):
    records = []
    offset = 0

    while offset < len(data):
        if offset + 12 > len(data):
            raise AssertionError(
                f"truncated record at offset {offset:#x}"
            )

        call_addr = struct.unpack_from("<Q", data, offset)[0]
        offset += 8

        target_count = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        targets = []

        for _ in range(target_count):
            if offset + 8 > len(data):
                raise AssertionError(
                    f"truncated target at offset {offset:#x}"
                )

            target = struct.unpack_from("<Q", data, offset)[0]
            offset += 8
            targets.append(target)

        records.append((call_addr, targets))

    return records


def load_records(binary: pathlib.Path):
    elf = parse_elf(binary)
    records = parse_records(
        elf.section_data(FUNCTION_POINTER_SECTION)
    )
    elf.assert_no_relocations(FUNCTION_POINTER_SECTION)
    return elf, records


def get_indirect_instruction_addresses(
    binary: pathlib.Path,
    llvm_bin: pathlib.Path,
    symbol: str,
):
    text = output([
        llvm_bin / "llvm-objdump",
        f"--disassemble-symbols={symbol}",
        "--no-show-raw-insn",
        binary,
    ])

    addresses = []
    instruction = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+([A-Za-z0-9_.]+)\b"
    )

    for line in text.splitlines():
        match = instruction.match(line)
        if not match:
            continue

        mnemonic = match.group(2)
        if mnemonic not in {"jalr", "jr"}:
            continue

        addresses.append(int(match.group(1), 16))

    return addresses


def get_symbol_addresses(
    binary: pathlib.Path,
    llvm_bin: pathlib.Path,
):
    result = {}

    text = output([
        llvm_bin / "llvm-nm",
        "-n",
        binary,
    ])

    for line in text.splitlines():
        fields = line.split()

        if len(fields) < 3:
            continue

        try:
            addr = int(fields[0], 16)
        except ValueError:
            continue

        name = fields[-1]
        result[name] = addr

    return result


def test_resolved(
    source_dir,
    work_dir,
    llvm_bin,
    plugin,
):
    binary = work_dir / "resolved"

    compile_test(
        source_dir / "pcsections.c",
        binary,
        llvm_bin,
        plugin,
    )

    _, records = load_records(binary)

    require(len(records) == 2, (
        f"expected 2 records, got {len(records)}"
    ))

    symbols = get_symbol_addresses(
        binary,
        llvm_bin,
    )

    foo = symbols["foo"]
    bar = symbols["bar"]
    baz = symbols["baz"]

    target_sets = Counter(
        frozenset(targets)
        for _, targets in records
    )

    expected = Counter([
        frozenset({foo, bar}),
        frozenset({bar, baz}),
    ])

    require(target_sets == expected, (
        f"unexpected targets:\n"
        f"  actual:   {target_sets}\n"
        f"  expected: {expected}"
    ))

    for call_addr, targets in records:
        require(call_addr != 0, "resolved call address is zero")
        require(
            len(targets) == 2,
            f"expected two resolved targets, got {targets}",
        )

    expected_call_addresses = Counter(
        get_indirect_instruction_addresses(
            binary,
            llvm_bin,
            "main",
        )
    )
    actual_call_addresses = Counter(
        call_addr for call_addr, _ in records
    )

    require(len(expected_call_addresses) == 2, (
        "expected two final indirect-call instructions in main, "
        f"got {expected_call_addresses}"
    ))
    require(actual_call_addresses == expected_call_addresses, (
        "function-pointer record addresses do not match the final "
        "indirect-call instruction VAs:\n"
        f"  actual:   {actual_call_addresses}\n"
        f"  expected: {expected_call_addresses}"
    ))


def test_external(
    source_dir,
    work_dir,
    llvm_bin,
    plugin,
):
    binary = work_dir / "external"

    compile_test(
        source_dir / "unresolved.c",
        binary,
        llvm_bin,
        plugin,
    )

    _, records = load_records(binary)

    data_size = sum(12 + 8 * len(targets) for _, targets in records)

    require(data_size == 12, (
        f"expected 12-byte unresolved record, "
        f"got {data_size} bytes"
    ))

    require(len(records) == 1, f"expected one record, got {records}")

    call_addr, targets = records[0]

    require(call_addr != 0, "external call address is zero")
    require(targets == [], f"external call unexpectedly resolved: {targets}")


def test_dlsym(
    source_dir,
    work_dir,
    llvm_bin,
    plugin,
):
    binary = work_dir / "dlsym"

    compile_test(
        source_dir / "dlsym.c",
        binary,
        llvm_bin,
        plugin,
        extra_link_args=["-ldl"],
    )

    _, records = load_records(binary)

    data_size = sum(12 + 8 * len(targets) for _, targets in records)

    require(data_size == 12, (
        f"expected 12-byte unresolved record, "
        f"got {data_size} bytes"
    ))

    require(len(records) == 1, f"expected one record, got {records}")

    call_addr, targets = records[0]

    require(call_addr != 0, "dlsym call address is zero")
    require(targets == [], f"dlsym call unexpectedly resolved: {targets}")


def test_direct_call_excluded(
    source_dir,
    work_dir,
    llvm_bin,
    plugin,
):
    binary = work_dir / "direct"

    compile_test(
        source_dir / "direct.c",
        binary,
        llvm_bin,
        plugin,
    )

    elf = parse_elf(binary)

    try:
        elf.section(FUNCTION_POINTER_SECTION)
    except ValueError as error:
        require("found 0" in str(error), str(error))
    else:
        raise AssertionError(
            "direct-only program unexpectedly contains "
            f"{FUNCTION_POINTER_SECTION}"
        )


def test_missing_extapi_failure(
    source_dir,
    work_dir,
    llvm_bin,
    plugin,
):
    plugin_dir = work_dir / "plugin-without-extapi"
    plugin_dir.mkdir()
    isolated_plugin = plugin_dir / plugin.name
    shutil.copy2(plugin, isolated_plugin)

    binary = work_dir / "missing-extapi"
    link = compile_test(
        source_dir / "pcsections.c",
        binary,
        llvm_bin,
        isolated_plugin,
        capture_link_output=True,
    )

    require(
        "extapi.bc unavailable" in link.stderr,
        link.stderr,
    )

    _, records = load_records(binary)

    require(len(records) == 2, (
        f"expected two failure records, got {len(records)}"
    ))
    require(
        all(not targets for _, targets in records),
        f"failure path unexpectedly resolved targets: {records}",
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--llvm-bin",
        type=pathlib.Path,
        required=True,
    )

    parser.add_argument(
        "--plugin",
        type=pathlib.Path,
        required=True,
    )

    args = parser.parse_args()

    source_dir = pathlib.Path(__file__).resolve().parent
    llvm_bin = args.llvm_bin.resolve()
    plugin = args.plugin.resolve()

    with tempfile.TemporaryDirectory(
        prefix="chimera-svf-test-"
    ) as tmp:
        work_dir = pathlib.Path(tmp)

        test_resolved(
            source_dir,
            work_dir,
            llvm_bin,
            plugin,
        )

        test_external(
            source_dir,
            work_dir,
            llvm_bin,
            plugin,
        )

        test_dlsym(
            source_dir,
            work_dir,
            llvm_bin,
            plugin,
        )

        test_direct_call_excluded(
            source_dir,
            work_dir,
            llvm_bin,
            plugin,
        )

        test_missing_extapi_failure(
            source_dir,
            work_dir,
            llvm_bin,
            plugin,
        )

    print("FunctionPointerPass tests passed")


if __name__ == "__main__":
    main()
