"""Exercise object-check boundaries and tool cancellation with real processes."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from riscv.codegen.jal_range_fixup import (
    JalRangeFixupError, _parse_relocations, _run, _run_lines, inspect_object,
)


@pytest.mark.parametrize("suffix", ["", " 0", " 0 target", " 0 target +",
                                    " 0 target + junk", " 0 target + -10"])
def test_malformed_direct_relocation_is_not_ignored(suffix):
    with pytest.raises(JalRangeFixupError, match="重定位"):
        _parse_relocations("0000 0000 R_RISCV_JAL" + suffix)


@pytest.mark.parametrize("sign,expected", [("+", 16), ("-", -16)])
def test_readelf_numeric_addend_is_hex(sign, expected):
    result = _parse_relocations(f"0000 0000 R_RISCV_JAL 0000 target {sign} 10")
    assert result == [(0, "R_RISCV_JAL", "target", expected)]


def test_real_object_addend_crosses_jal_limit(tmp_path):
    compiler = shutil.which("riscv64-elf-gcc")
    readelf = shutil.which("riscv64-elf-readelf")
    if not compiler or not readelf:
        pytest.skip("requires RISC-V object tools")
    source = tmp_path / "probe.S"
    obj = tmp_path / "probe.o"
    source.write_text(".option norvc\n.option norelax\n.text\n.globl target\n"
                      "chimera_j_site_1000:\njal zero,target+16\n"
                      ".space 1048560\ntarget:\nnop\n")
    subprocess.run([compiler, "-c", "-march=rv64gc", "-mabi=lp64d",
                    str(source), "-o", str(obj)], check=True, timeout=30,
                   capture_output=True)
    report = inspect_object(obj, readelf=readelf)
    assert report.out_of_range_sites == {0x1000}


def test_stream_timeout_covers_output_without_newline():
    command = [sys.executable, "-c", "import sys,time;sys.stdout.write('partial');sys.stdout.flush();time.sleep(60)"]
    with pytest.raises(JalRangeFixupError, match="超时"):
        list(_run_lines(command, timeout=0.3))


def test_buffered_tool_timeout_keeps_stderr():
    command = [sys.executable, "-c", "import sys,time;print('tool-stuck',file=sys.stderr,flush=True);time.sleep(60)"]
    with pytest.raises(JalRangeFixupError, match="tool-stuck"):
        _run(command, timeout=0.3)


def test_closing_stream_reaps_its_process():
    command = [sys.executable, "-c", "import os,time;print(os.getpid(),flush=True);time.sleep(60)"]
    lines = _run_lines(command, timeout=10)
    pid = int(next(lines))
    lines.close()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_stream_preserves_unterminated_last_line():
    assert list(_run_lines([sys.executable, "-c", "print('first');print('last',end='')"])) == ["first\n", "last"]
