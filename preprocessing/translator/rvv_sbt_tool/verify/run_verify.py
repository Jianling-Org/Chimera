#!/usr/bin/env python3
"""
Unified driver for semantic verification cases.

This script is designed for a split workflow:
- local macOS machine: generate translated assembly
- remote Linux machine: build and run verification binaries
"""

from __future__ import annotations

import argparse
import shutil
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent


@dataclass(frozen=True)
class VerifyCase:
    name: str
    fixture: Path
    case_dir: Path
    translated: str = "translated.s"
    elf: str = "verify.elf"

    @property
    def main_c(self) -> Path:
        return self.case_dir / "main.c"

    @property
    def translated_path(self) -> Path:
        return self.case_dir / self.translated

    @property
    def elf_path(self) -> Path:
        return self.case_dir / self.elf


CASES = {
    "vadd_rvv": VerifyCase(
        name="vadd_rvv",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "vadd_rvv.objdump.s",
        case_dir=ROOT / "vadd_rvv",
    ),
    "daxpy_k": VerifyCase(
        name="daxpy_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "daxpy_k.objdump.s",
        case_dir=ROOT / "daxpy_k",
    ),
    "saxpy_k": VerifyCase(
        name="saxpy_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "saxpy_k.objdump.s",
        case_dir=ROOT / "saxpy_k",
    ),
    "caxpy_k": VerifyCase(
        name="caxpy_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "caxpy_k.objdump.s",
        case_dir=ROOT / "caxpy_k",
    ),
    "zaxpy_k": VerifyCase(
        name="zaxpy_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "zaxpy_k.objdump.s",
        case_dir=ROOT / "zaxpy_k",
    ),
    "scopy_k": VerifyCase(
        name="scopy_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "scopy_k.objdump.s",
        case_dir=ROOT / "scopy_k",
    ),
    "dcopy_k": VerifyCase(
        name="dcopy_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "dcopy_k.objdump.s",
        case_dir=ROOT / "dcopy_k",
    ),
    "ccopy_k": VerifyCase(
        name="ccopy_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "ccopy_k.objdump.s",
        case_dir=ROOT / "ccopy_k",
    ),
    "dswap_k": VerifyCase(
        name="dswap_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "dswap_k.objdump.s",
        case_dir=ROOT / "dswap_k",
    ),
    "sswap_k": VerifyCase(
        name="sswap_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "sswap_k.objdump.s",
        case_dir=ROOT / "sswap_k",
    ),
    "dscal_k": VerifyCase(
        name="dscal_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "dscal_k.objdump.s",
        case_dir=ROOT / "dscal_k",
    ),
    "sscal_k": VerifyCase(
        name="sscal_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "sscal_k.objdump.s",
        case_dir=ROOT / "sscal_k",
    ),
    "ddot_k": VerifyCase(
        name="ddot_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "ddot_k.objdump.s",
        case_dir=ROOT / "ddot_k",
    ),
    "sdot_k": VerifyCase(
        name="sdot_k",
        fixture=REPO_ROOT / "tests" / "fixtures" / "objdump" / "sdot_k.objdump.s",
        case_dir=ROOT / "sdot_k",
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run or prepare semantic verification cases."
    )
    parser.add_argument(
        "action",
        choices=["list", "check-env", "translate", "build", "run", "full", "clean", "print-server-steps"],
        help="Action to execute.",
    )
    parser.add_argument(
        "--case",
        dest="case_name",
        default="all",
        help="Case name or 'all'.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable or "python3",
        help="Python interpreter used for translation.",
    )
    parser.add_argument(
        "--cc",
        default="riscv64-unknown-linux-gnu-gcc",
        help="Cross compiler used on the build machine.",
    )
    parser.add_argument(
        "--qemu",
        default="qemu-riscv64",
        help="QEMU binary used on the run machine.",
    )
    parser.add_argument(
        "--cflags",
        default="-O2 -static",
        help="Compiler flags passed to the cross compiler.",
    )
    return parser.parse_args()


def iter_cases(case_name: str) -> list[VerifyCase]:
    if case_name == "all":
        return [CASES[name] for name in sorted(CASES)]
    if case_name not in CASES:
        raise SystemExit(f"Unknown case: {case_name}")
    return [CASES[case_name]]


def tool_exists(tool: str) -> bool:
    return shutil.which(tool) is not None


def check_local_env(python_bin: str) -> int:
    missing = []
    if shutil.which(python_bin) is None and not Path(python_bin).exists():
        missing.append(python_bin)
    if missing:
        print("Missing local tools:")
        for item in missing:
            print(f"  - {item}")
        return 1
    print("Local translation tools are available.")
    return 0


def check_server_env(cc: str | None = None, qemu: str | None = None) -> int:
    missing = [tool for tool in (cc, qemu) if tool is not None and not tool_exists(tool)]
    if missing:
        print("Missing build/run tools:")
        for item in missing:
            print(f"  - {item}")
        print("Use a Linux machine with a complete RISC-V toolchain for build/run steps.")
        return 1
    print("Build/run tools are available.")
    return 0


def run_cmd(cmd: list[str], cwd: Path) -> None:
    try:
        subprocess.run(cmd, cwd=cwd, check=True)
    except OSError as exc:
        raise SystemExit(f"Cannot execute {cmd[0]!r} in {cwd}: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"Command failed with exit code {exc.returncode}: {' '.join(cmd)}"
        ) from None


def translate_case(case: VerifyCase, python_bin: str) -> None:
    case.case_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        python_bin,
        str(REPO_ROOT / "rvv_sbt.py"),
        str(case.fixture),
        "-o",
        case.translated,
    ]
    print(f"[translate] {case.name}")
    run_cmd(cmd, case.case_dir)


def build_case(case: VerifyCase, cc: str, cflags: str) -> None:
    try:
        flags = shlex.split(cflags)
    except ValueError as error:
        raise SystemExit(f"invalid --cflags: {error}") from error
    cmd = [cc, *flags, "-o", case.elf, "main.c", case.translated]
    print(f"[build] {case.name}")
    run_cmd(cmd, case.case_dir)


def run_case(case: VerifyCase, qemu: str) -> None:
    cmd = [qemu, f"./{case.elf}"]
    print(f"[run] {case.name}")
    run_cmd(cmd, case.case_dir)


def clean_case(case: VerifyCase) -> None:
    print(f"[clean] {case.name}")
    for path in (case.translated_path, case.elf_path):
        if path.exists():
            path.unlink()


def print_server_steps(case: VerifyCase, cc: str, qemu: str, cflags: str) -> None:
    print(f"[server-steps] {case.name}")
    print(f"  1. Ensure `{case.translated_path}` exists.")
    print(f"  2. Build:")
    print(f"     {cc} {cflags} -o {case.elf_path.name} main.c {case.translated_path.name}")
    print(f"  3. Run:")
    print(f"     {qemu} ./{case.elf_path.name}")


def list_cases() -> None:
    print("Verification cases:")
    for case in iter_cases("all"):
        print(f"  - {case.name}: fixture={case.fixture.name}")


def main() -> int:
    args = parse_args()
    cases = iter_cases(args.case_name)

    if args.action == "list":
        list_cases()
        return 0

    if args.action == "check-env":
        local_rc = check_local_env(args.python)
        build_ok, run_ok = tool_exists(args.cc), tool_exists(args.qemu)
        print(f"Capabilities: translate={local_rc == 0}, build={build_ok}, run={run_ok}")
        print("check-env succeeds only when all three capabilities are available; individual actions check their own tools.")
        return 0 if local_rc == 0 and build_ok and run_ok else 1

    if args.action == "translate":
        if check_local_env(args.python) != 0:
            return 1
        for case in cases:
            translate_case(case, args.python)
        return 0

    if args.action == "build":
        if check_server_env(cc=args.cc) != 0:
            return 1
        for case in cases:
            build_case(case, args.cc, args.cflags)
        return 0

    if args.action == "run":
        if check_server_env(qemu=args.qemu) != 0:
            return 1
        for case in cases:
            run_case(case, args.qemu)
        return 0

    if args.action == "full":
        if check_local_env(args.python) != 0:
            return 1
        if check_server_env(args.cc, args.qemu) != 0:
            return 1
        for case in cases:
            translate_case(case, args.python)
            build_case(case, args.cc, args.cflags)
            run_case(case, args.qemu)
        return 0

    if args.action == "clean":
        for case in cases:
            clean_case(case)
        return 0

    if args.action == "print-server-steps":
        for case in cases:
            print_server_steps(case, args.cc, args.qemu, args.cflags)
        return 0

    raise SystemExit(f"Unhandled action: {args.action}")


if __name__ == "__main__":
    raise SystemExit(main())
