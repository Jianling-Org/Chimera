#!/usr/bin/env python3
"""
生成或刷新 tests/fixtures/objdump 下的 objdump fixture。
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
FIXTURE_ROOT = ROOT / "fixtures"
OBJDUMP_ROOT = FIXTURE_ROOT / "objdump"
OPENBLAS_ARCHIVE_SHA256 = (
    "e754a112eb02ec57ea697d679544128c3f12d6bb06f681a37418b7670a696f4c"
)


def openblas_cache_root() -> Path:
    """返回按静态库摘要隔离的用户缓存目录。"""

    configured_cache = os.environ.get("XDG_CACHE_HOME")
    cache_root = (
        Path(configured_cache).expanduser()
        if configured_cache
        else Path.home() / ".cache"
    )
    return cache_root / "chimera" / "openblas" / OPENBLAS_ARCHIVE_SHA256


# 解包出的 .o 只是重建 objdump fixture 的中间产物，不能再次污染翻译器
# 目录。最终可评审输入仍写入 tests/fixtures/objdump，临时对象则与来源静态
# 库使用同一 SHA 隔离缓存，错误版本不会被另一份资产静默复用。
OBJ_ROOT = openblas_cache_root() / "objects"


def default_openblas_archive() -> Path:
    """返回外部 OpenBLAS 静态库缓存路径，不再依赖仓库内构建树。"""

    explicit = os.environ.get("CHIMERA_OPENBLAS_ARCHIVE")
    if explicit:
        return Path(explicit).expanduser()
    return openblas_cache_root() / "libopenblas.a"


DEFAULT_OPENBLAS_ARCHIVE = default_openblas_archive()


@dataclass(frozen=True)
class FixtureCase:
    name: str
    obj_path: Path
    objdump_path: Path
    archive_path: Path | None = None
    archive_member: str | None = None


CASES = {
    "saxpy_k": FixtureCase(
        name="saxpy_k",
        obj_path=OBJ_ROOT / "saxpy_k.o",
        objdump_path=OBJDUMP_ROOT / "saxpy_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="saxpy_k.o",
    ),
    "daxpy_k": FixtureCase(
        name="daxpy_k",
        obj_path=OBJ_ROOT / "daxpy_k.o",
        objdump_path=OBJDUMP_ROOT / "daxpy_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="daxpy_k.o",
    ),
    "caxpy_k": FixtureCase(
        name="caxpy_k",
        obj_path=OBJ_ROOT / "caxpy_k.o",
        objdump_path=OBJDUMP_ROOT / "caxpy_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="caxpy_k.o",
    ),
    "zaxpy_k": FixtureCase(
        name="zaxpy_k",
        obj_path=OBJ_ROOT / "zaxpy_k.o",
        objdump_path=OBJDUMP_ROOT / "zaxpy_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="zaxpy_k.o",
    ),
    "scopy_k": FixtureCase(
        name="scopy_k",
        obj_path=OBJ_ROOT / "scopy_k.o",
        objdump_path=OBJDUMP_ROOT / "scopy_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="scopy_k.o",
    ),
    "dcopy_k": FixtureCase(
        name="dcopy_k",
        obj_path=OBJ_ROOT / "dcopy_k.o",
        objdump_path=OBJDUMP_ROOT / "dcopy_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="dcopy_k.o",
    ),
    "ccopy_k": FixtureCase(
        name="ccopy_k",
        obj_path=OBJ_ROOT / "ccopy_k.o",
        objdump_path=OBJDUMP_ROOT / "ccopy_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="ccopy_k.o",
    ),
    "sdot_k": FixtureCase(
        name="sdot_k",
        obj_path=OBJ_ROOT / "sdot_k.o",
        objdump_path=OBJDUMP_ROOT / "sdot_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="sdot_k.o",
    ),
    "ddot_k": FixtureCase(
        name="ddot_k",
        obj_path=OBJ_ROOT / "ddot_k.o",
        objdump_path=OBJDUMP_ROOT / "ddot_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="ddot_k.o",
    ),
    "sswap_k": FixtureCase(
        name="sswap_k",
        obj_path=OBJ_ROOT / "sswap_k.o",
        objdump_path=OBJDUMP_ROOT / "sswap_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="sswap_k.o",
    ),
    "dswap_k": FixtureCase(
        name="dswap_k",
        obj_path=OBJ_ROOT / "dswap_k.o",
        objdump_path=OBJDUMP_ROOT / "dswap_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="dswap_k.o",
    ),
    "sscal_k": FixtureCase(
        name="sscal_k",
        obj_path=OBJ_ROOT / "sscal_k.o",
        objdump_path=OBJDUMP_ROOT / "sscal_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="sscal_k.o",
    ),
    "dscal_k": FixtureCase(
        name="dscal_k",
        obj_path=OBJ_ROOT / "dscal_k.o",
        objdump_path=OBJDUMP_ROOT / "dscal_k.objdump.s",
        archive_path=DEFAULT_OPENBLAS_ARCHIVE,
        archive_member="dscal_k.o",
    ),
}


def resolve_objdump(explicit: str | None) -> str:
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.extend([
        "/opt/homebrew/opt/llvm/bin/llvm-objdump",
        shutil.which("llvm-objdump") or "",
        shutil.which("xcrun") or "",
    ])

    for candidate in candidates:
        candidate = shutil.which(candidate) if candidate else None
        if not candidate or not Path(candidate).is_file() or not os.access(candidate, os.X_OK):
            continue
        if candidate.endswith("/xcrun") or candidate == "xcrun":
            probe = subprocess.run(
                [candidate, "--find", "llvm-objdump"],
                check=False,
                capture_output=True,
                text=True,
            )
            if probe.returncode == 0:
                path = probe.stdout.strip()
                if Path(path).is_file() and os.access(path, os.X_OK):
                    return path
            continue
        return candidate

    raise SystemExit("No usable llvm-objdump found.")


def _run_to_file(command: list[str], output_path: Path, *, cwd: Path | None = None) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.{uuid.uuid4().hex}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        if output_path.exists():
            os.fchmod(descriptor, stat.S_IMODE(output_path.stat().st_mode))
        out = os.fdopen(descriptor, "wb")
        descriptor = None
        with out:
            subprocess.run(command, check=True, stdout=out, cwd=cwd)
        os.replace(temporary, output_path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def run_objdump(objdump_bin: str, input_path: Path, output_path: Path) -> None:
    try:
        invocation_path = input_path.resolve().relative_to(REPO_ROOT)
        cwd = REPO_ROOT
    except ValueError:
        invocation_path = input_path.resolve()
        cwd = None

    _run_to_file([objdump_bin, "-d", str(invocation_path)], output_path, cwd=cwd)


def resolve_ar(explicit: str | None) -> str:
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.extend([
        "/opt/homebrew/opt/llvm/bin/llvm-ar",
        shutil.which("llvm-ar") or "",
        shutil.which("ar") or "",
        "/usr/bin/ar",
    ])

    for candidate in candidates:
        candidate = shutil.which(candidate) if candidate else None
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate

    raise SystemExit("No usable ar found.")


def resolve_archive_member(ar_bin: str, archive_path: Path, member: str) -> str:
    listing = subprocess.run(
        [ar_bin, "t", str(archive_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    members = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
    if member in members:
        return member
    with_slash = f"{member}/"
    if with_slash in members:
        return with_slash
    for archive_member in members:
        if archive_member.rstrip("/") == member:
            return archive_member
    raise SystemExit(f"Archive member not found: {member} in {archive_path}")


def _validate_archive(archive_path: Path) -> None:
    if not archive_path.exists():
        raise SystemExit(f"Missing archive file: {archive_path}")
    digest = hashlib.sha256()
    with archive_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != OPENBLAS_ARCHIVE_SHA256:
        raise SystemExit(
            "OpenBLAS archive SHA-256 mismatch: "
            f"expected={OPENBLAS_ARCHIVE_SHA256} actual={digest.hexdigest()}"
        )


def extract_archive_member(
    ar_bin: str,
    archive_path: Path,
    member: str,
    output_path: Path,
    *,
    verified_archives: set[Path] | None = None,
) -> None:
    archive_path = archive_path.resolve()
    if verified_archives is None or archive_path not in verified_archives:
        _validate_archive(archive_path)
        if verified_archives is not None:
            verified_archives.add(archive_path)
    resolved_member = resolve_archive_member(ar_bin, archive_path, member)
    _run_to_file([ar_bin, "p", str(archive_path), resolved_member], output_path)


def ensure_object_file(
    case: FixtureCase,
    ar_bin: str | None,
    archive_override: Path | None = None,
    *,
    verified_archives: set[Path] | None = None,
) -> Path:
    if case.obj_path.exists() and case.obj_path.stat().st_size > 0:
        return case.obj_path
    if case.obj_path.exists() and case.obj_path.stat().st_size == 0:
        case.obj_path.unlink()
    archive_path = archive_override or case.archive_path
    if archive_path and case.archive_member:
        ar_bin = resolve_ar(ar_bin)
        extract_archive_member(
            ar_bin, archive_path, case.archive_member, case.obj_path,
            verified_archives=verified_archives,
        )
        return case.obj_path
    raise SystemExit(f"Missing object file: {case.obj_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate objdump fixtures from .o files."
    )
    parser.add_argument(
        "action",
        choices=["list", "extract", "extract-all", "generate", "generate-all"],
        help="Action to execute.",
    )
    parser.add_argument(
        "--case",
        dest="case_name",
        help="Named fixture case.",
    )
    parser.add_argument(
        "--input",
        dest="input_path",
        help="Input object file path for ad-hoc generation.",
    )
    parser.add_argument(
        "--output",
        dest="output_path",
        help="Output objdump text path for ad-hoc generation.",
    )
    parser.add_argument(
        "--objdump",
        dest="objdump_bin",
        default=None,
        help="Path to llvm-objdump.",
    )
    parser.add_argument(
        "--ar",
        dest="ar_bin",
        default=None,
        help="Path to ar/llvm-ar.",
    )
    parser.add_argument(
        "--openblas-archive",
        type=Path,
        default=None,
        help=(
            "Path to the verified RISC-V libopenblas.a. Defaults to "
            "CHIMERA_OPENBLAS_ARCHIVE or the SHA-isolated user cache."
        ),
    )
    return parser.parse_args()


def list_cases() -> int:
    print("Fixture cases:")
    for case in sorted(CASES):
        fixture = CASES[case]
        archive_info = ""
        if fixture.archive_path and fixture.archive_member:
            archive_info = f" (extract: {fixture.archive_member} from {fixture.archive_path})"
        print(f"  - {fixture.name}: {fixture.obj_path} -> {fixture.objdump_path}{archive_info}")
    return 0


def generate_named(
    case_name: str,
    objdump_bin: str,
    ar_bin: str | None,
    archive_override: Path | None = None,
    *,
    verified_archives: set[Path] | None = None,
) -> int:
    if case_name not in CASES:
        raise SystemExit(f"Unknown fixture case: {case_name}")
    fixture = CASES[case_name]
    input_path = ensure_object_file(
        fixture, ar_bin, archive_override, verified_archives=verified_archives,
    )
    run_objdump(objdump_bin, input_path, fixture.objdump_path)
    print(f"Generated: {fixture.objdump_path}")
    return 0


def extract_named(
    case_name: str,
    ar_bin: str | None,
    archive_override: Path | None = None,
    *,
    verified_archives: set[Path] | None = None,
) -> int:
    if case_name not in CASES:
        raise SystemExit(f"Unknown fixture case: {case_name}")
    fixture = CASES[case_name]
    ensure_object_file(
        fixture, ar_bin, archive_override, verified_archives=verified_archives,
    )
    print(f"Prepared: {fixture.obj_path}")
    return 0


def generate_ad_hoc(input_path: str, output_path: str, objdump_bin: str) -> int:
    input_file = Path(input_path)
    output_file = Path(output_path)
    if not input_file.exists():
        raise SystemExit(f"Missing object file: {input_file}")
    run_objdump(objdump_bin, input_file, output_file)
    print(f"Generated: {output_file}")
    return 0


def main() -> int:
    args = parse_args()
    archive_override = (
        args.openblas_archive.expanduser().resolve()
        if args.openblas_archive is not None
        else None
    )

    if args.action == "list":
        return list_cases()

    ar_bin = args.ar_bin
    verified_archives: set[Path] = set()

    if args.action == "extract-all":
        for case_name in sorted(CASES):
            extract_named(case_name, ar_bin, archive_override, verified_archives=verified_archives)
        return 0

    if args.action == "extract":
        if not args.case_name:
            raise SystemExit("Use --case with extract.")
        return extract_named(args.case_name, ar_bin, archive_override)

    objdump_bin = resolve_objdump(args.objdump_bin)

    if args.action == "generate-all":
        for case_name in sorted(CASES):
            generate_named(
                case_name, objdump_bin, ar_bin, archive_override,
                verified_archives=verified_archives,
            )
        return 0

    if args.action == "generate":
        if args.case_name:
            return generate_named(
                args.case_name, objdump_bin, ar_bin, archive_override
            )
        if args.input_path and args.output_path:
            return generate_ad_hoc(args.input_path, args.output_path, objdump_bin)
        raise SystemExit("Use --case, or provide both --input and --output.")

    raise SystemExit(f"Unhandled action: {args.action}")


if __name__ == "__main__":
    raise SystemExit(main())
