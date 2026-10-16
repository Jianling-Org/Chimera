"""Install the llama.cpp scalar runtime set into the Chimera cache."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


SCALAR_FILES = (
    "ld-linux-riscv64-lp64d.so.1",
    "libc.so.6",
    "libgcc_s.so.1",
    "libgomp.so.1",
    "libm.so.6",
    "libstdc++.so.6",
)


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def install(source_dir: Path, destination: Path) -> None:
    source_dir = source_dir.expanduser().resolve()
    destination = destination.expanduser().resolve()
    if not source_dir.is_dir():
        raise ValueError(f"scalar source directory is missing: {source_dir}")
    missing = [name for name in SCALAR_FILES if not (source_dir / name).is_file()]
    if missing:
        raise ValueError("missing scalar source files: " + ", ".join(missing))

    manifest_path = destination / ".chimera-llamacpp.json"
    managed: dict[str, str] = {}
    if manifest_path.is_file():
        try:
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid scalar manifest: {manifest_path}: {error}") from error
        if not isinstance(document, dict) or document.get("schema_version") != 1:
            raise ValueError(f"unsupported scalar manifest: {manifest_path}")
        files = document.get("files")
        if files is not None and not isinstance(files, dict):
            raise ValueError(f"invalid scalar manifest files table: {manifest_path}")
        managed = files or {}

    destination.mkdir(parents=True, exist_ok=True)
    updates: list[tuple[str, Path, Path, str]] = []
    for name in SCALAR_FILES:
        source = source_dir / name
        target = destination / name
        source_hash = _digest(source)
        if target.is_symlink():
            raise ValueError(f"scalar target is a symlink; refusing to replace: {target}")
        if target.exists():
            target_hash = _digest(target)
            if target_hash != source_hash and managed.get(name) != target_hash:
                raise ValueError(
                    f"scalar conflict: {target} is not managed by this example; "
                    "move it aside or remove it explicitly"
                )
        updates.append((name, source, target, source_hash))

    for _name, source, target, _source_hash in updates:
        with tempfile.NamedTemporaryFile(
            dir=destination, prefix=f".{target.name}.", delete=False
        ) as stream:
            temporary = Path(stream.name)
        try:
            shutil.copy2(source, temporary)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    document = {
        "schema_version": 1,
        "example": "llama.cpp",
        "files": {name: source_hash for name, _source, _target, source_hash in updates},
    }
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=destination, prefix=".chimera-llamacpp.", delete=False
    ) as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = Path(stream.name)
    try:
        os.replace(temporary, manifest_path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        print(f"usage: {Path(sys.argv[0]).name} SOURCE_DIR DESTINATION", file=sys.stderr)
        return 2
    try:
        install(Path(arguments[0]), Path(arguments[1]))
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"llama.cpp scalar cache: {Path(arguments[1]).expanduser().resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
