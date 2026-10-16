"""Exercise fixture publication and backend quality gates on isolated inputs."""

import argparse
import hashlib
import os
import stat
import subprocess
from types import SimpleNamespace

import pytest

import generate_fixtures as fixtures
from tools import check_backend_quality as quality
from tools import generate_support_docs as support_docs


def _tool(path):
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return str(path)


@pytest.mark.parametrize("resolver,name", [(fixtures.resolve_objdump, "llvm-objdump"),
                                           (fixtures.resolve_ar, "llvm-ar")])
@pytest.mark.parametrize("invalid", ["directory", "non-executable"])
def test_tool_resolver_skips_unusable_candidate(tmp_path, monkeypatch, resolver, name, invalid):
    rejected = tmp_path / "rejected"
    if invalid == "directory":
        rejected.mkdir()
    else:
        rejected.write_text("not executable")
        rejected.chmod(0o644)
    valid = _tool(tmp_path / name)
    candidates = {str(rejected): str(rejected), name: valid, valid: valid}
    monkeypatch.setattr(fixtures.shutil, "which", candidates.get)
    assert resolver(str(rejected)) == valid


def test_xcrun_result_must_be_executable(tmp_path, monkeypatch):
    xcrun = _tool(tmp_path / "xcrun")
    result = tmp_path / "not-a-tool"
    result.mkdir()
    monkeypatch.setattr(fixtures.shutil, "which", lambda name: xcrun if name in {"xcrun", xcrun} else None)
    monkeypatch.setattr(fixtures.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=str(result)))
    with pytest.raises(SystemExit, match="No usable llvm-objdump"):
        fixtures.resolve_objdump(xcrun)


def test_objdump_failure_preserves_existing_fixture(tmp_path, monkeypatch):
    original = tmp_path / "source.o"
    original.write_bytes(b"object")
    output = tmp_path / "fixture.s"
    output.write_bytes(b"old fixture")
    output.chmod(0o640)

    def partial(command, **kwargs):
        kwargs["stdout"].write(b"partial fixture")
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(fixtures.subprocess, "run", partial)
    with pytest.raises(subprocess.CalledProcessError):
        fixtures.run_objdump("objdump", original, output)
    assert output.read_bytes() == b"old fixture"
    assert stat.S_IMODE(output.stat().st_mode) == 0o640
    assert not list(tmp_path.glob(".fixture.s.*"))


@pytest.mark.parametrize("existing", [False, True])
def test_archive_failure_never_publishes_partial_object(tmp_path, monkeypatch, existing):
    archive = tmp_path / "archive.a"
    archive.write_bytes(b"archive")
    monkeypatch.setattr(fixtures, "OPENBLAS_ARCHIVE_SHA256", hashlib.sha256(b"archive").hexdigest())
    monkeypatch.setattr(fixtures, "resolve_archive_member", lambda *args: "kernel.o")
    output = tmp_path / "kernel.o"
    if existing:
        output.write_bytes(b"old valid object")
    calls = []

    def extraction(command, **kwargs):
        calls.append(command)
        kwargs["stdout"].write(b"partial" if len(calls) == 1 else b"complete")
        if len(calls) == 1:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(fixtures.subprocess, "run", extraction)
    with pytest.raises(subprocess.CalledProcessError):
        fixtures.extract_archive_member("ar", archive, "kernel.o", output)
    if existing:
        assert output.read_bytes() == b"old valid object"
    else:
        assert not output.exists()
    assert not list(tmp_path.glob(".kernel.o.*"))
    if existing:
        fixtures.extract_archive_member("ar", archive, "kernel.o", output)
    else:
        case = fixtures.FixtureCase("kernel", output, tmp_path / "kernel.s", archive, "kernel.o")
        monkeypatch.setattr(fixtures, "resolve_ar", lambda explicit: explicit)
        fixtures.ensure_object_file(case, "ar")
    assert output.read_bytes() == b"complete"
    assert len(calls) == 2


def _arguments(action, **overrides):
    return argparse.Namespace(**dict(
        action=action, case_name=None, input_path=None, output_path=None,
        objdump_bin=None, ar_bin=None, openblas_archive=None,
    ) | overrides)


def test_archive_hash_is_shared_only_within_one_batch(tmp_path, monkeypatch):
    archive = tmp_path / "archive.a"
    archive.write_bytes(b"trusted archive")
    monkeypatch.setattr(fixtures, "OPENBLAS_ARCHIVE_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest())
    cases = {name: fixtures.FixtureCase(name, tmp_path / f"{name}.o", tmp_path / f"{name}.s",
                                       archive, f"{name}.o") for name in ("a", "b")}
    monkeypatch.setattr(fixtures, "CASES", cases)
    monkeypatch.setattr(fixtures, "parse_args", lambda: _arguments("extract-all"))
    monkeypatch.setattr(fixtures, "resolve_ar", lambda _explicit: "ar")
    monkeypatch.setattr(fixtures, "resolve_archive_member", lambda _ar, _archive, member: member)
    validate = fixtures._validate_archive
    checked = []

    def counted(path):
        checked.append(path)
        validate(path)

    def extract(command, **kwargs):
        kwargs["stdout"].write(command[-1].encode())

    monkeypatch.setattr(fixtures, "_validate_archive", counted)
    monkeypatch.setattr(fixtures.subprocess, "run", extract)
    assert fixtures.main() == 0
    assert checked == [archive]
    for case in cases.values():
        assert case.obj_path.read_bytes() == case.archive_member.encode()
        case.obj_path.unlink()
    archive.write_bytes(b"wrong archive")
    with pytest.raises(SystemExit, match="SHA-256 mismatch"):
        fixtures.main()
    assert checked == [archive, archive]
    assert all(not case.obj_path.exists() for case in cases.values())


def test_ad_hoc_generation_does_not_require_ar(tmp_path, monkeypatch):
    original, output = tmp_path / "input.o", tmp_path / "output.s"
    original.write_bytes(b"object")
    monkeypatch.setattr(fixtures, "parse_args", lambda: _arguments(
        "generate", input_path=str(original), output_path=str(output),
    ))
    monkeypatch.setattr(fixtures, "resolve_objdump", lambda _explicit: "objdump")

    def forbidden(_explicit):
        raise AssertionError("ar is not needed for an existing input object")

    def objdump(_command, **kwargs):
        kwargs["stdout"].write(b"decoded instructions")

    monkeypatch.setattr(fixtures, "resolve_ar", forbidden)
    monkeypatch.setattr(fixtures.subprocess, "run", objdump)
    assert fixtures.main() == 0
    assert output.read_bytes() == b"decoded instructions"


def test_archive_generation_still_requires_ar(tmp_path, monkeypatch):
    archive = tmp_path / "archive.a"
    archive.write_bytes(b"archive")
    case = fixtures.FixtureCase("test", tmp_path / "missing.o", tmp_path / "out.s", archive, "missing.o")

    def missing(_explicit):
        raise SystemExit("No usable ar found.")

    monkeypatch.setattr(fixtures, "resolve_ar", missing)
    with pytest.raises(SystemExit, match="No usable ar"):
        fixtures.ensure_object_file(case, None)


@pytest.fixture
def quality_tree(tmp_path, monkeypatch):
    forward = tmp_path / "rvv256"
    reverse = tmp_path / "rvv1024_transition"
    handlers = reverse / "handlers"
    forward.mkdir()
    handlers.mkdir(parents=True)
    monkeypatch.setattr(quality, "ROOT", tmp_path)
    monkeypatch.setattr(quality, "BACKEND_ROOTS", (forward, reverse))
    monkeypatch.setattr(quality, "TRANSITION_HANDLERS", handlers)
    return forward, handlers


def test_quality_gate_rejects_missing_scan_root(quality_tree, monkeypatch, capsys):
    forward, _ = quality_tree
    missing = forward / "missing"
    monkeypatch.setattr(quality, "BACKEND_ROOTS", (missing,))
    assert quality.main() == 1
    assert f"{missing}: missing required backend directory" in capsys.readouterr().out


def test_quality_gate_reports_parse_and_other_errors(quality_tree, capsys):
    forward, _ = quality_tree
    (forward / "syntax.py").write_text("def broken(:\n")
    (forward / "encoding.py").write_bytes(b"\xff")
    (forward / "broad.py").write_text("try:\n    pass\nexcept Exception:\n    pass\n")
    assert quality.main() == 1
    output = capsys.readouterr().out
    assert "syntax.py:1: SyntaxError" in output
    assert "encoding.py: UnicodeDecodeError" in output
    assert "broad.py:3: broad except Exception" in output


@pytest.mark.parametrize("caught", ["Exception", "BaseException", "(ValueError, Exception)",
                                     "(BaseException, KeyError)"])
def test_quality_gate_catches_broad_exception_tuples(quality_tree, caught):
    forward, _ = quality_tree
    (forward / "module.py").write_text(f"try:\n    pass\nexcept {caught}:\n    pass\n")
    assert quality.main() == 1


@pytest.mark.parametrize("source", [
    "from typing import cast\nx = cast(int, value)\n",
    "from typing import cast as checked\nx = checked(int, value)\n",
    "import typing as ty\nx = ty . cast (int, value)\n",
    "import typing\nx = typing.cast(int, value)\n",
])
def test_quality_gate_recognizes_typing_cast_aliases(quality_tree, source):
    forward, _ = quality_tree
    (forward / "module.py").write_text(source)
    assert quality.main() == 1


@pytest.mark.parametrize("source", [
    "_LEGAL_LMULS = frozenset([8, .125, .25, 1, .5, 4, 2])\n",
    "TOKENS = { .125 : 'mf8' }\n",
    "TOKENS = { 'mf8' : .125 }\n",
    "_STATE_BASE_MARKER = 'CHIMERA_STATE_BASE'\n",
    "count = (256) // (sew)\n",
    "allocator . get_offset ('v8')\n",
    "layout . get_vreg_offset ('v8')\n",
])
def test_quality_gate_detects_known_patterns_independent_of_spacing(quality_tree, source):
    _, handlers = quality_tree
    (handlers / "module.py").write_text(source)
    assert quality.main() == 1


def test_quality_gate_allows_comments_names_and_equal_unrelated_constants(quality_tree):
    forward, _ = quality_tree
    (forward / "module.py").write_text('''"""cast(, 256 // sew and CHIMERA_STATE_BASE are documentation."""
# allocator.get_offset('v8') and cast(int, x) are examples.
weights = [.125, .25, .5, 1, 2, 4, 8]
number = 256
broadcast(value)
downcast(value)
try:
    pass
except (ValueError, TypeError):
    pass
''')
    assert quality.main() == 0


def test_support_doc_update_preserves_mode_and_new_file_uses_umask(tmp_path):
    existing = tmp_path / "existing.md"
    existing.write_text("old")
    existing.chmod(0o640)
    support_docs._write_atomic(existing, "new\n")
    assert existing.read_text() == "new\n"
    assert stat.S_IMODE(existing.stat().st_mode) == 0o640
    reference = tmp_path / "reference.md"
    reference.write_text("ordinary creation")
    created = tmp_path / "created.md"
    support_docs._write_atomic(created, "new file\n")
    assert stat.S_IMODE(created.stat().st_mode) == stat.S_IMODE(reference.stat().st_mode)


def test_support_doc_fdopen_failure_closes_descriptor(tmp_path, monkeypatch):
    path = tmp_path / "doc.md"
    path.write_text("old")
    descriptors = []

    def failed(descriptor, *args, **kwargs):
        descriptors.append(descriptor)
        raise OSError("fdopen failed")

    monkeypatch.setattr(support_docs.os, "fdopen", failed)
    with pytest.raises(OSError, match="fdopen failed"):
        support_docs._write_atomic(path, "new")
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert path.read_text() == "old"
    assert not list(tmp_path.glob(".doc.md.*"))


def test_support_doc_write_failure_keeps_old_file(tmp_path, monkeypatch):
    path = tmp_path / "doc.md"
    path.write_text("old")

    def failed(_descriptor):
        raise OSError("flush failed")

    monkeypatch.setattr(support_docs.os, "fsync", failed)
    with pytest.raises(OSError, match="flush failed"):
        support_docs._write_atomic(path, "new")
    assert path.read_text() == "old"
    assert not list(tmp_path.glob(".doc.md.*"))
