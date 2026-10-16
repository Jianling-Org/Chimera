from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from chimera.cli import build_parser, main


class BuildBundleCliTests(unittest.TestCase):
    def test_pkg_exposes_pack_and_unpack(self):
        parser = build_parser("pkg", prog="chimera-pkg")
        choices = parser._subparsers._group_actions[0].choices
        self.assertIn("build-bundle", choices)
        actions = choices["build-bundle"]._subparsers._group_actions[0].choices
        self.assertEqual(set(actions), {"pack", "unpack"})

    def test_runtime_does_not_expose_build_bundles(self):
        parser = build_parser("user", prog="chimera-user")
        self.assertNotIn("build-bundle", parser._subparsers._group_actions[0].choices)


class BuildBundleTests(unittest.TestCase):
    def setUp(self):
        from chimera import build_bundle
        self.bundle = build_bundle
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profile = self.root / "app profile.toml"
        self.script = self.root / "build elf.sh"
        self.instructions = self.root / "操作说明.md"
        self.profile.write_bytes(b'[profile]\nname = "example"\n')
        self.script.write_bytes(b'#!/bin/bash\nprintf "build only\\n"\n')
        self.instructions.write_text("先设置 LLAMA_SOURCE，再执行构建脚本。\n", encoding="utf-8")
        self.archive = self.root / "bundle with spaces.build-bundle"
        self.out = self.root / "unpacked with spaces"

    def pack(self, required_env=("LLAMA_SOURCE=llama.cpp 源码目录", "RUN=新的构建结果目录")):
        return self.bundle.pack_build_bundle(
            self.profile, self.script, self.instructions, self.archive,
            required_env=required_env,
        )

    def unpack(self):
        return self.bundle.unpack_build_bundle(self.archive, self.out)

    def mutate_archive(self, update):
        with zipfile.ZipFile(self.archive) as archive:
            entries = [(info, archive.read(info)) for info in archive.infolist()]
        entries = update(entries)
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for info, data in entries:
                archive.writestr(info, data)

    def change_manifest(self, update):
        def mutate(entries):
            result = []
            for info, data in entries:
                if info.filename == "build-bundle.json":
                    doc = json.loads(data)
                    update(doc)
                    data = json.dumps(doc, ensure_ascii=False).encode("utf-8")
                result.append((info, data))
            return result
        self.mutate_archive(mutate)

    def test_round_trip_preserves_all_three_files_and_names(self):
        self.assertEqual(self.pack(), self.archive.resolve())
        self.assertEqual(self.unpack(), self.out.resolve())
        for source in (self.profile, self.script, self.instructions):
            self.assertEqual((self.out / source.name).read_bytes(), source.read_bytes())
        doc = json.loads((self.out / "build-bundle.json").read_text(encoding="utf-8"))
        self.assertEqual({item["role"] for item in doc["files"]}, {"profile", "script", "instructions"})
        for item in doc["files"]:
            self.assertEqual(item["sha256"], hashlib.sha256((self.out / item["path"]).read_bytes()).hexdigest())
        self.assertEqual({path.name for path in self.out.iterdir()},
                         {self.profile.name, self.script.name, self.instructions.name, "build-bundle.json"})

    def test_unpacked_usage_prints_instructions_variables_and_file_paths(self):
        self.pack()
        self.unpack()
        text = self.bundle.render_build_bundle_usage(self.out, environment={"RUN": "private-value"})
        self.assertIn(self.instructions.read_text(encoding="utf-8").strip(), text)
        self.assertIn("LLAMA_SOURCE", text)
        self.assertIn("llama.cpp 源码目录", text)
        self.assertIn(str(self.out / self.profile.name), text)
        self.assertIn(str(self.out / self.script.name), text)
        self.assertNotIn("private-value", text)

    def test_pack_does_not_capture_environment_values(self):
        with patch.dict(os.environ, {"LLAMA_SOURCE": "secret-machine-path"}):
            self.pack()
        with zipfile.ZipFile(self.archive) as archive:
            self.assertNotIn(b"secret-machine-path", archive.read("build-bundle.json"))

    def test_unpack_never_executes_script(self):
        marker = self.root / "must-not-exist"
        self.script.write_text(f"#!/bin/bash\necho bad > '{marker.as_posix()}'\n", encoding="utf-8")
        self.pack()
        self.unpack()
        self.assertFalse(marker.exists())

    def test_source_profile_bytes_and_policy_are_not_rewritten(self):
        original = b'# keep comment\r\n[profile]\r\nname = "test"\r\n[[profile.workflow.steps]]\r\nstep = "safety"\r\nparameters = { unknown_stack_size_policy = "conservative" }\r\n'
        self.profile.write_bytes(original)
        self.pack()
        self.unpack()
        self.assertEqual(self.profile.read_bytes(), original)
        self.assertEqual((self.out / self.profile.name).read_bytes(), original)

    def test_relative_profile_references_are_reported_without_rewriting(self):
        self.profile.write_text('[config]\nscalar_root = "~/.chimera/scalar"\n'
                                '[[config.translators]]\ntranslator_path = "../translator/run.py"\n'
                                '[config.tools]\nobjdump = "objdump"\n'
                                '[profile]\nname = "test"\n', encoding="utf-8")
        self.pack()
        self.unpack()
        text = self.bundle.render_build_bundle_usage(self.out, environment={})
        self.assertIn("../translator/run.py", text)
        self.assertIn("config.translators[0].translator_path", text)
        self.assertNotIn("config.tools.objdump", text)

    def test_no_env_declarations_directs_reader_to_usage(self):
        self.pack(required_env=())
        self.unpack()
        text = self.bundle.render_build_bundle_usage(self.out, environment={})
        self.assertIn("未单独声明", text)

    def test_existing_archive_is_not_overwritten(self):
        self.archive.write_bytes(b"existing")
        with self.assertRaises((ValueError, OSError)):
            self.pack()
        self.assertEqual(self.archive.read_bytes(), b"existing")

    def test_existing_output_directory_is_not_modified(self):
        self.pack()
        self.out.mkdir()
        (self.out / "keep").write_bytes(b"old")
        with self.assertRaises((ValueError, OSError)):
            self.unpack()
        self.assertEqual(list(self.out.iterdir()), [self.out / "keep"])

    def test_invalid_env_names_and_duplicates_are_rejected(self):
        for declarations in (("BAD-NAME",), ("X", "X=again"), ("X;touch file",), ("=no-name",)):
            with self.subTest(declarations=declarations):
                with self.assertRaises(ValueError):
                    self.pack(required_env=declarations)
                self.assertFalse(self.archive.exists())

    def test_missing_or_empty_inputs_are_rejected_before_creating_archive(self):
        self.instructions.unlink()
        with self.assertRaises((ValueError, OSError)):
            self.pack()
        self.assertFalse(self.archive.exists())
        self.instructions.write_bytes(b"")
        with self.assertRaises(ValueError):
            self.pack()
        self.assertFalse(self.archive.exists())

    def test_non_utf8_instructions_are_rejected(self):
        self.instructions.write_bytes(b"\xff\xff")
        with self.assertRaises(ValueError):
            self.pack()
        self.assertFalse(self.archive.exists())

    def test_invalid_toml_is_rejected(self):
        self.profile.write_bytes(b"[profile\n")
        with self.assertRaises(ValueError):
            self.pack()
        self.assertFalse(self.archive.exists())

    def test_same_basename_and_manifest_name_are_rejected(self):
        other = self.root / "other"
        other.mkdir()
        duplicate = other / self.profile.name
        duplicate.write_text("usage", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.bundle.pack_build_bundle(self.profile, self.script, duplicate, self.archive)
        reserved = self.root / "build-bundle.json"
        reserved.write_text("usage", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.bundle.pack_build_bundle(self.profile, self.script, reserved, self.archive)

    def test_tampered_script_is_rejected_before_extracting(self):
        self.pack()
        self.mutate_archive(lambda entries: [(info, b"changed" if info.filename == self.script.name else data)
                                            for info, data in entries])
        with self.assertRaises(ValueError):
            self.unpack()
        self.assertFalse(self.out.exists())

    def test_invalid_manifest_roles_version_and_env_are_rejected(self):
        mutations = (
            lambda doc: doc.update(version=99),
            lambda doc: doc.update(version=True),
            lambda doc: doc["files"][0].update(role="instructions"),
            lambda doc: doc["files"][0].update(role=[]),
            lambda doc: doc["files"][0].update(path="../outside"),
            lambda doc: doc["files"][0].update(size=True),
            lambda doc: doc["required_env"].append({"name": "BAD-NAME", "description": "bad"}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                if self.archive.exists():
                    self.archive.unlink()
                self.pack()
                self.change_manifest(mutation)
                with self.assertRaises(ValueError):
                    self.unpack()
                self.assertFalse(self.out.exists())

    def test_duplicate_and_unexpected_members_are_rejected(self):
        for name in (self.script.name, "extra"):
            with self.subTest(name=name):
                if self.archive.exists():
                    self.archive.unlink()
                self.pack()
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(self.archive, "a") as archive:
                        archive.writestr(name, b"extra")
                with self.assertRaises(ValueError):
                    self.unpack()
                self.assertFalse(self.out.exists())

    def test_traversal_and_symlink_members_are_rejected(self):
        for filename, mode in (("../outside", stat.S_IFREG), (self.script.name, stat.S_IFLNK),
                               ("C:outside", stat.S_IFREG), ("folder/file", stat.S_IFREG)):
            with self.subTest(filename=filename):
                if self.archive.exists():
                    self.archive.unlink()
                self.pack()
                def update(entries):
                    info = zipfile.ZipInfo(filename)
                    info.create_system = 3
                    info.external_attr = (mode | 0o644) << 16
                    return [(info, data) if old.filename == self.script.name else (old, data)
                            for old, data in entries]
                self.mutate_archive(update)
                with self.assertRaises(ValueError):
                    self.unpack()
                self.assertFalse(self.out.exists())
                self.assertFalse((self.root / "outside").exists())

    def test_size_limit_is_checked_before_reading_payload(self):
        self.pack()
        with patch.object(self.bundle, "MAX_FILE_BYTES", 8):
            with self.assertRaises(ValueError):
                self.unpack()
        self.assertFalse(self.out.exists())

    def test_manifest_size_limit_also_applies_to_pack(self):
        with patch.object(self.bundle, "MAX_MANIFEST_BYTES", 8):
            with self.assertRaises(ValueError):
                self.pack()
        self.assertFalse(self.archive.exists())

    def test_pack_interrupt_removes_unfinished_archive(self):
        with patch.object(zipfile.ZipFile, "writestr", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.pack()
        self.assertFalse(self.archive.exists())

    def test_failed_extraction_removes_only_created_files(self):
        self.pack()
        original_open = Path.open
        def fail_script(path, *args, **kwargs):
            if path == self.out / self.script.name:
                raise OSError("injected write failure")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", fail_script):
            with self.assertRaises(OSError):
                self.unpack()
        self.assertFalse(self.out.exists())
        self.assertTrue(self.archive.is_file())
        self.assertTrue(self.profile.is_file())

    def test_output_symlinks_are_rejected(self):
        destination = self.root / "other-directory"
        destination.mkdir()
        link = self.root / "link"
        try:
            link.symlink_to(destination, target_is_directory=True)
        except OSError:
            self.skipTest("creating symlinks is unavailable on this host")
        self.pack()
        with self.assertRaises(ValueError):
            self.bundle.unpack_build_bundle(self.archive, link / "out")
        self.assertEqual(list(destination.iterdir()), [])

    def test_receiver_usage_does_not_follow_replaced_file_link(self):
        self.pack()
        self.unpack()
        replaced = self.out / self.script.name
        replaced.unlink()
        try:
            replaced.symlink_to(self.script)
        except OSError:
            self.skipTest("creating symlinks is unavailable on this host")
        with self.assertRaises(ValueError):
            self.bundle.render_build_bundle_usage(self.out)

    def test_usage_refuses_a_link_to_identical_external_contents(self):
        self.pack()
        self.unpack()
        # The host denies native symlink creation. Model that one file's link
        # status; its matching bytes must not authorize following the link.
        original_is_symlink = Path.is_symlink
        def is_replaced_link(path):
            return path == self.out / self.script.name or original_is_symlink(path)
        with patch.object(Path, "is_symlink", is_replaced_link):
            with self.assertRaises(ValueError):
                self.bundle.render_build_bundle_usage(self.out)

    def test_cli_round_trip_prints_usage(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["build-bundle", "pack", "--profile", str(self.profile),
                       "--script", str(self.script), "--instructions", str(self.instructions),
                       "--require-env", "LLAMA_SOURCE=源码目录", "--output", str(self.archive)],
                      command_group="pkg", prog="chimera-pkg")
        self.assertEqual(rc, 0)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(["build-bundle", "unpack", "--input", str(self.archive),
                       "--output-dir", str(self.out)], command_group="pkg", prog="chimera-pkg")
        self.assertEqual(rc, 0)
        self.assertIn("LLAMA_SOURCE", stdout.getvalue())
        self.assertIn(self.instructions.read_text(encoding="utf-8").strip(), stdout.getvalue())

    def test_cli_invalid_archive_returns_tool_error(self):
        self.archive.write_bytes(b"not an archive")
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            rc = main(["build-bundle", "unpack", "--input", str(self.archive),
                       "--output-dir", str(self.out)], command_group="pkg", prog="chimera-pkg")
        self.assertEqual(rc, 2)
        self.assertIn("error", stderr.getvalue())
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
