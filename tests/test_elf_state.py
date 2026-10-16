"""ELF state registry tests."""

from __future__ import annotations

import tempfile
import json
import multiprocessing
import unittest
from pathlib import Path
from unittest import mock

from chimera import elf_state

from chimera.elf_state import (
    CHECKED,
    PROBLEMATIC,
    REMEDIATED,
    UNCHECKED,
    ElfStateRegistry,
)


def _concurrent_registration(registry_path, elf_path, status, previous, barrier, results):
    """Pause hashing to expose writers that loaded the same registry snapshot."""
    original_hash = elf_state.sha256_of

    def synchronized_hash(path):
        barrier.wait(timeout=15)
        return original_hash(path)

    try:
        with mock.patch.object(elf_state, "sha256_of", synchronized_hash):
            ElfStateRegistry(Path(registry_path)).set_status(
                Path(elf_path), status, expected_previous=previous
            )
        results.put(("ok", str(elf_path)))
    except Exception as error:
        results.put((type(error).__name__, str(error)))


class ElfStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.registry_path = self.root / "elf_registry.json"
        self.registry = ElfStateRegistry(self.registry_path)

    def _write_elf(self, name: str, payload: bytes = b"\x7fELF") -> Path:
        path = self.root / name
        path.write_bytes(payload)
        return path

    def test_unknown_elf_is_unchecked_with_no_record(self):
        elf = self._write_elf("a.so")
        status, record = self.registry.effective_status(elf)
        self.assertEqual(status, UNCHECKED)
        self.assertIsNone(record)

    def test_set_and_read_back_checked(self):
        elf = self._write_elf("b.so")
        record = self.registry.set_status(elf, CHECKED)
        self.assertEqual(record.status, CHECKED)
        status, _ = self.registry.effective_status(elf)
        self.assertEqual(status, CHECKED)

    def test_problematic_then_remediated(self):
        elf = self._write_elf("c.so")
        decision = self._write_elf("c.decision.json", b"{}")
        self.registry.set_status(
            elf, PROBLEMATIC, decision_ref=str(decision),
            expected_previous=UNCHECKED,
        )
        status, _ = self.registry.effective_status(elf)
        self.assertEqual(status, PROBLEMATIC)
        entry = self.registry.entry(elf)
        self.assertEqual(entry.decision_ref, str(decision))
        self.registry.set_status(
            elf, REMEDIATED, expected_previous=PROBLEMATIC
        )
        status, _ = self.registry.effective_status(elf)
        self.assertEqual(status, REMEDIATED)

    def test_content_change_degrades_to_unchecked(self):
        elf = self._write_elf("d.so")
        self.registry.set_status(elf, CHECKED)
        elf.write_bytes(b"changed bytes")
        status, record = self.registry.effective_status(elf)
        self.assertEqual(status, UNCHECKED)
        self.assertIsNotNone(record)

    def test_expected_previous_guard_rejects_drift(self):
        elf = self._write_elf("e.so")
        with self.assertRaises(RuntimeError):
            self.registry.set_status(
                elf, REMEDIATED, expected_previous=PROBLEMATIC
            )

    def test_unknown_status_rejected(self):
        elf = self._write_elf("f.so")
        with self.assertRaises(ValueError):
            self.registry.set_status(elf, "MAYBE")

    def test_missing_file_rejected_when_required(self):
        with self.assertRaises(FileNotFoundError):
            self.registry.set_status(self.root / "ghost.so", CHECKED)

    def test_registry_file_is_created_atomically_valid_json(self):
        elf = self._write_elf("g.so")
        self.registry.set_status(elf, CHECKED)
        import json
        data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        key = str(elf.resolve())
        self.assertIn(key, data)
        self.assertEqual(data[key]["status"], CHECKED)

    def _register_concurrently(self, entries):
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(len(entries))
        results = context.Queue()
        processes = [
            context.Process(
                target=_concurrent_registration,
                args=(str(self.registry_path), str(elf), status, previous, barrier, results),
            )
            for elf, status, previous in entries
        ]
        try:
            for process in processes:
                process.start()
            outcomes = [results.get(timeout=25) for _ in processes]
            for process in processes:
                process.join(timeout=5)
                self.assertEqual(process.exitcode, 0)
            return outcomes
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            results.close()
            results.join_thread()

    def test_parallel_link_registrations_preserve_all_elfs_and_existing_credential(self):
        existing = self._write_elf("llama-perplexity")
        self.registry.set_status(
            existing, CHECKED, check_fingerprint="verified-fingerprint",
            check_scope={"checks": ["safety.stack-liveness"]},
        )
        original_record = self.registry.entry(existing)
        lto1 = self._write_elf("lto1")
        lto_dump = self._write_elf("lto-dump")
        outcomes = self._register_concurrently([
            (lto1, REMEDIATED, None), (lto_dump, REMEDIATED, None),
        ])
        self.assertEqual(sorted(kind for kind, _ in outcomes), ["ok", "ok"], outcomes)
        try:
            data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            self.fail(f"parallel registrations corrupted the registry: {error}")
        self.assertEqual(set(data), {str(path.resolve()) for path in (existing, lto1, lto_dump)})
        self.assertEqual(self.registry.entry(existing), original_record)
        for path in (lto1, lto_dump):
            self.assertEqual(self.registry.effective_status(path)[0], REMEDIATED)
            self.assertIsNone(self.registry.entry(path).check_fingerprint)

    def test_parallel_expected_previous_guard_allows_only_one_transition(self):
        elf = self._write_elf("same-elf")
        self.registry.set_status(elf, PROBLEMATIC)
        outcomes = self._register_concurrently([
            (elf, CHECKED, PROBLEMATIC), (elf, REMEDIATED, PROBLEMATIC),
        ])
        self.assertEqual(sorted(kind for kind, _ in outcomes), ["RuntimeError", "ok"], outcomes)
        self.assertIn("elf state transition expects", next(
            message for kind, message in outcomes if kind == "RuntimeError"
        ))

    def test_publish_failure_preserves_registry_and_cleans_own_temporary(self):
        first = self._write_elf("first")
        second = self._write_elf("second")
        self.registry.set_status(first, CHECKED)
        original = self.registry_path.read_bytes()
        with mock.patch.object(elf_state.os, "replace", side_effect=OSError("publish failed")):
            with self.assertRaisesRegex(OSError, "publish failed"):
                self.registry.set_status(second, REMEDIATED)
        self.assertEqual(self.registry_path.read_bytes(), original)
        self.assertEqual(list(self.root.glob("*.tmp")), [])
        self.registry.set_status(second, REMEDIATED)
        self.assertEqual(self.registry.effective_status(second)[0], REMEDIATED)

    def test_stale_legacy_temporary_is_not_used_or_removed(self):
        stale = self.registry_path.with_suffix(".json.tmp")
        stale.write_bytes(b"old interrupted writer")
        elf = self._write_elf("fresh")
        self.registry.set_status(elf, CHECKED)
        self.assertTrue(stale.is_file(), "do not reuse another writer's temporary path")
        self.assertEqual(stale.read_bytes(), b"old interrupted writer")

    def test_corrupt_registry_is_not_silently_replaced(self):
        self.registry_path.write_text("{invalid", encoding="utf-8")
        elf = self._write_elf("valid-elf")
        with self.assertRaisesRegex(RuntimeError, "elf registry is corrupt"):
            self.registry.set_status(elf, REMEDIATED)
        self.assertEqual(self.registry_path.read_text(encoding="utf-8"), "{invalid")


if __name__ == "__main__":
    unittest.main()
