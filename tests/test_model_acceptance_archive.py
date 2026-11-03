"""Verify published evidence copies; this does not run or re-audit K3 raw traces."""
import hashlib
import json
import math
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[1]
ARCHIVE = REPO / "experiments/runtime-evaluation/k3-20261102"


def read_json(path):
    return json.loads(path.read_bytes())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ModelAcceptanceArchiveTests(unittest.TestCase):
    def test_all_archived_files_match_provenance(self):
        files = read_json(ARCHIVE / "provenance.json")["files"]
        actual = {p.relative_to(ARCHIVE).as_posix() for p in ARCHIVE.rglob("*")
                  if p.is_file() and p.name != "provenance.json"}
        self.assertEqual(actual, set(files))
        for name, expected in files.items():
            with self.subTest(name=name):
                path = ARCHIVE / name
                self.assertTrue(path.resolve().is_relative_to(ARCHIVE.resolve()))
                self.assertEqual(path.stat().st_size, expected["bytes"])
                self.assertEqual(digest(path), expected["sha256"])

    def test_qualified_markers_bind_actual_success_and_reports(self):
        for n in ("41", "42"):
            with self.subTest(model=n):
                root = ARCHIVE / "records" / ("model" + n)
                marker = read_json(root / "qualified.json")
                self.assertTrue(marker["passed"])
                bound = {
                    "completion": root / "runtime-completion.json",
                    "audit": root / "verification.json",
                    "audit_completion": root / "completion.json",
                    "audit_resources": root / "unit.resources.json",
                    "local_verification": root / "local-verification.json",
                    "report": ARCHIVE / f"reports/4.{n[-1]}-完整重测报告.zh-CN.md",
                    "report_change_notes": ARCHIVE / f"reports/4.{n[-1]}-性能报告修改意见.zh-CN.md",
                }
                for key, path in bound.items():
                    self.assertEqual(digest(path), marker[key]["sha256"], key)
                for name in ("completion.json", "runtime-completion.json", "verification.json"):
                    self.assertTrue(read_json(root / name)["passed"])
                verification = read_json(root / "verification.json")
                for resource in (read_json(root / "unit.resources.json"),
                                 read_json(root / "runtime-resources.json"),
                                 verification["model_parent_resources"]):
                    self.assertEqual([resource[k] for k in
                                      ("SERVICE_RESULT", "EXIT_CODE", "EXIT_STATUS")],
                                     ["success", "exited", "0"])
                    self.assertEqual(int(resource["memory.swap.peak"]), 0)
                    events = dict(line.split() for line in resource["memory.events"].splitlines())
                    for key in ("oom", "oom_kill", "oom_group_kill"):
                        self.assertEqual(int(events[key]), 0)
                self.assertTrue(read_json(root / "runtime-resources.json")["trace_cleanup_passed"])
        marker42 = read_json(ARCHIVE / "records/model42/qualified.json")
        self.assertEqual(marker42["model41_qualified_sha256"],
                         digest(ARCHIVE / "records/model41/qualified.json"))

    def test_per_case_totals_and_separate_native_references(self):
        models = read_json(ARCHIVE / "acceptance-summary.json")["models"]
        for n, summary in zip(("41", "42"), models):
            with self.subTest(model=n):
                root = ARCHIVE / "records" / ("model" + n)
                verification = read_json(root / "verification.json")
                rows = [json.loads(line) for line in
                        (root / "case-audits.jsonl").read_text(encoding="utf-8").splitlines()]
                self.assertEqual([row["index"] for row in rows], list(range(len(rows))))
                self.assertEqual(rows[0]["stage"], "native-reference")
                self.assertEqual(rows[0]["threads"], 16)
                native = rows[0]["ppl"]
                self.assertEqual(native, verification["native_reference_ppl"])
                automatic = rows[1:]
                self.assertEqual(len(automatic), verification["automatic_rounds"])
                self.assertEqual([r["threads"] for r in rows if r["stage"] == "matrix"],
                                 [2, 4, 8, 12, 16, 24, 32])
                repeated = [r for r in rows if r["stage"] == "repeat-16"]
                self.assertEqual(len(repeated), 10)
                self.assertTrue(all(r["threads"] == 16 for r in repeated))
                mixed = [r for r in rows if r["stage"] == "mixed"]
                self.assertEqual(len(mixed), verification["mixed_rounds"])
                seconds = math.fsum(r["seconds"] for r in mixed)
                self.assertGreaterEqual(seconds, 7200)
                self.assertAlmostEqual(seconds, verification["mixed_actual_application_seconds"], places=8)
                self.assertAlmostEqual(seconds, summary["mixed_actual_application_seconds"], places=8)
                for row in rows:
                    self.assertTrue(math.isfinite(row["ppl"]) and row["ppl"] > 0)
                    self.assertTrue(math.isfinite(row["seconds"]) and row["seconds"] > 0)
                    self.assertAlmostEqual(abs(row["ppl"] - native) / native,
                                           row["relative_ppl_delta"], places=14)
                    self.assertLessEqual(row["relative_ppl_delta"], .02)
                maximum = max(r["relative_ppl_delta"] for r in automatic)
                self.assertEqual(maximum, verification["maximum_relative_ppl_delta"])
                self.assertEqual(maximum, summary["maximum_relative_ppl_delta"])
                routes = {key: sum(r["routes"][key] for r in automatic)
                          for key in ("256-to-1024", "1024-to-256")}
                self.assertEqual(routes, verification["route_counts"])
                self.assertEqual(routes, summary["route_counts"])
                self.assertTrue(all(count > 0 for count in routes.values()))
                self.assertEqual(sum(r["predicate_witnesses"] for r in automatic), sum(routes.values()))
                for key, field in (("owned_threads", "owned_thread_instances"),
                                   ("short_threads", "short_thread_instances")):
                    self.assertEqual(sum(r[key] for r in automatic), verification[field])
                self.assertTrue(all(r["all_threads_published_ready"] for r in automatic))
                self.assertEqual(verification["main_thread_actual_migration_cases"], len(automatic))
                for field in ("all_40_receipts_current", "all_3019_source_files_reconstructed",
                              "all_commits_positive_kernel_predicate", "raw_ready_bools_unchanged",
                              "nine_ledgers_zero", "trace_loss_zero", "six_private_probes_cleaned"):
                    self.assertTrue(verification[field], field)
                self.assertEqual(verification["timeout_increment"], 0)
                self.assertFalse(verification["numerical_difference_cause_resolved"])

    def test_driver_and_policy_bindings(self):
        bindings = read_json(ARCHIVE / "public-driver-bindings.json")
        bindings.update(read_json(ARCHIVE / "source-patch-bindings.json"))
        for name, binding in bindings.items():
            with self.subTest(name=name):
                raw = (REPO / name).read_bytes()
                # Git can normalize a measured CRLF file to LF on checkout.
                # Compare the recorded normalized identity without losing the
                # binding to the original measured bytes.
                self.assertEqual(hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest(),
                                 binding["lf_sha256"])
                self.assertIn(binding["measured_sha256"],
                              (binding["local_sha256"], binding["lf_sha256"]))
        policy = read_json(ARCHIVE / "ppl-policy-summary.json")
        self.assertEqual(policy["user_authorization_quote"], "改为2%新协议重测，报告披露并保留旧失败")
        for n, cpus in (("41", list(range(8))), ("42", list(range(8, 16)))):
            cfg = read_json(ARCHIVE / f"records/model{n}/config-summary.json")
            self.assertEqual(cfg["relative_ppl_tolerance"], .02)
            self.assertEqual(cfg["native_cpus"], cpus)
            self.assertEqual(cfg["application_configuration"], "original-default")
            self.assertEqual(cfg["automatic_preference"], "prefer-a100")
            self.assertEqual(cfg["assets_sha256"]["policy_authorization"],
                             policy["authorization_artifact_sha256"])

    def test_source_reconstruction_and_actual_scalar_build_proofs(self):
        for n in ("41", "42"):
            root = ARCHIVE / "records" / ("model" + n)
            verification = read_json(root / "verification.json")
            path = root / "source-and-build-verification.json"
            self.assertEqual(digest(path), verification["source_build_verification_sha256"])
            source = read_json(path)
            self.assertTrue(source["passed"])
            self.assertEqual(source["reconstructed_files"], 3019)
            self.assertEqual(len(source["patches"]), 4)
        source42 = read_json(ARCHIVE / "records/model42/source-and-build-verification.json")
        self.assertEqual(source42["compile_commands"], 337)
        self.assertEqual(sum(source42["control_targets"].values()), 200)
        self.assertEqual(source42["ggml_rvv_commands"], 26)
        self.assertEqual(len(source42["selected_existing_objects"]), 226)
        self.assertGreater(source42["whole_elf_vector_instructions"], 0)


if __name__ == "__main__":
    unittest.main()
