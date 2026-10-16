from __future__ import annotations

import csv
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "examples/scripts/run/run_llamacpp_benchmark.sh"


class LlamaCppBenchmarkScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("bash") is None:
            self.skipTest("bash is required for the benchmark script test")
        probe = subprocess.run(
            ["bash", "--version"], capture_output=True, text=True, check=False
        )
        if probe.returncode != 0 or "GNU bash" not in probe.stdout:
            self.skipTest("GNU bash is required for the benchmark script test")

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _make_fixture(self, root: Path, *, failing_scheduler: bool = False) -> Path:
        run_dir = root / "examples/scripts/run"
        run_dir.mkdir(parents=True)
        (run_dir / "run_llamacpp_benchmark.sh").write_text(
            BENCHMARK.read_text(encoding="utf-8"), encoding="utf-8"
        )

        binary = (
            root
            / "examples/applications/llama-cpp/llama.cpp/build-remediated/bin"
            / "llama-perplexity-bidirectional"
        )
        self._write_executable(
            binary,
            "#!/usr/bin/env bash\n"
            "printf 'perplexity: 10.00 seconds per pass\\n'\n"
            "printf 'Final estimate: PPL = 20.0000 +/- 0.1\\n'\n",
        )
        for relative in (
            "examples/applications/llama-cpp/model/model.gguf",
            "examples/applications/llama-cpp/prompt/file.txt",
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture", encoding="utf-8")

        scenario_body = (
            "#!/usr/bin/env bash\n"
            "printf 'perplexity: 10.00 seconds per pass\\n'\n"
            "printf 'Final estimate: PPL = 20.0000 +/- 0.1\\n'\n"
        )
        for name in (
            "run_llamacpp_256_to_1024.sh",
            "run_llamacpp_1024_to_256.sh",
            "run_llamacpp_scheduler.sh",
        ):
            self._write_executable(run_dir / name, scenario_body)
        if failing_scheduler:
            self._write_executable(
                run_dir / "run_llamacpp_scheduler.sh",
                "#!/usr/bin/env bash\n"
                "counter=${BENCHMARK_TEST_COUNTER:?missing counter path}\n"
                "count=0\n"
                "[[ -f \"$counter\" ]] && count=$(<\"$counter\")\n"
                "count=$((count + 1))\n"
                "printf '%s\\n' \"$count\" > \"$counter\"\n"
                "if [[ \"$count\" -eq 1 ]]; then\n"
                "  printf 'fixture failure\\n' >&2\n"
                "  exit 7\n"
                "fi\n"
                + scenario_body.split("\n", 1)[1],
            )
        return binary

    @staticmethod
    def _run(root: Path, output: Path, *, runs: int):
        control = root / "control"
        control.write_text("", encoding="utf-8")
        counter = root / "scheduler.counter"
        environment = {
            "BENCHMARK_RUNS": "99",
            "BENCHMARK_OUTPUT_DIR": str(output),
            "CHIMERA_BENCHMARK_AI_THREAD_CONTROL": str(control),
            "BENCHMARK_TEST_COUNTER": str(counter),
            "MODEL": str(root / "examples/applications/llama-cpp/model/model.gguf"),
            "PROMPT_FILE": str(root / "examples/applications/llama-cpp/prompt/file.txt"),
        }
        command = ["bash", str(root / "examples/scripts/run/run_llamacpp_benchmark.sh"), "--runs", str(runs)]
        return subprocess.run(
            command,
            cwd=root,
            env={**os.environ, **environment},
            text=True,
            capture_output=True,
            check=False,
        )

    def test_runs_rotate_scenarios_and_writes_averages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._make_fixture(root)
            output = root / "results"
            result = self._run(root, output, runs=2)

            self.assertEqual(result.returncode, 0, result.stderr)
            samples = list(csv.DictReader(
                (output / "samples.tsv").open(encoding="utf-8"), delimiter="\t"
            ))
            self.assertEqual(len(samples), 10)
            self.assertEqual(
                [row["scenario"] for row in samples],
                [
                    "256-pure", "1024-pure", "256-to-1024", "1024-to-256",
                    "run_llamacpp_scheduler", "1024-pure", "256-to-1024",
                    "1024-to-256", "run_llamacpp_scheduler", "256-pure",
                ],
            )
            self.assertTrue(all(row["status"] == "ok" for row in samples))
            self.assertEqual(samples[0]["seconds_per_pass"], "10.00")
            self.assertEqual(samples[0]["ppl"], "20.0000")
            self.assertTrue((output / "summary.tsv").is_file())
            summary = list(csv.DictReader(
                (output / "summary.tsv").open(encoding="utf-8"), delimiter="\t"
            ))
            self.assertEqual([row["requested"] for row in summary], ["2"] * 5)
            self.assertTrue(all(row["valid"] == "2" and row["failed"] == "0" for row in summary))
            self.assertTrue(all(row["avg_seconds_per_pass"] == "10.00" for row in summary))
            self.assertTrue(all(row["avg_ppl"] == "20.0000" for row in summary))
            self.assertTrue((root / "control").read_text(encoding="utf-8").strip().isdigit())
            self.assertEqual(list((output / "logs").iterdir()), [])

    def test_failure_is_recorded_and_remaining_runs_continue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._make_fixture(root, failing_scheduler=True)
            output = root / "results"
            result = self._run(root, output, runs=2)

            self.assertEqual(result.returncode, 1)
            samples = list(csv.DictReader(
                (output / "samples.tsv").open(encoding="utf-8"), delimiter="\t"
            ))
            self.assertEqual(len(samples), 10)
            failed = [row for row in samples if row["status"] != "ok"]
            self.assertEqual(len(failed), 1)
            self.assertEqual(failed[0]["scenario"], "run_llamacpp_scheduler")
            self.assertEqual(failed[0]["exit_code"], "7")
            self.assertTrue(Path(failed[0]["log_path"]).is_file())
            summary = list(csv.DictReader(
                (output / "summary.tsv").open(encoding="utf-8"), delimiter="\t"
            ))
            scheduler = next(row for row in summary if row["scenario"] == "run_llamacpp_scheduler")
            self.assertEqual(scheduler["requested"], "2")
            self.assertEqual(scheduler["valid"], "1")
            self.assertEqual(scheduler["failed"], "1")
