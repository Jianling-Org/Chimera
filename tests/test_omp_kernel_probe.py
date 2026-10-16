"""Host smoke tests; K3/RVV and LLVM libomp require separate board validation."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples/applications/omp-kernel-probe"


class ProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("gcc")
        if not compiler:
            raise unittest.SkipTest("host GCC with OpenMP required")
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / ("probe.exe" if os.name == "nt" else "probe")
        kernel = Path(cls.temp.name) / "kernel.o"
        subprocess.run([
            compiler, "-std=c11", "-O3", "-ffast-math", "-fno-lto",
            "-Wall", "-Wextra", "-Werror", "-c", str(SOURCE / "kernel.c"),
            "-o", str(kernel),
        ], check=True, capture_output=True, text=True)
        subprocess.run([
            compiler, "-std=c11", "-O3", "-fopenmp", "-fno-lto",
            "-Wall", "-Wextra", "-Werror",
            str(SOURCE / "probe.c"), str(kernel),
            "-lm", "-o", str(cls.binary),
        ], check=True, capture_output=True, text=True)

    def run_probe(self, mode, schedule):
        result = subprocess.run([
            str(self.binary), "--mode", mode, "--schedule", schedule,
            "--threads", "3", "--rows", "7", "--cols", "17",
            "--chunk", "3", "--rounds", "3", "--passes", "2",
        ], check=True, capture_output=True, text=True, timeout=20)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_same_work_and_result_across_schedules(self):
        checksums = []
        for mode, schedule in [("serial", "static"), ("omp", "static"), ("omp", "dynamic")]:
            records = self.run_probe(mode, schedule)
            passes = [r for r in records if r["event"] == "pass"]
            self.assertEqual(len(passes), 2)
            for result in passes:
                workers = [r for r in records if r["event"] == "worker" and r["pass"] == result["pass"]]
                self.assertTrue(result["valid"])
                self.assertEqual(sum(r["chunks"] for r in workers), 9)
                self.assertEqual(sum(r["rows"] for r in workers), 21)
                self.assertEqual(result["elements"], 21 * 17)
                self.assertEqual(len(workers), 1 if mode == "serial" else 3)
                checksums.append(result["checksum"])
        self.assertTrue(all(x == checksums[0] for x in checksums))

    def test_invalid_arguments_fail(self):
        for args in [["--threads", "0"], ["--chunk", "0"], ["--schedule", "bad"], ["--rows"], ["--mode", "bad"]]:
            result = subprocess.run([str(self.binary), *args], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
