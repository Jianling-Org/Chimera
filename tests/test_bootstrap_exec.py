"""Real make -> shell -> child exec verifies constructor re-registration.
The fixture runtime is deliberately a stub; this tests lifecycle, not RVV migration.
"""
from pathlib import Path
from hashlib import sha256
import os
import shutil
import subprocess
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]

def build_bootstrap(tmp_path):
    output = tmp_path / "libchimera-bootstrap.so"
    subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
        "-I" + str(ROOT / "runtime/interfaces/abi"),
        "-I" + str(ROOT / "runtime/artifacts/manifest/linux_riscv64_rvv_v1"),
        str(ROOT / "runtime/runtime/bootstrap/bootstrap.c"),
        str(ROOT / "runtime/artifacts/manifest/linux_riscv64_rvv_v1/integrity.c"),
        "-ldl", "-o", str(output)], check=True)
    return output

def check_make_exec_registry(bootstrap, tmp_path):
    make = Path(shutil.which("make")).resolve()
    child = tmp_path / "child"
    source = tmp_path / "child.c"
    source.write_text('#include <stdlib.h>\nint main(void) { return getenv("LD_PRELOAD") ? 0 : 9; }\n')
    subprocess.run(["cc", str(source), "-o", str(child)], check=True)
    runtime = tmp_path / "runtime.so"
    source.write_text(r"""#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
const unsigned long long chimera_runtime_abi_v1 = 1;
int chimera_runtime_initialize_v1(const char *workspace) {
 FILE *f = fopen(getenv("BOOT_LOG"), "a");
 if (!f) return 0;
 fprintf(f, "%ld %s\n", (long)getpid(), workspace); fclose(f); return 1;
}
""")
    subprocess.run(["cc", "-shared", "-fPIC", str(source), "-o", str(runtime)], check=True)
    registry = tmp_path / "workspaces.tsv"
    def record(exe, workspace, digest=None):
        artifacts = workspace / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        rows = []
        for path in (exe, runtime):
            st = path.stat()
            rows.append('\t'.join(map(str, (path, sha256(path.read_bytes()).hexdigest(),
                st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns//10**9,
                st.st_mtime_ns%10**9, st.st_ctime_ns//10**9, st.st_ctime_ns%10**9)))+'\n')
        (artifacts / 'verified-files.tsv').write_text(''.join(rows))
        return "\t".join((str(exe), digest or sha256(exe.read_bytes()).hexdigest(),
            str(workspace), str(runtime), sha256(runtime.read_bytes()).hexdigest())) + "\n"
    registry.write_text("chimera-registry-v1\n" + record(make, tmp_path / "make-ws") + record(child, tmp_path / "child-ws"))
    log = tmp_path / "log"
    env = dict(os.environ, LD_PRELOAD=str(bootstrap), CHIMERA_REGISTRY=str(registry),
               CHIMERA_WORKSPACE="/incorrect-parent", BOOT_LOG=str(log))
    env.pop("CHIMERA_AUTOMIGRATE", None)
    (tmp_path / "Makefile").write_text("all:\n\t@" + str(child) + "\n\t@" + str(child) + "\n")
    env["PYTHONPATH"] = str(ROOT / "cli") + ":" + str(ROOT)
    runner = "import sys; sys.meta_path = [f for f in sys.meta_path if type(f).__name__ != 'ScikitBuildRedirectingFinder']; import chimera.user; raise SystemExit(chimera.user.main())"
    subprocess.run([sys.executable, "-c", runner, "run", "--registry", str(registry),
        "--bootstrap", str(bootstrap), str(make), "-j2", "-C", str(tmp_path)], env=env, check=True)
    entries = log.read_text().splitlines()
    assert len(entries) == 3
    assert len({line.split()[0] for line in entries}) == 3
    assert sum(line.endswith("child-ws") for line in entries) == 2
    assert sum(line.endswith("make-ws") for line in entries) == 1
    # Stale executable identity must never load the runtime.
    log.unlink()
    registry.write_text("chimera-registry-v1\n" + record(child, tmp_path, "0" * 64))
    subprocess.run([str(child)], env=env, check=True)
    assert not log.exists()
    # A modified runtime is rejected before its constructor executes.
    registry.write_text("chimera-registry-v1\n" + record(child, tmp_path).replace(
        sha256(runtime.read_bytes()).hexdigest(), "0" * 64))
    subprocess.run([str(child)], env=env, check=True)
    assert not log.exists()
    # Duplicate records are ambiguous and fail closed.
    registry.write_text("chimera-registry-v1\n" + record(child, tmp_path) * 2)
    subprocess.run([str(child)], env=env, check=True)
    assert not log.exists()

class BootstrapExecTest(unittest.TestCase):
    def test_make_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            check_make_exec_registry(build_bootstrap(root), root)

if __name__ == "__main__":
    unittest.main()
