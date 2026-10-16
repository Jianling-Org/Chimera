"""Cold imports against the wheel's package layout, without source aliases."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest


class InstalledAnalysisImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.temporary = tempfile.TemporaryDirectory()
        cls.installed = Path(cls.temporary.name) / 'installed'
        packages = tomllib.loads((cls.repo / 'pyproject.toml').read_text(encoding='utf-8'))
        packages = packages['tool']['scikit-build']['wheel']['packages']
        for target, source in packages.items():
            for original in (cls.repo / source).rglob('*.py'):
                destination = cls.installed / target / original.relative_to(cls.repo / source)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, destination)
        # The application packages come only from the staged wheel layout;
        # pyelftools can be provided by this test interpreter's dependencies.
        spec = importlib.util.find_spec('elftools')
        cls.dependencies = str(Path(spec.origin).parent.parent) if spec else None

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def cold(self, body):
        paths = [str(self.installed)]
        if self.dependencies:
            paths.append(self.dependencies)
        code = 'import sys;sys.path[:0]=' + repr(paths) + '\n' + body
        return subprocess.run([sys.executable, '-I', '-c', code],
                              cwd=self.temporary.name, capture_output=True,
                              text=True, encoding='utf-8', timeout=30)

    def test_stack_semantics_can_be_the_first_import(self):
        result = self.cold(
            'from chimera.preprocess.offline.analysis.arch.riscv.stack_semantics '
            'import RiscvStackSemantics\nassert RiscvStackSemantics() is not None')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rvv_services_constructs_the_semantics_after_cold_import(self):
        result = self.cold(
            'from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices\n'
            'from chimera.preprocess.offline.analysis.arch.riscv.stack_semantics '
            'import RiscvStackSemantics\n'
            'assert isinstance(RvvServices().stack_semantics, RiscvStackSemantics)')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_services_semantics_export_is_preserved(self):
        result = self.cold(
            'from chimera.preprocess.offline.analysis.arch.riscv.rvv.services '
            'import RiscvStackSemantics, RvvServices\n'
            'from chimera.preprocess.offline.analysis.arch.riscv.stack_semantics '
            'import RiscvStackSemantics as Canonical\n'
            'assert RiscvStackSemantics is Canonical\n'
            'assert isinstance(RvvServices().stack_semantics, Canonical)')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_identity_audit_import_order_works_in_the_wheel_layout(self):
        result = self.cold(
            'import runpy\n'
            'sys.argv = ["audit_module_identity.py", "--out-dir", ' +
            repr(str(Path(self.temporary.name) / 'identity')) +
            ', "--source-root", ' + repr(str(self.repo)) +
            ', "--venv", ' + repr(str(self.installed)) + ']\n'
            'runpy.run_path(' + repr(str(self.repo / 'tools/audit_module_identity.py')) +
            ', run_name="__main__")')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)


if __name__ == '__main__':
    unittest.main()
