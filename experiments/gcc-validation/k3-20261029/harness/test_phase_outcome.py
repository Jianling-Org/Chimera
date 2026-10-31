import json
from pathlib import Path
import tempfile
import unittest
from phase_outcome import classify


class PhaseOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'stage-results').mkdir()

    def resources(self, **fields):
        data = dict(SERVICE_RESULT='success', EXIT_CODE='exited', EXIT_STATUS='0')
        data.update(fields)
        (self.root / 'stage-results/prepare_cc1-1.resources.json').write_text(json.dumps(data))

    def classify(self, rc=0):
        return classify(self.root, 'prepare_cc1', 1, 'chimera-gcc-prepare-cc1-1.service', rc)

    def test_clean_systemd_sigterm_is_not_success(self):
        self.resources(EXIT_CODE='killed', EXIT_STATUS='TERM')
        self.assertEqual(self.classify()[0], 143)

    def test_guard_stop_overrides_zero_runner_exit(self):
        self.resources(EXIT_CODE='killed', EXIT_STATUS='TERM')
        (self.root / 'DISK_GUARD_TRIGGERED.json').write_text(json.dumps({'unit': 'chimera-gcc-prepare-cc1-1.service'}))
        self.assertEqual(self.classify()[0], 28)

    def test_missing_exit_evidence_fails_closed(self):
        self.assertEqual(self.classify()[0], 125)

    def test_clean_exit_without_publication_fails(self):
        self.resources()
        self.assertEqual(self.classify()[0], 125)

    def test_real_published_zero_exit_succeeds(self):
        self.resources()
        workspace = self.root / 'workspaces/cc1'
        (workspace / 'artifacts').mkdir(parents=True)
        (workspace / 'workspace.json').write_text('{}')
        (workspace / 'artifacts/modules.tsv').write_text('manifest')
        self.assertEqual(self.classify()[0], 0)

    def test_nonzero_runner_exit_preserved(self):
        self.resources()
        self.assertEqual(self.classify(7)[0], 7)

    def test_older_guard_does_not_taint_other_attempt(self):
        self.resources(EXIT_CODE='killed', EXIT_STATUS='TERM')
        (self.root / 'DISK_GUARD_TRIGGERED.json').write_text(json.dumps({'unit': 'chimera-gcc-prepare-cc1-0.service'}))
        self.assertEqual(self.classify()[0], 143)


if __name__ == '__main__':
    unittest.main()
