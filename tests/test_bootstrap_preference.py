"""Policy selection reaches the kernel before exec and is never silently ignored."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bootstrap_launch", ROOT / "runtime/launcher/preload/chimera/preload/bootstrap_launch.py")
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


class PreferenceTest(unittest.TestCase):
    def test_each_policy_opts_in_before_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            files = [Path(directory) / name for name in ("app", "bootstrap.so", "registry")]
            for file in files:
                file.touch()
            for preference in ("prefer-x100", "prefer-a100", None):
                control = mock_open()
                with patch("builtins.open", control), patch.object(os, "execve") as execute:
                    launch.launch_bootstrap(*files[:1], [], *files[1:], automigrate=True, preference=preference)
                control.assert_called_once_with("/proc/" + (preference or "prefer-a100").replace("-", "_"), "w")
                control().write.assert_called_once_with("inherit:" + str(os.getpid()) + "\n")
                self.assertEqual(execute.call_args.args[1], [str(files[0])])

    def test_unavailable_interface_does_not_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "input"
            file.touch()
            with patch("builtins.open", side_effect=FileNotFoundError), patch.object(os, "execve") as execute:
                with self.assertRaises(FileNotFoundError):
                    launch.launch_bootstrap(file, [], file, file, preference="prefer-x100")
                execute.assert_not_called()

    def test_invalid_policy_rejected(self):
        with self.assertRaisesRegex(ValueError, "preference"):
            launch.launch_bootstrap("missing", [], "missing", "missing", preference="other")


if __name__ == "__main__":
    unittest.main()
