import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "prepare-ci-lock.py"
spec = importlib.util.spec_from_file_location("prepare_ci_lock", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def lock_bytes(version, include_tests=True):
    text = f'version = 4\n\n[[package]]\nname = "yoke-derive"\nversion = "{version}"\n'
    if include_tests:
        text += '\n[[package]]\nname = "iced_test"\nversion = "0.14.0"\n'
    return text.encode()


class PrepareLockTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.lock = self.root / "Cargo.lock"
        self.legacy = lock_bytes("0.8.3", include_tests=False)
        self.current = lock_bytes("0.8.4")
        self.calls = []

    def run_cargo(self, args, **kwargs):
        self.assertEqual(kwargs["cwd"], self.root)
        self.assertTrue(kwargs["check"])
        self.calls.append(args)
        if args[1] == "update":
            self.lock.write_bytes(self.current)
        return subprocess.CompletedProcess(args, 0)

    def test_known_legacy_lock_gets_one_targeted_update_then_locked_validation(self):
        self.lock.write_bytes(self.legacy)
        with patch.object(module, "LEGACY_LOCK_BLOB", module.git_blob_sha(self.legacy)):
            result = module.prepare(self.root, self.run_cargo)
        self.assertEqual(self.calls[0], ["cargo", "update", "--package", "yoke-derive", "--precise", "0.8.4"])
        self.assertEqual(len(self.calls), 2)
        self.assertIn("--locked", self.calls[1])
        self.assertTrue(result["refreshed"])
        self.assertEqual(result["sha256"], hashlib.sha256(self.current).hexdigest())
        self.assertEqual(self.lock.read_bytes(), self.current)

    def test_current_lock_is_not_regenerated(self):
        self.lock.write_bytes(self.current)
        result = module.prepare(self.root, self.run_cargo)
        self.assertFalse(result["refreshed"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][1], "metadata")
        self.assertIn("--locked", self.calls[0])
        self.assertEqual(self.lock.read_bytes(), self.current)

    def test_unrecognized_legacy_lock_fails_without_running_cargo(self):
        self.lock.write_bytes(self.legacy)
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            module.prepare(self.root, self.run_cargo)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.lock.read_bytes(), self.legacy)

    def test_update_failure_is_not_ignored(self):
        self.lock.write_bytes(self.legacy)
        def failure(args, **kwargs):
            raise subprocess.CalledProcessError(1, args)
        with patch.object(module, "LEGACY_LOCK_BLOB", module.git_blob_sha(self.legacy)):
            with self.assertRaises(subprocess.CalledProcessError):
                module.prepare(self.root, failure)
        self.assertEqual(self.lock.read_bytes(), self.legacy)

    def test_locked_metadata_must_not_change_the_snapshot(self):
        self.lock.write_bytes(self.current)
        def mutation(args, **kwargs):
            self.lock.write_bytes(self.current + b"\n# unexpected mutation\n")
            return subprocess.CompletedProcess(args, 0)
        with self.assertRaisesRegex(ValueError, "changed"):
            module.prepare(self.root, mutation)

    def test_missing_gui_dependency_is_not_silently_bootstrapped(self):
        self.lock.write_bytes(lock_bytes("0.8.4", include_tests=False))
        with self.assertRaisesRegex(ValueError, "iced_test"):
            module.prepare(self.root, self.run_cargo)
        self.assertEqual(self.calls, [])

    def test_malformed_lock_is_rejected(self):
        self.lock.write_bytes(b"not valid TOML [")
        with self.assertRaises(ValueError):
            module.prepare(self.root, self.run_cargo)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
