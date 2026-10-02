"""Exercise the workflow's actual writeback block with synthetic local Git repos."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "preflight.yml"
STEP = "      - name: Commit the lock only after all automated gates pass\n"
BRANCH = "dev/rust-rewrite-v1"
PWSH = shutil.which("pwsh")
ORIGINAL = b"version = 4\n# synthetic lock fixture\n"
UPDATED = ORIGINAL + b"# synthetic dependency update\n"


def writeback_block():
    # The named step is deliberately the final step; fail if that contract moves.
    source = WORKFLOW.read_text(encoding="utf-8")
    if source.count(STEP) != 1:
        raise AssertionError("Expected exactly one lock writeback step")
    tail = source.split(STEP, 1)[1]
    header, body = tail.split("        run: |\n", 1)
    if "shell: pwsh" not in header or any(
        line and not line.startswith("          ") for line in body.splitlines()
    ):
        raise AssertionError("Writeback step structure changed; review this extractor")
    return textwrap.dedent(body)


class WorkflowContractTests(unittest.TestCase):
    def test_commit_decision_uses_staged_diff_and_rejects_errors(self):
        block = writeback_block()
        self.assertNotIn("git status --porcelain", block)
        self.assertIn("git add -- Cargo.lock", block)
        self.assertIn("git diff --cached --quiet", block)
        self.assertLess(block.index("git add --"), block.index("git diff --cached"))
        self.assertLess(block.index("git diff --cached"), block.index("git commit -m"))
        self.assertIn("$lockDiff = $LASTEXITCODE", block)
        self.assertIn("$lockDiff -eq 1", block)
        self.assertIn("$lockDiff -eq 0", block)
        self.assertIn('throw "Could not compare the staged lockfile."', block)
        self.assertNotIn("--allow-empty", block)
        self.assertNotIn("git push --force", block)

    def test_windows_regressions_run_before_rust_build(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        command = "python -m unittest discover -s tests/ci -p test_lock_writeback.py -v"
        self.assertIn(command, source)
        self.assertLess(source.index(command), source.index("cargo build --release"))
        self.assertIn('REQUIRE_PWSH_WRITEBACK_TESTS: "1"', source)

    def test_required_powershell_cannot_silently_skip(self):
        if os.environ.get("REQUIRE_PWSH_WRITEBACK_TESTS") == "1":
            self.assertIsNotNone(PWSH, "Windows writeback tests require PowerShell")


class GitFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pm-ci-writeback-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.remote = self.root / "origin.git"
        self.repo.mkdir()
        self.env = os.environ.copy()
        for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
            self.env.pop(key, None)
        self.env["GIT_CONFIG_NOSYSTEM"] = "1"
        self.env["GIT_CONFIG_GLOBAL"] = str(self.root / "empty-config")
        self.env["GIT_TERMINAL_PROMPT"] = "0"
        (self.root / "empty-config").write_text("", encoding="utf-8")
        self.git("init", "-q", "-b", BRANCH)
        self.git("config", "user.name", "Synthetic CI")
        self.git("config", "user.email", "ci@example.test")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "true")
        self.git("config", "core.safecrlf", "false")
        self.lock = self.repo / "Cargo.lock"
        self.lock.write_bytes(ORIGINAL)
        self.git("add", "Cargo.lock")
        self.git("commit", "-qm", "synthetic baseline")
        self.head = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("init", "-q", "--bare", str(self.remote))
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "-q", "origin", f"HEAD:refs/heads/{BRANCH}")
        self.lock.unlink()
        self.git("checkout", "--", "Cargo.lock")
        # The artifact's sidecar is not part of the lockfile commit.
        (self.repo / "Cargo.lock.sha256").write_text("synthetic sidecar\n", encoding="utf-8")

    def git(self, *args, check=True):
        return subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env, check=check,
            capture_output=True, text=True, timeout=30,
        )

    def remote_head(self):
        return self.git("ls-remote", "--heads", "origin", f"refs/heads/{BRANCH}").stdout.split()[0]


class GitNormalizationTests(GitFixture):
    def test_artifact_lf_only_change_has_no_staged_delta(self):
        self.assertIn(b"\r\n", self.lock.read_bytes())
        self.lock.write_bytes(ORIGINAL)
        self.assertTrue(self.git("status", "--porcelain", "--", "Cargo.lock").stdout)
        self.git("add", "--", "Cargo.lock")
        self.assertEqual(self.git("diff", "--cached", "--quiet", "--", "Cargo.lock", check=False).returncode, 0)
        # This is the real failure path of the former unconditional commit.
        self.assertNotEqual(self.git("commit", "-m", "empty commit must fail", check=False).returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.head)

    def test_real_dependency_change_has_a_staged_delta(self):
        self.lock.write_bytes(UPDATED)
        self.git("add", "--", "Cargo.lock")
        self.assertEqual(self.git("diff", "--cached", "--quiet", "--", "Cargo.lock", check=False).returncode, 1)


@unittest.skipUnless(PWSH, "PowerShell execution is required on the Windows CI gate")
class PowerShellWritebackTests(GitFixture):
    def run_block(self):
        script = self.root / "writeback.ps1"
        script.write_text(
            "$ErrorActionPreference = 'Stop'\n" + writeback_block()
            + "\nif (Test-Path variable:LASTEXITCODE) { exit $LASTEXITCODE }\n",
            encoding="utf-8",
        )
        env = dict(self.env, GITHUB_SHA=self.head)
        return subprocess.run(
            [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
            cwd=self.repo, env=env, capture_output=True, text=True, timeout=30,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unchanged_lock_succeeds_without_new_commit(self):
        self.assert_success(self.run_block())
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.head)
        self.assertEqual(self.remote_head(), self.head)

    def test_lf_artifact_succeeds_without_empty_commit(self):
        self.lock.write_bytes(ORIGINAL)
        self.assert_success(self.run_block())
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.head)
        self.assertEqual(self.remote_head(), self.head)

    def test_real_change_commits_only_lock_and_pushes(self):
        self.lock.write_bytes(UPDATED)
        self.assert_success(self.run_block())
        current = self.git("rev-parse", "HEAD").stdout.strip()
        self.assertNotEqual(current, self.head)
        self.assertEqual(self.remote_head(), current)
        self.assertEqual(self.git("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").stdout.strip(), "Cargo.lock")
        self.assertEqual(self.git("show", "HEAD:Cargo.lock").stdout.encode(), UPDATED)

    def test_moved_remote_is_not_overwritten(self):
        (self.repo / "other.txt").write_text("other writer\n", encoding="utf-8")
        self.git("add", "other.txt")
        self.git("commit", "-qm", "another writer")
        self.git("push", "-q", "origin", f"HEAD:refs/heads/{BRANCH}")
        moved = self.remote_head()
        self.git("reset", "--hard", self.head)  # Only this disposable test repository.
        self.lock.write_bytes(UPDATED)
        self.assert_success(self.run_block())
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.head)
        self.assertEqual(self.remote_head(), moved)

    def test_staging_failure_is_not_treated_as_no_change(self):
        self.lock.write_bytes(UPDATED)
        (self.repo / ".git" / "index.lock").write_text("synthetic blocker", encoding="utf-8")
        self.assertNotEqual(self.run_block().returncode, 0)
        self.assertEqual(self.remote_head(), self.head)

    def test_remote_failure_is_not_treated_as_no_change(self):
        self.lock.write_bytes(UPDATED)
        self.git("remote", "set-url", "origin", str(self.root / "missing.git"))
        self.assertNotEqual(self.run_block().returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.head)

    def test_commit_failure_is_not_ignored(self):
        self.lock.write_bytes(UPDATED)
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        hook.write_bytes(b"#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        self.assertNotEqual(self.run_block().returncode, 0)
        self.assertEqual(self.remote_head(), self.head)

    def test_push_failure_is_not_ignored(self):
        self.lock.write_bytes(UPDATED)
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_bytes(b"#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        self.assertNotEqual(self.run_block().returncode, 0)
        self.assertEqual(self.remote_head(), self.head)


if __name__ == "__main__":
    unittest.main()
