"""The publish-time audit: it must be able to say no.

The repo is going public once and the audit runs before that push. An audit that
cannot fail is a checkbox, so this module plants each kind of finding in a throwaway
git repo and asserts the audit refuses, then asserts an allowlist entry with a
reason clears it -- and that a credential is NOT clearable that way.

The launchd plist is checked here too: it is the other publish-time artifact
nothing else parses, and a plist that does not parse is a daily run that never
happens.
"""

from __future__ import annotations

import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "tools" / "public_repo_audit.py"
PLIST = ROOT / "deploy" / "ai.cyberwatch.daily.plist"
RUNNER = ROOT / "deploy" / "cyberwatch-daily.sh"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True,
                   capture_output=True, text=True, timeout=60)


class TestAuditCanFail(unittest.TestCase):
    """Each finding is planted in a fresh repo; the audit must refuse it."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cyberwatch-audit-"))
        self.addCleanup(self._cleanup)
        # A minimal copy: the audit only needs itself, the allowlist and files
        # to scan. Copying the whole repo would drag its real findings in.
        (self.tmp / "tools").mkdir()
        (self.tmp / "deploy").mkdir()
        (self.tmp / "tools" / "public_repo_audit.py").write_text(
            AUDIT.read_text(encoding="utf-8"), encoding="utf-8"
        )
        (self.tmp / "deploy" / "audit-allowlist.txt").write_text(
            # The audit's own source matches its own patterns (it contains them).
            # Accepting that once is the baseline; every test's planted finding
            # is on top of it.
            "internal host|tools/public_repo_audit.py  # the audit's own patterns\n",
            encoding="utf-8",
        )
        _git(self.tmp, "init", "-q")
        _git(self.tmp, "add", "-A")

    def _cleanup(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_audit(self) -> tuple[int, str]:
        proc = subprocess.run(
            [sys.executable, str(self.tmp / "tools" / "public_repo_audit.py")],
            capture_output=True, text=True, timeout=120,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def plant(self, name: str, text: str) -> None:
        (self.tmp / name).write_text(text, encoding="utf-8")
        _git(self.tmp, "add", name)

    def allow(self, line: str) -> None:
        path = self.tmp / "deploy" / "audit-allowlist.txt"
        path.write_text(
            path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8"
        )

    def test_a_clean_repo_passes(self) -> None:
        code, out = self.run_audit()
        self.assertEqual(code, 0, out)
        self.assertIn("CLEAR TO PUBLISH", out)

    def test_an_internal_host_is_refused_then_allowlistable(self) -> None:
        self.plant("notes.md", "the model lives at http://localhost:8001/v1\n")
        code, out = self.run_audit()
        self.assertEqual(code, 1, out)
        self.assertIn("internal host", out)

        self.allow("internal host|notes.md  # mDNS-only name, not a credential")
        code, out = self.run_audit()
        self.assertEqual(code, 0, out)
        self.assertIn("mDNS-only name", out)

    def test_an_rfc1918_address_is_refused(self) -> None:
        self.plant("notes.md", "ssh 192.168.1.40\n")
        code, out = self.run_audit()
        self.assertEqual(code, 1, out)

    def test_an_absolute_home_path_is_refused(self) -> None:
        self.plant("notes.md", "see /Users/someone/Projects/thing\n")
        code, out = self.run_audit()
        self.assertEqual(code, 1, out)
        self.assertIn("absolute home path", out)

    def test_an_email_address_is_refused(self) -> None:
        self.plant("notes.md", "contact someone@example.org\n")
        code, out = self.run_audit()
        self.assertEqual(code, 1, out)
        self.assertIn("email address", out)

    def test_a_token_is_refused_and_cannot_be_allowlisted(self) -> None:
        self.plant("conf.py", 'TOKEN = "ghp_' + "a" * 30 + '"\n')
        code, out = self.run_audit()
        self.assertEqual(code, 1, out)
        self.assertIn("GitHub token", out)

        # The escape hatch that makes an audit useless: allowlisting a secret.
        self.allow("GitHub token|conf.py  # it is fine honestly")
        code, out = self.run_audit()
        self.assertEqual(code, 1, out)
        self.assertIn("cannot be allowlisted", out)

    def test_a_private_key_and_an_env_file_are_refused(self) -> None:
        # Assembled at runtime: a literal key header in this file would be a
        # finding in this file, and the audit refuses to allowlist secrets --
        # correctly, so the fixture must not be one.
        header = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"
        self.plant("key.pem", header + "\nAAAA\n")
        code, out = self.run_audit()
        self.assertEqual(code, 1, out)

    def test_an_assigned_password_is_refused(self) -> None:
        self.plant("conf.py", "pass" + 'word = "hunter2hunter2"\n')
        code, out = self.run_audit()
        self.assertEqual(code, 1, out)
        self.assertIn("assigned secret", out)

    def test_an_allowlist_entry_does_not_cover_another_file(self) -> None:
        self.plant("notes.md", "http://localhost:8001/v1\n")
        self.plant("other.md", "http://localhost:8001/v1\n")
        self.allow("internal host|notes.md  # accepted")
        code, out = self.run_audit()
        self.assertEqual(
            code, 1,
            "an accepted finding in one file must not silently accept the same "
            "finding in a new file",
        )
        self.assertIn("other.md", out)

    def test_an_untracked_file_is_not_scanned(self) -> None:
        # git never publishes it, so flagging it would train the reader to
        # ignore the audit.
        (self.tmp / "scratch.md").write_text("ghp_" + "b" * 30 + "\n", encoding="utf-8")
        code, out = self.run_audit()
        self.assertEqual(code, 0, out)


class TestRealRepoIsClearToPublish(unittest.TestCase):
    """The audit on this actual repo, which is the check before the push."""

    def test_the_repo_has_no_unaccepted_findings(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(AUDIT)], capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(
            proc.returncode, 0,
            "tools/public_repo_audit.py refuses this tree:\n" + proc.stdout + proc.stderr,
        )

    def test_docs_carries_no_internal_host(self) -> None:
        docs = ROOT / "docs"
        if not docs.is_dir():
            self.skipTest("docs/ not built")
        for page in sorted(docs.rglob("*")):
            if not page.is_file() or page.suffix not in {".html", ".xml", ".css"}:
                continue
            text = page.read_text(encoding="utf-8")
            for needle in ("localhost", "127.0.0.1", "localhost", "192.168."):
                self.assertNotIn(needle, text, f"{page.name} names {needle}")


class TestLaunchdPlist(unittest.TestCase):
    """The daily run's plist, which nothing else in the suite parses."""

    def setUp(self) -> None:
        with PLIST.open("rb") as handle:
            self.plist = plistlib.load(handle)

    def test_it_parses_and_names_the_runner(self) -> None:
        self.assertEqual(self.plist["Label"], "ai.cyberwatch.daily")
        program = self.plist["ProgramArguments"]
        self.assertTrue(program[-1].endswith("deploy/cyberwatch-daily.sh"))

    def test_it_runs_once_a_day_and_not_on_load(self) -> None:
        interval = self.plist["StartCalendarInterval"]
        self.assertIn("Hour", interval)
        self.assertIn("Minute", interval)
        self.assertFalse(
            self.plist.get("RunAtLoad", False),
            "loading the agent must not publish an issue",
        )

    def test_it_captures_both_streams(self) -> None:
        self.assertTrue(self.plist["StandardOutPath"].endswith(".log"))
        self.assertTrue(self.plist["StandardErrorPath"].endswith(".log"))

    def test_the_runner_exists_and_is_valid_bash(self) -> None:
        self.assertTrue(RUNNER.is_file())
        proc = subprocess.run(
            ["bash", "-n", str(RUNNER)], capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_the_runner_stages_only_the_published_directories(self) -> None:
        text = RUNNER.read_text(encoding="utf-8")
        self.assertIn("git add issues docs", text)
        self.assertNotIn("git add -A", text)
        self.assertNotIn("git add .", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
