"""The daily run, executed. Not grepped.

``deploy/cyberwatch-daily.sh`` is the only thing in this repo that runs
unattended and the only thing that can push. Its three guarantees are about
what it does NOT do -- no commit when the feeds failed, no commit when nothing
changed, no push unless a human turned publishing on -- and none of those can
be established by reading the file. A test that asserts ``"git push" in text``
passes against a script that pushes from a line the reader did not think about.

So this module runs the real script against stub stages in a throwaway repo:

  * ``run.py`` and ``build_site.py`` are replaced by stubs whose outcome is
    chosen by an environment variable, so a feed outage is a real non-zero exit
    from the real script rather than a mocked one.
  * ``git`` on PATH is a shim that appends every invocation to a log and then
    calls the real git. "No push was attempted" is then a fact about the
    recorded argv, not an inference from an absent side effect -- a push to an
    unreachable remote also leaves no side effect.
  * ``origin`` is a real bare repository, so the shim's verdict is
    cross-checked: if no push was attempted, the bare repo has no refs.

The push case is exercised too. A gate that is never seen open is
indistinguishable from a script that cannot push at all, and that test would
stay green if the push were deleted.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "deploy" / "cyberwatch-daily.sh"

# The stub stages. Both are deliberately dumb: the thing under test is the
# shell around them, not these.
STUB_RUN = '''#!/usr/bin/env python3
"""Stand-in for run.py. CYBERWATCH_STUB_MODE picks the outcome."""
import os, sys
from pathlib import Path

mode = os.environ.get("CYBERWATCH_STUB_MODE", "new")
issues = Path(__file__).resolve().parent / "issues"

if mode == "kev-outage":
    print("stub: CISA KEV catalogue unavailable", file=sys.stderr)
    raise SystemExit(2)
if mode == "nothing-to-ship":
    print("stub: no candidate survived", file=sys.stderr)
    raise SystemExit(4)

issues.mkdir(exist_ok=True)
if mode == "same":
    # A run that produced nothing new: it rewrites the issue already on disk,
    # byte for byte. This is the ordinary quiet-day outcome, not an error.
    (issues / "2026-09-21.md").write_text("# issue one\\n", encoding="utf-8")
else:
    (issues / "2026-09-22.md").write_text("# issue two\\n", encoding="utf-8")
print("stub run.py: ok")
'''

STUB_BUILD = '''#!/usr/bin/env python3
"""Stand-in for build_site.py: docs/ is a function of issues/, no clock."""
import os, sys
from pathlib import Path

if os.environ.get("CYBERWATCH_STUB_SITE") == "fail":
    print("stub: docs/ unwritable", file=sys.stderr)
    raise SystemExit(2)

here = Path(__file__).resolve().parent
docs = here / "docs"
docs.mkdir(exist_ok=True)
names = sorted(p.name for p in (here / "issues").glob("*.md"))
(docs / "index.html").write_text(
    "<ul>" + "".join(f"<li>{n}</li>" for n in names) + "</ul>\\n", encoding="utf-8"
)
print("stub build_site.py: ok")
'''

GIT_SHIM = '''#!/bin/bash
# Records what the script asked git to do, then does it. The log is the
# evidence; the forwarding keeps the script's behaviour real.
printf '%s\\n' "$*" >> "$CYBERWATCH_GIT_LOG"
exec {real_git} "$@"
'''


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(cwd), *args], check=True,
                          capture_output=True, text=True, timeout=60)
    return proc.stdout.strip()


class DailyRunCase(unittest.TestCase):
    """A throwaway repo with the real runner, stub stages and a bare origin."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cyberwatch-daily-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.repo = self.tmp / "repo"
        (self.repo / "deploy").mkdir(parents=True)
        (self.repo / "issues").mkdir()
        (self.repo / "docs").mkdir()

        shutil.copy2(RUNNER, self.repo / "deploy" / "cyberwatch-daily.sh")
        (self.repo / "run.py").write_text(STUB_RUN, encoding="utf-8")
        (self.repo / "build_site.py").write_text(STUB_BUILD, encoding="utf-8")
        (self.repo / "issues" / "2026-09-21.md").write_text("# issue one\n", encoding="utf-8")
        (self.repo / "docs" / "index.html").write_text(
            "<ul><li>2026-09-21.md</li></ul>\n", encoding="utf-8"
        )

        _git(self.repo, "init", "-q", "-b", "master")
        _git(self.repo, "config", "user.name", "test")
        _git(self.repo, "config", "user.email", "test@localhost")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "base")
        self.base = _git(self.repo, "rev-parse", "HEAD")

        # A real bare remote, added but not pushed to.
        self.remote = self.tmp / "origin.git"
        subprocess.run(["git", "init", "-q", "--bare", str(self.remote)],
                       check=True, capture_output=True, timeout=60)
        _git(self.repo, "remote", "add", "origin", str(self.remote))

        # The recording git.
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        real_git = shutil.which("git")
        assert real_git, "git is required to run this test"
        shim = self.bin / "git"
        shim.write_text(GIT_SHIM.format(real_git=real_git), encoding="utf-8")
        shim.chmod(0o755)
        self.git_log = self.tmp / "git-invocations.log"
        self.git_log.write_text("", encoding="utf-8")

    def run_daily(self, **env: str) -> subprocess.CompletedProcess[str]:
        environ = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
            "CYBERWATCH_GIT_LOG": str(self.git_log),
            "CYBERWATCH_PYTHON": sys.executable,
        }
        environ.pop("CYBERWATCH_PUBLISH", None)
        environ.update(env)
        return subprocess.run(
            ["bash", str(self.repo / "deploy" / "cyberwatch-daily.sh")],
            capture_output=True, text=True, timeout=180, env=environ, cwd=str(self.tmp),
        )

    # -- the three facts each case is judged on -------------------------------

    def git_calls(self) -> list[str]:
        return [line for line in self.git_log.read_text(encoding="utf-8").splitlines() if line]

    def push_attempts(self) -> list[str]:
        return [c for c in self.git_calls() if " push" in f" {c}" or c.startswith("push")]

    def head(self) -> str:
        return _git(self.repo, "rev-parse", "HEAD")

    def remote_refs(self) -> str:
        return _git(self.remote, "for-each-ref")


class TestAFailedRunWritesNothing(DailyRunCase):
    """Acceptance: no feed reachable exits non-zero and creates no commit."""

    def test_a_kev_outage_exits_nonzero_and_commits_nothing(self) -> None:
        proc = self.run_daily(CYBERWATCH_STUB_MODE="kev-outage")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(self.head(), self.base, "a failed run must not commit")
        self.assertEqual(self.push_attempts(), [])

    def test_a_failed_run_does_not_even_rebuild_the_site(self) -> None:
        # The ordering matters: a site rebuilt from a half-written issues/ is
        # how a feed outage reaches the published page.
        before = (self.repo / "docs" / "index.html").read_text(encoding="utf-8")
        self.run_daily(CYBERWATCH_STUB_MODE="kev-outage")
        self.assertEqual((self.repo / "docs" / "index.html").read_text(encoding="utf-8"), before)

    def test_nothing_to_ship_also_exits_nonzero_and_commits_nothing(self) -> None:
        proc = self.run_daily(CYBERWATCH_STUB_MODE="nothing-to-ship")
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        self.assertEqual(self.head(), self.base)

    def test_a_site_generator_failure_commits_nothing(self) -> None:
        proc = self.run_daily(CYBERWATCH_STUB_MODE="new", CYBERWATCH_STUB_SITE="fail")
        self.assertEqual(proc.returncode, 5, proc.stdout + proc.stderr)
        self.assertEqual(self.head(), self.base,
                         "an issue written but not published must not be committed alone")


class TestAnUnchangedRunCommitsNothing(DailyRunCase):
    """Acceptance: a run that produces no new content creates no commit."""

    def test_a_quiet_day_exits_zero_with_no_commit(self) -> None:
        proc = self.run_daily(CYBERWATCH_STUB_MODE="same")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.head(), self.base, "an identical rebuild must not commit")
        self.assertIn("nothing new to commit", proc.stdout)

    def test_a_quiet_day_leaves_the_tree_clean(self) -> None:
        # An empty commit is one failure mode; a run that stages changes and
        # walks away leaves the next run committing them under today's date.
        self.run_daily(CYBERWATCH_STUB_MODE="same")
        self.assertEqual(_git(self.repo, "status", "--porcelain"), "")

    def test_a_quiet_day_never_reaches_the_push(self) -> None:
        self.run_daily(CYBERWATCH_STUB_MODE="same", CYBERWATCH_PUBLISH="1")
        self.assertEqual(self.push_attempts(), [],
                         "nothing was committed, so there is nothing to publish")


class TestPushingIsOffUnlessTurnedOn(DailyRunCase):
    """Acceptance: pushing is off unless an environment variable is set.

    A remote is configured in every one of these cases. That is the point: the
    previous version of this script pushed whenever a remote existed, so adding
    the remote was itself the act that started publishing.
    """

    def test_no_push_is_attempted_by_default(self) -> None:
        proc = self.run_daily(CYBERWATCH_STUB_MODE="new")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotEqual(self.head(), self.base, "the issue should still be committed")
        self.assertEqual(
            self.push_attempts(), [],
            "git was never asked to push; recorded calls: " + "; ".join(self.git_calls()),
        )
        self.assertEqual(self.remote_refs(), "", "the remote received nothing")
        self.assertIn("publishing is off", proc.stdout)

    def test_a_value_other_than_one_does_not_publish(self) -> None:
        for value in ("0", "", "true", "yes", "no"):
            with self.subTest(value=value):
                self.git_log.write_text("", encoding="utf-8")
                self.run_daily(CYBERWATCH_STUB_MODE="new", CYBERWATCH_PUBLISH=value)
                self.assertEqual(self.push_attempts(), [], f"CYBERWATCH_PUBLISH={value!r} pushed")
                self.assertEqual(self.remote_refs(), "")

    def test_the_gate_opens_when_it_is_set(self) -> None:
        # Without this, deleting the push entirely would leave every test above
        # green. The gate has to be seen open at least once.
        proc = self.run_daily(CYBERWATCH_STUB_MODE="new", CYBERWATCH_PUBLISH="1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(self.push_attempts(), "CYBERWATCH_PUBLISH=1 must push")
        self.assertIn("refs/heads/master", self.remote_refs())

    def test_publishing_with_no_remote_fails_loudly(self) -> None:
        # Silence here would mean a job that reports success every morning
        # while the site never updates.
        _git(self.repo, "remote", "remove", "origin")
        proc = self.run_daily(CYBERWATCH_STUB_MODE="new", CYBERWATCH_PUBLISH="1")
        self.assertEqual(proc.returncode, 8, proc.stdout + proc.stderr)
        self.assertIn("no git remote", proc.stdout)

    def test_only_issues_and_docs_are_committed(self) -> None:
        # A daily job that commits whatever is in the tree publishes a
        # half-finished source edit somebody left behind.
        (self.repo / "src_leftover.py").write_text("SECRET = 'oops'\n", encoding="utf-8")
        self.run_daily(CYBERWATCH_STUB_MODE="new")
        committed = _git(self.repo, "show", "--name-only", "--format=", "HEAD").split()
        self.assertTrue(committed)
        for name in committed:
            self.assertTrue(
                name.startswith(("issues/", "docs/")),
                f"the daily commit touched {name}",
            )


class TestThePlistIsNotSelfInstalling(unittest.TestCase):
    """Acceptance: the plist exists under deploy/ and no code installs it.

    Installing a LaunchAgent is a change to the machine, not to the repo. A
    test run, a build, or an import must never schedule a daily job on someone
    who only cloned this to read it.
    """

    def test_the_plist_is_where_the_card_says(self) -> None:
        self.assertTrue((ROOT / "deploy" / "ai.cyberwatch.daily.plist").is_file())

    def test_the_shipped_plist_does_not_turn_publishing_on(self) -> None:
        # The gate in the runner is worth nothing if the artifact that invokes
        # it ships with the gate already open.
        import plistlib
        with (ROOT / "deploy" / "ai.cyberwatch.daily.plist").open("rb") as handle:
            plist = plistlib.load(handle)
        env = plist.get("EnvironmentVariables", {})
        self.assertNotIn(
            "CYBERWATCH_PUBLISH", env,
            "the installed agent would publish unattended from day one",
        )

    def test_no_tracked_file_installs_it(self) -> None:
        # Only executable code can install anything. Prose that *documents* the
        # install command is the intended way a human learns it -- this repo's
        # README does exactly that -- so scanning markdown here would force the
        # documentation to be vague in order to keep a test green, which is a
        # worse repo and a worse test. Scripts and modules are the surface that
        # can actually run launchctl, so they are the surface scanned.
        proc = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                              capture_output=True, text=True, timeout=120, check=True)
        offenders: list[str] = []
        for rel in proc.stdout.split():
            path = ROOT / rel
            if not path.is_file() or path.suffix not in {".py", ".sh", ".bash", ".zsh"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            in_docstring = False
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.count('"""') == 1 or stripped.count("'''") == 1:
                    in_docstring = not in_docstring
                    continue
                if in_docstring or stripped.startswith("#"):
                    continue
                if "launchctl" in stripped or "LaunchAgents" in stripped:
                    offenders.append(f"{rel}: {stripped}")
        self.assertEqual(offenders, [], "these lines would install the agent:\n" + "\n".join(offenders))


if __name__ == "__main__":
    unittest.main(verbosity=2)
