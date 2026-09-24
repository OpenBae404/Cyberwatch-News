"""The daily run, executed. Not grepped.

``deploy/cyberwatch-daily.sh`` is the only thing in this repo that runs
unattended and the only thing that can push. Its guarantees are about what it
does NOT do -- no commit when the feeds failed, no commit when nothing changed,
no push unless a human approved this issue -- and none of those can be
established by reading the file. A test that asserts ``"git push" in text``
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
  * ``approve-gate`` is a stub that records the argv it was called with and
    exits with a code the case chooses. PATH is rebuilt from scratch for every
    run so the operator's REAL approve-gate can never be reached: a test that
    posted a live Telegram approval request every time the suite ran would be
    its own incident.

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
    # Two CVE ids, one of them repeated, because the approval request has to
    # name what is being published and must not name it twice.
    (issues / "2026-09-22.md").write_text(
        "# issue two\\n\\nCVE-2026-11111 and CVE-2026-22222, then CVE-2026-11111 again\\n",
        encoding="utf-8",
    )
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

APPROVE_STUB = '''#!/bin/bash
# Stand-in for ~/.local/bin/approve-gate. Records the whole argv and exits with
# the code the test chose. Arguments are NUL-separated because --detail is
# deliberately multi-line: a line-based log would split one argument into
# several and the test would be reading a different argv than the script sent.
# The real approve-gate asks a human over Telegram; that is exactly why no test
# may reach it.
{{
  for a in "$@"; do printf '%s\\0' "$a"; done
  printf '\\036'
}} >> "$CYBERWATCH_APPROVE_LOG"
exit {code}
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
        self.approve_log = self.tmp / "approve-invocations.log"
        self.approve_log.write_text("", encoding="utf-8")

    def install_approver(self, exit_code: int) -> None:
        """Put a stub approve-gate on the run's PATH, exiting as told."""
        stub = self.bin / "approve-gate"
        stub.write_text(APPROVE_STUB.format(code=exit_code), encoding="utf-8")
        stub.chmod(0o755)

    def run_daily(self, **env: str) -> subprocess.CompletedProcess[str]:
        # PATH is built, not inherited. The operator's real approve-gate lives
        # in ~/.local/bin, which is on the ambient PATH: inheriting it would
        # mean every green test run posted a live approval request to a phone.
        environ = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "CYBERWATCH_GIT_LOG": str(self.git_log),
            "CYBERWATCH_APPROVE_LOG": str(self.approve_log),
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

    def approve_calls(self) -> list[list[str]]:
        """Every approve-gate invocation, as argv lists."""
        raw = self.approve_log.read_text(encoding="utf-8")
        calls: list[list[str]] = []
        for record in raw.split("\x1e"):
            if not record:
                continue
            args = record.split("\x00")
            if args and args[-1] == "":
                args.pop()
            calls.append(args)
        return calls

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
        self.install_approver(0)
        self.run_daily(CYBERWATCH_STUB_MODE="same")
        self.assertEqual(self.push_attempts(), [],
                         "nothing was committed, so there is nothing to publish")
        self.assertEqual(self.approve_calls(), [],
                         "no issue was produced, so nobody should have been asked")


class TestPushingRequiresAnApproval(DailyRunCase):
    """Acceptance: the push waits for a human decision about THIS issue.

    A remote is configured in every one of these cases. That is the point: the
    runner once pushed whenever a remote existed, so adding the remote was
    itself the act that started publishing. The env gate that replaced it had
    the same shape one level up -- set once, and every later morning publishes
    unreviewed.
    """

    def test_no_push_when_no_approver_is_installed(self) -> None:
        # The state of every clone but the author's. It must not be a failure,
        # and it must not be a push.
        proc = self.run_daily(CYBERWATCH_STUB_MODE="new")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotEqual(self.head(), self.base, "the issue should still be committed")
        self.assertEqual(
            self.push_attempts(), [],
            "git was never asked to push; recorded calls: " + "; ".join(self.git_calls()),
        )
        self.assertEqual(self.remote_refs(), "", "the remote received nothing")
        self.assertIn("no approve-gate on PATH", proc.stdout)

    def test_a_denied_approval_does_not_push_and_still_exits_zero(self) -> None:
        self.install_approver(1)
        proc = self.run_daily(CYBERWATCH_STUB_MODE="new")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(len(self.approve_calls()), 1, "the operator must have been asked once")
        self.assertEqual(self.push_attempts(), [],
                         "denied; recorded calls: " + "; ".join(self.git_calls()))
        self.assertEqual(self.remote_refs(), "", "the remote received nothing")
        self.assertIn("not approved", proc.stdout)
        self.assertNotEqual(self.head(), self.base, "a denial must not undo the commit")

    def test_an_approval_pushes(self) -> None:
        # Without this, deleting the push entirely would leave every test above
        # green. The gate has to be seen open at least once.
        self.install_approver(0)
        proc = self.run_daily(CYBERWATCH_STUB_MODE="new")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(self.push_attempts(), "an approved run must push")
        self.assertIn("refs/heads/master", self.remote_refs())

    def test_the_request_names_the_cves_and_the_url(self) -> None:
        # An approval request that says only "push?" trains the operator to tap
        # Approve without reading. What is in --detail is the whole point of
        # asking, so it is asserted on the transmitted argv.
        self.install_approver(0)
        self.run_daily(CYBERWATCH_STUB_MODE="new")
        calls = self.approve_calls()
        self.assertEqual(len(calls), 1, f"expected one request, got {calls}")
        argv = calls[0]

        self.assertTrue(argv[0].startswith("Publish CyberWatch issue "),
                        f"the action line reads {argv[0]!r}")
        self.assertIn("--requester", argv)
        self.assertEqual(argv[argv.index("--requester") + 1], "cyberwatch-daily")
        self.assertIn("--ttl", argv)
        self.assertTrue(int(argv[argv.index("--ttl") + 1]) > 0)

        detail = argv[argv.index("--detail") + 1]
        self.assertIn("CVE-2026-11111", detail, detail)
        self.assertIn("CVE-2026-22222", detail, detail)
        self.assertEqual(detail.count("CVE-2026-11111"), 1,
                         "a repeated CVE must be listed once:\n" + detail)
        self.assertIn("https://cyberwatch.asutera.dev", detail, detail)
        self.assertIn("issues/2026-09-22.md", detail, detail)
        self.assertIn(_git(self.repo, "rev-parse", "--short", "HEAD"), detail, detail)

    def test_the_approval_is_asked_after_the_commit_exists(self) -> None:
        # The operator is shown a commit hash and a CVE list read out of that
        # commit. Asking first would mean approving a description of an issue
        # that had not been written yet.
        self.install_approver(0)
        self.run_daily(CYBERWATCH_STUB_MODE="new")
        detail = self.approve_calls()[0][self.approve_calls()[0].index("--detail") + 1]
        self.assertIn(_git(self.repo, "rev-parse", "--short", "HEAD"), detail)
        self.assertNotIn(self.base[:7], detail, "the request described the previous commit")

    def test_the_old_environment_gate_no_longer_publishes(self) -> None:
        # The variable this card removed. If it still worked, the approval would
        # be decoration: the plist could set it once and never ask again.
        for value in ("1", "0", "true", "yes"):
            with self.subTest(CYBERWATCH_PUBLISH=value):
                self.setUp()
                proc = self.run_daily(CYBERWATCH_STUB_MODE="new", CYBERWATCH_PUBLISH=value)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(self.push_attempts(), [],
                                 f"CYBERWATCH_PUBLISH={value!r} still pushes")
                self.assertEqual(self.remote_refs(), "")

    def test_no_environment_variable_can_supply_a_different_approver(self) -> None:
        # The obvious way to make this script testable is to read the approver's
        # name from the environment. That hands the plist a one-line rubber
        # stamp -- CYBERWATCH_APPROVER=/usr/bin/true -- which is the env gate
        # this card removed under a new name. So the name is hard-coded, and a
        # run with no approve-gate on PATH must stay unpublished no matter what
        # the environment points at.
        stamp = self.bin / "rubber-stamp"
        stamp.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
        stamp.chmod(0o755)
        proc = self.run_daily(
            CYBERWATCH_STUB_MODE="new",
            CYBERWATCH_APPROVER=str(stamp),
            CYBERWATCH_APPROVE_CMD=str(stamp),
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.push_attempts(), [],
                         "an environment variable named a substitute approver and it was used")
        self.assertEqual(self.remote_refs(), "")

    def test_publishing_with_no_remote_fails_loudly(self) -> None:
        # Silence here would mean a job that reports success every morning
        # while the site never updates.
        self.install_approver(0)
        _git(self.repo, "remote", "remove", "origin")
        proc = self.run_daily(CYBERWATCH_STUB_MODE="new")
        self.assertEqual(proc.returncode, 8, proc.stdout + proc.stderr)
        self.assertIn("no git remote", proc.stdout)
        self.assertEqual(self.approve_calls(), [],
                         "asking to publish with nowhere to push wastes the operator's decision")

    def test_a_push_failure_is_reported(self) -> None:
        # Approved and then broken: the operator said yes, so a failure here is
        # a real failure and must not be reported as a successful morning.
        self.install_approver(0)
        _git(self.repo, "remote", "set-url", "origin", str(self.tmp / "does-not-exist.git"))
        proc = self.run_daily(CYBERWATCH_STUB_MODE="new")
        self.assertEqual(proc.returncode, 7, proc.stdout + proc.stderr)
        self.assertIn("push failed", proc.stdout)

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

    def test_the_shipped_plist_carries_no_publishing_switch(self) -> None:
        # The gate in the runner is worth nothing if the artifact that invokes
        # it ships with the gate already open, and nothing if the plist can name
        # its own approver.
        import plistlib
        with (ROOT / "deploy" / "ai.cyberwatch.daily.plist").open("rb") as handle:
            plist = plistlib.load(handle)
        env = plist.get("EnvironmentVariables", {})
        for key in ("CYBERWATCH_PUBLISH", "CYBERWATCH_APPROVER", "CYBERWATCH_APPROVE_CMD"):
            self.assertNotIn(
                key, env,
                f"{key} in the installed agent would publish without asking anyone",
            )

    def test_the_plist_puts_the_approver_on_the_runs_path(self) -> None:
        # The runner looks up approve-gate on PATH, and launchd gives a job a
        # bare PATH: without ~/.local/bin the approval would silently never be
        # requested, which looks exactly like a working, cautious job.
        import plistlib
        with (ROOT / "deploy" / "ai.cyberwatch.daily.plist").open("rb") as handle:
            plist = plistlib.load(handle)
        path = plist.get("EnvironmentVariables", {}).get("PATH", "")
        self.assertIn(".local/bin", path,
                      "approve-gate lives in ~/.local/bin and would not be found")

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
