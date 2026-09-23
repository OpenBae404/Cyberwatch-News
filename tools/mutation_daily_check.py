#!/usr/bin/env python3
"""Break the daily runner on a throwaway copy; tests/test_daily_run.py must go red.

A test suite nobody has watched fail is a decoration. Every guarantee in
``deploy/cyberwatch-daily.sh`` is about something the script does NOT do, and a
test for an absent side effect is exactly the kind that passes for the wrong
reason -- "no push happened" is also true of a script with no push in it, of a
script that exited early for an unrelated reason, and of a push to a remote that
silently refused.

So each mutation below restores a plausible version of the script -- most of
them versions this script has actually had -- and asserts the suite catches it.
The mutation that matters most is #1: pushing when a remote exists. That is what
the runner did before this card, it looks responsible, and every "no push was
attempted" test in a suite without a configured remote stays green under it.

    python3 tools/mutation_daily_check.py

Exit 0 only if every mutant is caught.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER_REL = "deploy/cyberwatch-daily.sh"
TEST = "tests.test_daily_run"

PUSH_BLOCK = '''# The gate. Not `if a remote exists` -- that would mean the act of adding a
# remote silently turns an unattended publisher on, which is exactly the
# surprise this repo cannot afford once it is public.
if [ "${CYBERWATCH_PUBLISH:-0}" != "1" ]; then
  echo "[$(stamp)] publishing is off (CYBERWATCH_PUBLISH is not 1) -- commit is local only"
  exit 0
fi

if ! git remote | grep -q .; then
  echo "[$(stamp)] CYBERWATCH_PUBLISH=1 but no git remote is configured -- nothing pushed"
  exit 8
fi
'''


def mutate_push_when_remote_exists(text: str) -> str:
    """The version this card replaced: a remote existing turns publishing on."""
    return text.replace(PUSH_BLOCK, 'if ! git remote | grep -q .; then\n  exit 0\nfi\n')


def mutate_publish_when_variable_merely_set(text: str) -> str:
    """`-n` instead of `= 1`: CYBERWATCH_PUBLISH=0 publishes."""
    return text.replace(
        'if [ "${CYBERWATCH_PUBLISH:-0}" != "1" ]; then',
        'if [ -z "${CYBERWATCH_PUBLISH+x}" ]; then',
    )


def mutate_publish_by_default(text: str) -> str:
    """The default flipped to on -- the one-character version of the bug."""
    return text.replace('"${CYBERWATCH_PUBLISH:-0}"', '"${CYBERWATCH_PUBLISH:-1}"')


def mutate_ignore_run_failure(text: str) -> str:
    """A feed outage no longer stops the run: build and commit proceed."""
    return re.sub(
        r'status=\$\?\nif \[ "\$status" -ne 0 \]; then\n'
        r'  echo "\[\$\(stamp\)\] run\.py exited .*?\n  exit "\$status"\nfi\n',
        'status=$?\n',
        text,
        count=1,
        flags=re.S,
    )


def mutate_ignore_site_failure(text: str) -> str:
    """The site generator's exit code is dropped; a stale docs/ is committed."""
    return re.sub(
        r'status=\$\?\nif \[ "\$status" -ne 0 \]; then\n'
        r'  echo "\[\$\(stamp\)\] build_site\.py exited .*?\n  exit 5\nfi\n',
        'status=$?\n',
        text,
        count=1,
        flags=re.S,
    )


def mutate_commit_even_when_unchanged(text: str) -> str:
    """The quiet-day guard removed: an empty commit every morning."""
    return re.sub(
        r'if git diff --cached --quiet; then\n.*?\n  exit 0\nfi\n',
        '',
        text,
        count=1,
        flags=re.S,
    ).replace('commit --quiet -m', 'commit --quiet --allow-empty -m')


def mutate_stage_everything(text: str) -> str:
    """`git add -A`: whatever is in the tree ships with the issue."""
    return text.replace("git add issues docs", "git add -A")


def mutate_silent_missing_remote(text: str) -> str:
    """Publishing on, no remote, exit 0: a job that reports success forever."""
    return text.replace(
        '  echo "[$(stamp)] CYBERWATCH_PUBLISH=1 but no git remote is configured -- nothing pushed"\n  exit 8\n',
        '  exit 0\n',
    )


MUTATIONS = [
    ("push whenever a remote exists (the behaviour this card replaced)",
     mutate_push_when_remote_exists),
    ("publish when CYBERWATCH_PUBLISH is merely set, whatever its value",
     mutate_publish_when_variable_merely_set),
    ("publishing defaults to on", mutate_publish_by_default),
    ("a feed outage no longer stops the run", mutate_ignore_run_failure),
    ("the site generator's failure is ignored", mutate_ignore_site_failure),
    ("commit even when nothing changed", mutate_commit_even_when_unchanged),
    ("stage the whole tree, not just issues/ and docs/", mutate_stage_everything),
    ("publishing on with no remote exits 0 in silence", mutate_silent_missing_remote),
]


def run_suite(root: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", TEST],
        cwd=str(root), capture_output=True, text=True, timeout=900,
        env={"PYTHONPATH": str(root), "PATH": __import__("os").environ["PATH"],
             "HOME": __import__("os").environ.get("HOME", "")},
    )
    return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")


def main() -> int:
    original = (ROOT / RUNNER_REL).read_text(encoding="utf-8")
    tmp = Path(tempfile.mkdtemp(prefix="cyberwatch-daily-mut-"))
    try:
        work = tmp / "repo"
        # Copy only what the test module needs; .git is irrelevant to it except
        # for the plist-install scan, which is skipped by copying git metadata.
        shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".worktrees", ".venv", "docs"))
        shutil.copytree(ROOT / ".git", work / ".git", symlinks=True) \
            if (ROOT / ".git").is_dir() else shutil.copy2(ROOT / ".git", work / ".git")

        ok, output = run_suite(work)
        print(f"baseline: {'PASS' if ok else 'FAIL'}")
        if not ok:
            print(output[-4000:])
            print("The suite fails before any mutation; nothing below means anything.")
            return 1

        runner = work / RUNNER_REL
        caught = 0
        for index, (label, mutate) in enumerate(MUTATIONS, start=1):
            mutated = mutate(original)
            if mutated == original:
                print(f"  {index}. {label}: MUTATION DID NOT APPLY -- the script moved")
                continue
            runner.write_text(mutated, encoding="utf-8")
            ok, output = run_suite(work)
            runner.write_text(original, encoding="utf-8")
            if ok:
                print(f"  {index}. {label}: SURVIVED -- the suite does not hold this")
                print(output[-2500:])
            else:
                print(f"  {index}. {label}: caught")
                caught += 1

        print()
        if caught == len(MUTATIONS):
            print(f"PASSED: all {caught} mutants were caught")
            return 0
        print(f"FAILED: {len(MUTATIONS) - caught} of {len(MUTATIONS)} mutant(s) survived")
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
