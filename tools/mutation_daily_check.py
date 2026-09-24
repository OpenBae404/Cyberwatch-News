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
The two that matter most are the two gates this file has already outlived:
pushing whenever a remote exists, and pushing whenever CYBERWATCH_PUBLISH=1 is
set in the plist. Both look responsible. Both mean the decision to publish was
taken on some earlier day by someone who had not read the issue.

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

# Everything between the commit and the push: the approver lookup, the remote
# check, the detail the operator reads, and the blocking request. The mutants
# that replace the gate wholesale replace all of it, which is why the pattern is
# anchored on the request's own denial branch rather than on the first `exit 0`.
ASK_BLOCK = re.compile(
    r"# The gate\. Not an environment variable.*?"
    r"not approved \(denied or expired\).*?\n  exit 0\nfi\n",
    re.S,
)


def mutate_push_when_remote_exists(text: str) -> str:
    """The version two cards ago: a remote existing turns publishing on."""
    return ASK_BLOCK.sub('if ! git remote | grep -q .; then\n  exit 0\nfi\n', text, count=1)


def mutate_env_gate_instead_of_asking(text: str) -> str:
    """The gate this card replaced: set CYBERWATCH_PUBLISH=1 once, publish forever."""
    return ASK_BLOCK.sub(
        'if [ "${CYBERWATCH_PUBLISH:-0}" != "1" ]; then\n  exit 0\nfi\n'
        'if ! git remote | grep -q .; then\n  exit 8\nfi\n',
        text,
        count=1,
    )


def mutate_approver_overridable_by_env(text: str) -> str:
    """The approver read from the environment: CYBERWATCH_APPROVER=/usr/bin/true."""
    return text.replace(
        'if ! command -v approve-gate >/dev/null 2>&1; then',
        'APPROVER="${CYBERWATCH_APPROVER:-approve-gate}"\n'
        'if ! command -v "$APPROVER" >/dev/null 2>&1; then',
    ).replace('if approve-gate "Publish CyberWatch issue $today" \\',
              'if "$APPROVER" "Publish CyberWatch issue $today" \\')


def mutate_push_when_the_approver_is_missing(text: str) -> str:
    """Fail-open: no approver installed means publish unasked."""
    return ASK_BLOCK.sub(
        'if ! git remote | grep -q .; then\n  exit 8\nfi\n'
        'if command -v approve-gate >/dev/null 2>&1; then\n'
        '  approve-gate "Publish CyberWatch issue $(date -u \'+%Y-%m-%d\')" \\\n'
        '       --ttl 60 --requester cyberwatch-daily --detail "CVEs, and the live URL" || exit 0\n'
        'fi\n',
        text,
        count=1,
    )


def mutate_ignore_the_denial(text: str) -> str:
    """The approval is requested and its answer discarded: a decoration."""
    return re.sub(
        r'if approve-gate "Publish CyberWatch issue \$today" \\\n'
        r'.*?\n'
        r'  exit 0\nfi\n',
        'approve-gate "Publish CyberWatch issue $today" \\\n'
        '     --ttl "${CYBERWATCH_APPROVAL_TTL:-21600}" \\\n'
        '     --requester cyberwatch-daily \\\n'
        '     --detail "$detail" || true\n',
        text,
        count=1,
        flags=re.S,
    )


def mutate_detail_says_nothing(text: str) -> str:
    """The request drops the CVEs and the URL: "publish?" with nothing to read."""
    return re.sub(
        r'detail="\$\(printf .*?\)"\n',
        'detail="the daily run would like to push"\n',
        text,
        count=1,
        flags=re.S,
    )


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
    """No remote, exit 0: a job that reports success forever."""
    return text.replace(
        '  echo "[$(stamp)] no git remote is configured -- not asking for an approval that could not be acted on"\n  exit 8\n',
        '  exit 0\n',
    )


def mutate_cycling_cve_delimiter(text: str) -> str:
    """`paste -sd ', '` cycles the two delimiters: five CVEs read as three."""
    return text.replace(
        "  | paste -sd , - | sed 's/,/, /g')\"",
        "  | paste -sd ', ' -)\"",
    )


MUTATIONS = [
    ("push whenever a remote exists (the behaviour two cards ago)",
     mutate_push_when_remote_exists),
    ("an environment variable decides instead of a person (the gate this card replaced)",
     mutate_env_gate_instead_of_asking),
    ("the approver is redirectable by environment variable",
     mutate_approver_overridable_by_env),
    ("no approver installed, so publish anyway", mutate_push_when_the_approver_is_missing),
    ("ask for approval and ignore the answer", mutate_ignore_the_denial),
    ("the request says nothing about what is being published", mutate_detail_says_nothing),
    ("a feed outage no longer stops the run", mutate_ignore_run_failure),
    ("the site generator's failure is ignored", mutate_ignore_site_failure),
    ("commit even when nothing changed", mutate_commit_even_when_unchanged),
    ("stage the whole tree, not just issues/ and docs/", mutate_stage_everything),
    ("no remote exits 0 in silence", mutate_silent_missing_remote),
    ("the CVE list is joined with a cycling delimiter", mutate_cycling_cve_delimiter),
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
