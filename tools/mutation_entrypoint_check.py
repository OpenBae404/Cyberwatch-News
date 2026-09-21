#!/usr/bin/env python3
"""Break the KEV-outage guard on a throwaway copy and check the tests go red.

`tests/test_run_entrypoint.py` claims a KEV outage aborts the run. A test that
has never been watched fail proves nothing, and this particular one is easy to
write in a way that passes against a `load_kev` that quietly returns `None` --
because the ranker accepts `kev=None` and the run continues looking healthy.

So: copy the repo to a temp dir, apply each mutation, run the entrypoint tests,
and assert they FAIL. If a mutant survives, the guard is decorative and this
script exits non-zero.

    python3 tools/mutation_entrypoint_check.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (name, file, find, replace) -- each is a plausible-looking bug.
MUTATIONS = [
    (
        "a KEV fetch failure returns None instead of raising",
        "run.py",
        '    except KevError as exc:\n'
        '        raise KevOutage(f"CISA KEV catalogue unavailable: {exc}") from exc',
        '    except KevError:\n'
        '        return None',
    ),
    (
        "a truncated catalogue is accepted as a quiet day",
        "run.py",
        "    if size < minimum:",
        "    if False:",
    ),
    (
        "the run writes its issue before checking anything",
        "run.py",
        '    except RunFailure as exc:\n'
        '        print(f"run.py: {exc}", file=sys.stderr)',
        '    except RunFailure as exc:\n'
        '        return 0  # mutant: swallow the failure\n'
        '        print(f"run.py: {exc}", file=sys.stderr)',
    ),
    (
        "the NVD window is lastMod",
        "run.py",
        '                by="published",',
        '                by="modified",',
    ),
    (
        "tier 1 is never fetched by id (a window-only run)",
        "run.py",
        "    kev_items, kev_recent = collect_kev_candidates(\n"
        "        catalog, kev_item_fetch, timeout=timeout,\n"
        "    )",
        "    kev_items, kev_recent = [], 0  # mutant: window-only, tier 1 unreachable",
    ),
    (
        "a by-id fetch failure kills the run instead of thinning it",
        "run.py",
        "    except (NvdError, OSError, ValueError) as exc:\n"
        "        print(",
        "    except (NvdError, OSError, ValueError) as exc:\n"
        "        raise FeedFailure(str(exc)) from exc\n"
        "        print(",
    ),
]

TEST_ARGV = ["-m", "unittest", "tests.test_run_entrypoint"]


def run_tests(cwd: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, *TEST_ARGV],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, "PYTHONPATH": str(cwd)},
    )
    return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")


def main() -> int:
    survivors: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        baseline = Path(tmp) / "baseline"
        shutil.copytree(ROOT, baseline, ignore=shutil.ignore_patterns(".git", "issues"))
        ok, output = run_tests(baseline)
        if not ok:
            print("baseline is already red -- fix the tests before mutating")
            print(output[-2000:])
            return 1
        print("baseline: PASS")

        for index, (name, filename, find, replace) in enumerate(MUTATIONS, start=1):
            work = Path(tmp) / f"mutant{index}"
            shutil.copytree(baseline, work)
            target = work / filename
            text = target.read_text(encoding="utf-8")
            if find not in text:
                print(f"  {index}. {name}: MUTATION DID NOT APPLY (pattern moved)")
                survivors.append(f"{name} (pattern not found)")
                continue
            target.write_text(text.replace(find, replace, 1), encoding="utf-8")

            passed, _output = run_tests(work)
            verdict = "SURVIVED" if passed else "caught"
            print(f"  {index}. {name}: {verdict}")
            if passed:
                survivors.append(name)

    print()
    if survivors:
        print(f"FAILED: {len(survivors)} mutant(s) survived -- the guard is decorative")
        for name in survivors:
            print(f"  - {name}")
        return 1
    print(f"PASSED: all {len(MUTATIONS)} mutants were caught")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
