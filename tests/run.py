#!/usr/bin/env python3
"""Run the CyberWatch test suite.

    python3 tests/run.py            # everything, including the live NVD test
    python3 tests/run.py --offline  # skip the test that needs the network

Exit code 0 only if every selected test passed. Anything else is a non-zero
exit -- including the live feed being unreachable, which is reported as a
failure rather than a skip so a green run always means the live check
actually ran.

The suite is two kinds of test:

  offline  deterministic, no network, runs in milliseconds
           - tests/test_dedupe.py           unit tests for the collapse
           - tests/test_nvd_vulnerable_flag.py  the CPE vulnerable-flag split
           - tests/test_rank.py             smoke script for the ranker
           - tests/test_rank_strict.py      CPE equality: the Dell regression
                                            and docker vs dockerfile_parser
           - tests/test_negative_control.py the control, plus its mutant
           - tests/test_render_fields.py    four labelled fields per item
           - tests/test_render_reason.py    every item says in words whether it
                                            is known-exploited or severity-
                                            chosen, and KEV items look different
           - tests/test_render_llm.py       the summarisation call transmits
                                            enable_thinking=false (asserted on
                                            the request bytes), and a model
                                            that answers nothing is announced
                                            loudly instead of silently falling
                                            back to raw NVD text
           - tests/test_render_empty.py     zero matches renders an honest,
                                            unpadded document
           - tests/test_kev_source.py       TestKevParsing: the KEV parser,
                                            its lookup and its error contract
           - tests/test_news_rank.py        the two-tier selection: KEV outranks
                                            severity, severity outranks reach,
                                            cap of five, quiet-KEV day still ships
           - tests/test_run_entrypoint.py   run.py end to end on stubbed feeds:
                                            a dated issue is written, a KEV
                                            outage exits non-zero and writes
                                            nothing, the window is never lastMod
           - tools/mutation_check.py        breaks src/rank.py and checks the
                                            control goes red

  live     hits the real NVD API and the real CISA KEV feed, takes about a
           minute
           - tests/test_dedupe_live.py      pre-count > post-count for real
           - tests/test_kev_source.py       TestKevLiveFeed: the live CISA
                                            catalogue's shape and dates

Offline first: if the ranker or the renderer is broken, there is no reason to
spend a minute on the network to find out.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

OFFLINE = [
    ("unit: dedupe", ["-m", "unittest", "tests.test_dedupe", "-v"]),
    ("render: four labelled fields", ["-m", "unittest", "tests.test_render_fields", "-v"]),
    ("render: why each item is in the issue",
     ["-m", "unittest", "tests.test_render_reason", "-v"]),
    # The LLM path: the flag that makes the reasoning model answer at all, and
    # the loud failure when it does not. Placed next to the other render tests
    # because it is the same stage; kept separate because it is the only one
    # that asserts on transmitted bytes.
    ("render: the LLM writes, and silence is loud",
     ["-m", "unittest", "tests.test_render_llm", "-v"]),
    ("kev: parser and error contract",
     ["-m", "unittest", "tests.test_kev_source.TestKevParsing", "-v"]),
    ("rank: the two-tier newsletter selection",
     ["-m", "unittest", "tests.test_news_rank", "-v"]),
    ("entrypoint: one command, a dated issue, a loud KEV outage",
     ["-m", "unittest", "tests.test_run_entrypoint", "-v"]),
    # Breaks the KEV-outage guard four ways on a throwaway copy and asserts the
    # entrypoint tests go red each time. In the suite on purpose: the guard's
    # whole job is to prevent a run that otherwise looks healthy, so a test
    # nobody has watched fail is not evidence.
    ("mutation: the KEV-outage guard is load-bearing",
     ["tools/mutation_entrypoint_check.py"]),
    # Breaks src/rank.py on a throwaway copy and asserts the control goes red.
    # In the suite on purpose: a control nobody re-proves is a control that
    # quietly stops working.
    # Same idea for the zero-match document: pads it on a throwaway copy and
    # asserts tests/test_render_empty.py goes red.
    # And for strict matching: relaxes equality three ways on a throwaway copy
    # and asserts tests/test_rank_strict.py goes red each time.
]

LIVE = [
    ("live: dedupe on the real NVD feed",
     ["-m", "unittest", "tests.test_dedupe_live", "-v"]),
    ("live: the real CISA KEV catalogue",
     ["-m", "unittest", "tests.test_kev_source.TestKevLiveFeed", "-v"]),
]


def run_one(name: str, argv: list[str]) -> tuple[bool, float, str]:
    started = time.time()
    proc = subprocess.run(
        [sys.executable, *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    elapsed = time.time() - started
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, elapsed, output


def main() -> int:
    offline_only = "--offline" in sys.argv
    plan = OFFLINE + ([] if offline_only else LIVE)

    print(f"CyberWatch test suite -- {len(plan)} module(s)")
    if offline_only:
        print("  --offline: the live NVD test is NOT running, so the dedupe")
        print("  acceptance criterion is NOT covered by this run.")
    print("=" * 72)

    failures: list[str] = []
    for name, argv in plan:
        print(f"\n>>> {name}")
        ok, elapsed, output = run_one(name, argv)
        print(output.rstrip())
        verdict = "PASS" if ok else "FAIL"
        print(f"<<< {verdict}  ({elapsed:.1f}s)")
        if not ok:
            failures.append(name)

    print("\n" + "=" * 72)
    if failures:
        print(f"FAILED: {len(failures)} of {len(plan)} module(s)")
        for name in failures:
            print(f"  - {name}")
        return 1
    scope = "offline only" if offline_only else "offline + live"
    print(f"PASSED: all {len(plan)} module(s) ({scope})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
