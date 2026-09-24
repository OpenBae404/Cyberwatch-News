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
                                            cap of five, quiet-KEV day still ships,
                                            and reach matched at the HEAD of a
                                            product name, per vendor
           - tests/test_run_entrypoint.py   run.py end to end on stubbed feeds:
                                            a dated issue is written, a KEV
                                            outage exits non-zero and writes
                                            nothing, the window is never lastMod
           - tests/test_kev_scored_diff.py  the reach-change audit can return
                                            both verdicts: a product the table
                                            still prices losing its score is a
                                            regression, a vendor wildcard
                                            losing one is not
           - tests/test_site.py            the static site: one page and one
                                            index entry per issue, no markdown
                                            marker on any page, a CVE
                                            description full of angle brackets
                                            escaped, feed.xml parses with one
                                            item per issue, and a rebuild with
                                            no new issue changes no byte
           - tests/test_publish.py         the publish-time audit refuses each
                                            kind of disclosure and cannot be
                                            talked out of a credential; the
                                            launchd plist parses and the daily
                                            runner is valid bash
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
    # The audit instrument's own pass rule: a reach figure with no vulnerable
    # CPE behind it must fail the run, whichever surface it came in through.
    # In the suite because an instrument that cannot say no is not evidence.
    ("audit: the live reach audit can fail",
     ["-m", "unittest", "tests.test_live_reach_audit", "-v"]),
    # The same standard for the instrument that grades the reach CHANGE rather
    # than one issue: kev_scored_diff.py decides whether a lost score is the
    # narrowing working or software quietly losing a weight the table still
    # prices. Both verdicts are exercised on crafted pairs, including the
    # false positive the predicate actually produced once.
    ("audit: the reach-change diff can fail",
     ["-m", "unittest", "tests.test_kev_scored_diff", "-v"]),
    # Delivery. The site is the only stage whose output is read by strangers, so
    # its tests are about output rather than intent: one page per issue, no
    # markdown marker on any page, a CVE description full of angle brackets
    # escaped, a feed that parses, and a rebuild that changes no byte.
    ("site: the static site is faithful, escaped and reproducible",
     ["-m", "unittest", "tests.test_site", "-v"]),
    # The publish-time audit and the launchd plist. The audit runs once, before
    # this repo becomes public, so it is tested the way the KEV guard is: each
    # kind of finding is planted and the audit must refuse it, and a secret must
    # not be allowlistable.
    ("publish: the public-repo audit can say no, and the plist parses",
     ["-m", "unittest", "tests.test_publish", "-v"]),
    # The daily run itself, executed rather than grepped: the real shell script
    # against stub stages in a throwaway repo, with a recording `git` on PATH, a
    # stub approve-gate whose exit code the test chooses, and a real bare
    # remote. Its guarantees are all about what it does NOT do -- no commit on a
    # feed outage, no commit on a quiet day, no push unless a human approved
    # this morning's issue -- and "no push happened" is equally true of a script
    # that cannot push at all, so the gate is also seen open once.
    ("daily: the unattended run commits narrowly and never publishes unapproved",
     ["-m", "unittest", "tests.test_daily_run", "-v"]),
    # Breaks the runner eleven ways on a throwaway copy -- push whenever a
    # remote exists, decide by environment variable instead of by a person, let
    # the environment name a rubber-stamp approver, publish when no approver is
    # installed, ask and ignore the answer -- and asserts
    # tests/test_daily_run.py goes red each time. The first two mutants are the
    # two gates this runner has already outlived.
    ("mutation: the daily run's refusals are load-bearing",
     ["tools/mutation_daily_check.py"]),
    # Breaks the KEV-outage guard four ways on a throwaway copy and asserts the
    # entrypoint tests go red each time. In the suite on purpose: the guard's
    # whole job is to prevent a run that otherwise looks healthy, so a test
    # nobody has watched fail is not evidence.
    ("mutation: the KEV-outage guard is load-bearing",
     ["tools/mutation_entrypoint_check.py"]),
    # Breaks the head-anchored reach rule three ways on a throwaway copy --
    # match anywhere in the name, stop mid-word, ignore the vendor scope --
    # and asserts tests/test_news_rank.py goes red each time. Those three ARE
    # the substring behaviour this card replaced, so a suite that stays green
    # under them is not holding the fix.
    ("mutation: the reach match rule is load-bearing",
     ["tools/mutation_reach_check.py"]),
    # Breaks the site generator ten ways on a throwaway copy -- escape after
    # formatting, publish the internal endpoint, take the feed date from the
    # clock, leave an orphan page -- and asserts tests/test_site.py goes red
    # each time. The escaping criterion especially needs this: an escaping test
    # passes trivially against a generator whose hostile input never reaches the
    # page.
    ("mutation: the site generator's guarantees are load-bearing",
     ["tools/mutation_site_check.py"]),
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
