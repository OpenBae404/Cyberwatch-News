#!/usr/bin/env python3
"""Are the new reach tests load-bearing?

Copies the tree to a throwaway dir, breaks the head-anchored match rule three
ways -- each one a return to a piece of the old substring behaviour -- and
asserts tests/test_news_rank.py goes RED every time. A test nobody has watched
fail is not evidence.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MUTATIONS = [
    (
        "a token may match anywhere in the name (the 'chrome' defect)",
        "src/news_rank.py",
        '    return name == token or name.startswith(f"{token} ")',
        '    return f" {name} ".find(f" {token} ") >= 0 or token in name.split()',
    ),
    (
        "a token may stop mid-word (the '.net' defect)",
        "src/news_rank.py",
        '    return name == token or name.startswith(f"{token} ")',
        '    return name.startswith(token)',
    ),
    (
        "the vendor scope on a token is ignored (the 'cisco ios' defect)",
        "src/news_rank.py",
        "                    (not entry.scope or candidate.vendor == entry.scope)",
        "                    True",
    ),
    (
        "any token may lead its vendor word (vendor wildcards come back)",
        "src/news_rank.py",
        "                vendor_word_ok = entry.token not in company_names",
        "                vendor_word_ok = True",
    ),
    (
        "no token may lead its vendor word (WordPress/Core unrated again)",
        "src/news_rank.py",
        "                vendor_word_ok = entry.token not in company_names",
        "                vendor_word_ok = False",
    ),
]

failures = []
for label, relpath, old, new in MUTATIONS:
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "tree"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "scratch", ".worktrees"))
        target = copy / relpath
        text = target.read_text()
        if text.count(old) != 1:
            print(f"SETUP FAIL {label}: anchor appears {text.count(old)} times")
            failures.append(label)
            continue
        target.write_text(text.replace(old, new))
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "tests.test_news_rank"],
            cwd=copy, capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(copy)},
        )
        went_red = proc.returncode != 0
        tail = [ln for ln in proc.stderr.splitlines() if ln.startswith("FAIL: ")]
        print(f"{'ok  ' if went_red else 'FAIL'} mutation: {label}")
        print(f"      exit {proc.returncode}, {len(tail)} test(s) red")
        for line in tail[:4]:
            print(f"        {line}")
        if not went_red:
            failures.append(label)

print()
print(f"{len(MUTATIONS) - len(failures)}/{len(MUTATIONS)} mutations caught"
      + (f"; survived: {failures}" if failures else ""))
sys.exit(1 if failures else 0)
