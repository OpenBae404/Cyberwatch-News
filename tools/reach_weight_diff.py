#!/usr/bin/env python3
"""Prove the reach WEIGHTS did not move between two revisions of the table.

The card's criterion is "every weight in data/software_reach.txt is unchanged,
proven by a diff of the numbers". The matching change adds alternative
spellings to lines that already carried their number, so a naive line diff is
noisy: the line `62   fortinet` becomes `62   vendor:fortinet`. This tool
therefore reports three things:

  1. the weight multiset, line by line -- the numbers themselves;
  2. every old token, and what carries its weight now (the same token, or a
     declared re-spelling of it);
  3. any weight that appears in one revision and not the other.

Usage: python3 tools/reach_weight_diff.py <rev|WORKTREE> <rev|WORKTREE>
"""
from __future__ import annotations

import collections
import re
import subprocess
import sys

# How a token was RE-SPELLED by the matching change. A company that may no
# longer lead a product name is written vendor: or brand:; a token two vendors
# share is scoped. Each entry says: this old token is now written this way, at
# the same weight.
RESPELLINGS = {
    "apache": "vendor:apache", "apple": "vendor:apple",
    "atlassian": "vendor:atlassian", "cisco": "vendor:cisco",
    "citrix": "vendor:citrix", "f5": "vendor:f5",
    "fortinet": "vendor:fortinet", "ivanti": "vendor:ivanti",
    "juniper": "vendor:juniper", "mozilla": "vendor:mozilla",
    "oracle": "vendor:oracle", "palo alto": "vendor:palo alto",
    "red hat": "vendor:red hat", "sap": "vendor:sap",
    "sonicwall": "vendor:sonicwall", "vmware": "vendor:vmware",
    "debian": "vendor:debian", "ubuntu": "ubuntu linux",
    "android": "brand:android", "asus": "brand:asus", "d-link": "brand:d-link",
    "netgear": "brand:netgear", "qnap": "brand:qnap",
    "synology": "brand:synology", "tp-link": "brand:tp-link",
    "ubiquiti": "brand:ubiquiti",
    "ios xe": "cisco/ios xe", "iphone os": "apple/ios",
    "esxi": "esxi", "fortios": "fortios", "log4j": "log4j",
    "macos": "macos", "microsoft edge": "microsoft edge",
    "pulse secure": "pulse secure", "rhel": "rhel",
}


def spellings(text):
    """[(weight, token)] -- one entry per SPELLING, comma-splitting each line."""
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not re.match(r"^\d+$", parts[0]):
            continue
        for token in parts[1].split(","):
            token = token.strip().lower()
            if token:
                out.append((int(parts[0]), token))
    return out


def lines(text):
    """[weight] -- one entry per LINE, which is one reach claim."""
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        parts = line.split(None, 1)
        if len(parts) == 2 and re.match(r"^\d+$", parts[0]):
            out.append(int(parts[0]))
    return out


def load(rev):
    if rev == "WORKTREE":
        with open("data/software_reach.txt") as handle:
            return handle.read()
    return subprocess.run(
        ["git", "show", f"{rev}:data/software_reach.txt"],
        capture_output=True, text=True, check=True).stdout


a, b = sys.argv[1], sys.argv[2]
ta, tb = load(a), load(b)

# 1. the numbers
la, lb = lines(ta), lines(tb)
ca, cb = collections.Counter(la), collections.Counter(lb)
print(f"reach claims (lines): {a} {len(la)}   {b} {len(lb)}")
print(f"weight multiset identical: {ca == cb}")
for weight in sorted(set(ca) | set(cb)):
    if ca[weight] != cb[weight]:
        print(f"  weight {weight}: {ca[weight]} line(s) -> {cb[weight]}")

# 2. every old token accounted for
sa = {t: w for w, t in spellings(ta)}
sb = {t: w for w, t in spellings(tb)}
moved = {t: (sa[t], sb[t]) for t in set(sa) & set(sb) if sa[t] != sb[t]}
print(f"\ntokens present in both, weight changed: {moved or 'none'}")

unaccounted = []
respelled = []
for token, weight in sorted(sa.items()):
    if sb.get(token) == weight:
        continue
    new = RESPELLINGS.get(token)
    if new and sb.get(new) == weight:
        respelled.append((token, new, weight))
    else:
        unaccounted.append((token, weight, sb.get(token), new, sb.get(new or "")))

print(f"\nold tokens still spelled the same, same weight: "
      f"{len(sa) - len(respelled) - len(unaccounted)}")
print(f"old tokens re-spelled at the SAME weight: {len(respelled)}")
for token, new, weight in respelled:
    print(f"  {weight:3d}  {token!r} -> {new!r}")
print(f"\nold tokens NOT accounted for: {len(unaccounted)}")
for row in unaccounted:
    print(f"  {row}")

added = sorted(t for t in set(sb) - set(sa)
               if t not in {n for _, n, _ in respelled})
print(f"\nspellings added at an existing weight: {len(added)}")
for token in added:
    print(f"  {sb[token]:3d}  {token!r}")

ok = ca == cb and not moved and not unaccounted
print(f"\nVERDICT: {'weights unchanged' if ok else 'A WEIGHT MOVED'}")
sys.exit(0 if ok else 1)
