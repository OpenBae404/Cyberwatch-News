#!/usr/bin/env python3
"""Compare two `kev_scored_rows.py` reports and classify every change.

    python3 tools/kev_scored_diff.py BEFORE.json AFTER.json [--json OUT]

The headline count (942 -> 750) is not by itself a verdict: a reach change
that narrows matching is *supposed* to unrate rows, and the only question that
matters is which rows and why. Every row whose score changed is sorted into
one of four classes, decided here and not taken from any report:

  lost-vendor-wildcard   scored before through a token that is the row's own
                         vendor word, and the table now writes that name as a
                         `vendor:`/`brand:` line -- i.e. the company-is-not-
                         software rule firing, which is the point of AG-14.
  lost-never-named       the table no longer prices any product token that
                         could lead this row's names. The software was never
                         named; its old score came from a substring of some
                         other line. Accepted, but it must be visible.
  lost-still-named       THE REGRESSION CLASS. The table still prices a
                         product token equal to this row's vendor word or
                         leading its product name, and the row scores 0
                         anyway. This must be empty; the tool exits non-zero
                         if it is not.
  gained / retokened     a row that now scores, or scores through a different
                         token.

The "still named" predicate is computed from the AFTER revision's own reach
file, read as text: any `<weight> <token>` line that is not a `vendor:` or
`brand:` line is a name the file claims is software.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NON_ALNUM = re.compile(r"[^a-z0-9]+")
SEPARATORS = re.compile(r"[\s,/|_]+")


def norm(text: str) -> str:
    return NON_ALNUM.sub(" ", str(text).lower()).strip()


def product_tokens(reach_file: Path) -> set[str]:
    """Names the file prices as SOFTWARE (not vendor:/brand: lines)."""
    tokens: set[str] = set()
    for line in reach_file.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        head, _, rest = line.partition(" ")
        if not head.isdigit():
            continue
        for raw in rest.split(","):
            raw = raw.strip()
            if not raw or raw.startswith(("vendor:", "brand:")):
                continue
            if "/" in raw:          # scoped cisco/ios -- the bare name only
                raw = raw.split("/", 1)[1]
            token = norm(raw)
            if token:
                tokens.add(token)
    return tokens


def company_names(reach_file: Path) -> set[str]:
    names: set[str] = set()
    for line in reach_file.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        head, _, rest = line.partition(" ")
        if not head.isdigit():
            continue
        for raw in rest.split(","):
            raw = raw.strip()
            for prefix in ("vendor:", "brand:"):
                if raw.startswith(prefix):
                    name = norm(raw[len(prefix):])
                    if name:
                        names.add(name)
    return names


def leads(name: str, token: str) -> bool:
    """token leads name at a word boundary -- the rule the table documents."""
    name, token = norm(name), norm(token)
    if not name or not token:
        return False
    if name == token:
        return True
    return name.startswith(token + " ")


def still_named(row: dict, tokens: set[str]) -> str:
    """Return the token that should still price this row, or ''.

    Three ways a name in the file can be this row's software, and no fourth:

      * the token IS the row's whole vendor field ("WordPress" / "Core");
      * the token leads the product name ("windows" / "Windows Server 2019");
      * the token leads the vendor-qualified name AND reaches past the vendor
        word ("linux kernel" over "Linux" / "Kernel").

    The last clause is not decoration. Without it a token that covers only
    part of a multi-word vendor field counts -- "npm" over "Npm package /
    System Information Library for Node.JS" -- and the audit reports a
    regression on a row no reach rule would ever have scored that way.
    """
    vendor_word = norm(row.get("vendor", ""))
    product = norm(row.get("product", ""))
    qualified = f"{vendor_word} {product}".strip()
    for token in sorted(tokens):
        if vendor_word and token == vendor_word:
            return token
        if leads(product, token):
            return token
        if leads(qualified, token) and (
            token == vendor_word or token.startswith(vendor_word + " ")
        ):
            return token
    return ""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="kev_scored_diff.py")
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--reach-file", default=str(ROOT / "data" / "software_reach.txt"))
    parser.add_argument("--json", default=None)
    parser.add_argument("--detail", action="store_true",
                        help="list every classified row, not just the counts")
    args = parser.parse_args(argv)

    before = json.loads(Path(args.before).read_text(encoding="utf-8"))
    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    reach_file = Path(args.reach_file)
    tokens = product_tokens(reach_file)
    companies = company_names(reach_file)

    b = {r["cve_id"]: r for r in before["per_row"]}
    a = {r["cve_id"]: r for r in after["per_row"]}
    assert set(b) == set(a), "the two runs must score the same catalogue"

    buckets: dict[str, list[dict]] = {
        "lost-vendor-wildcard": [], "lost-never-named": [], "lost-still-named": [],
        "gained": [], "retokened": [],
    }
    for cve_id, old in b.items():
        new = a[cve_id]
        if old["reach"] == new["reach"] and old["reach_match"] == new["reach_match"]:
            continue
        row = {
            "cve_id": cve_id, "vendor": old["vendor"], "product": old["product"],
            "before": [old["reach"], old["reach_match"]],
            "after": [new["reach"], new["reach_match"]],
        }
        if not new["reach"] and old["reach"]:
            named = still_named(old, tokens)
            old_token = norm(old["reach_match"])
            if named:
                row["table_still_prices"] = named
                buckets["lost-still-named"].append(row)
            elif old_token == norm(old["vendor"]) or old_token in companies:
                buckets["lost-vendor-wildcard"].append(row)
            else:
                buckets["lost-never-named"].append(row)
        elif new["reach"] and not old["reach"]:
            buckets["gained"].append(row)
        else:
            buckets["retokened"].append(row)

    print(f"{before['label'] or args.before} -> {after['label'] or args.after}")
    print(f"  scored: {before['scored']} -> {after['scored']}  of {after['rows']} rows")
    for name, rows in buckets.items():
        print(f"  {name:22} {len(rows)}")
        if name.startswith("lost"):
            top = Counter(r["before"][1] for r in rows).most_common(6)
            if top:
                print(f"      by old token: {top}")
    for row in buckets["lost-still-named"]:
        print(f"      REGRESSION {row['cve_id']:16} {row['vendor']} / {row['product']}"
              f"  was {row['before']}  table still prices {row['table_still_prices']!r}")

    if args.detail:
        for name in ("lost-never-named", "gained"):
            print(f"\n--- {name} ({len(buckets[name])})")
            for row in buckets[name]:
                print(f"    {row['cve_id']:17} {row['vendor']} / {row['product']}"
                      f"   was {row['before']}  now {row['after']}")
        print("\n--- retokened, grouped by old -> new token")
        pairs = Counter(
            (r["before"][1], r["before"][0], r["after"][1], r["after"][0])
            for r in buckets["retokened"]
        )
        for (old, ow, new, nw), n in pairs.most_common():
            direction = "UP" if nw > ow else ("down" if nw < ow else "same")
            print(f"    {n:4}  {old!r} {ow} -> {new!r} {nw}   [{direction}]")

    report = {
        "before": before.get("label"), "after": after.get("label"),
        "scored_before": before["scored"], "scored_after": after["scored"],
        "counts": {k: len(v) for k, v in buckets.items()},
        **buckets,
    }
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1), encoding="utf-8")

    bad = len(buckets["lost-still-named"])
    print(f"\nVERDICT: {'CLEAN' if not bad else str(bad) + ' rows lost while still named'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
