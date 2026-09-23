#!/usr/bin/env python3
"""The reach acceptance criteria, checked against the live feeds.

Runs against whatever revision it is executed inside (it imports src/), so the
same file can be run on a base worktree for the before/after contrast. Prints
one line per criterion and exits non-zero if any fails.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.news_rank import ReachTable, load_reach_table  # noqa: E402
from src.sources.kev import fetch_kev_catalog  # noqa: E402
from src.sources.nvd import fetch_cves_by_id  # noqa: E402

TABLE = load_reach_table()

# The Cisco router-OS line, isolated: every entry whose token is an IOS
# spelling AND whose scope is Cisco. Scoring against a table holding ONLY
# these answers exactly the card's question -- does Cisco's ios entry take an
# Apple row? -- without confusing it with Apple's own iOS line, which happens
# to carry the same token under a different scope.
CISCO_IOS_ENTRIES = tuple(
    e for e in TABLE.entries
    if e.kind == "product" and e.scope == "cisco" and e.token.startswith("ios")
)
CISCO_ONLY = ReachTable(entries=CISCO_IOS_ENTRIES, source="cisco-ios-only")
UNSCOPED_IOS = ReachTable(
    entries=tuple(
        type(e)(token=e.token, weight=e.weight, note=e.note, kind="product", scope="")
        for e in CISCO_IOS_ENTRIES
    ),
    source="cisco-ios-unscoped",
)

results = []


def record(name, ok, detail):
    results.append((name, ok, detail))
    print(f"{'ok  ' if ok else 'FAIL'} {name}\n      {detail}")


class Row:
    """Item shaped the way a KEV row reaches the ranker: vendor + product."""

    def __init__(self, vendor, product):
        self.vendor = vendor
        self.product = product
        self.affected_products = ()
        self.vulnerable_cpes = ()
        self.platform_cpes = ()
        self.cna_products = ()
        self.description = ""


# --------------------------------------------------------------------------- #
# 1. Cisco's ios entry scores zero Apple rows in the live KEV catalogue
# --------------------------------------------------------------------------- #
catalog = fetch_kev_catalog()
rows = list(getattr(catalog, "entries", catalog))
apple_rows = [r for r in rows if "apple" in str(getattr(r, "vendor", "")).lower()]
hits = [
    (e.vendor, e.product) + CISCO_ONLY.score(Row(e.vendor, e.product))
    for e in apple_rows
    if CISCO_ONLY.score(Row(e.vendor, e.product))[0]
]
record(
    "1. Cisco ios scores no Apple row (live KEV)",
    not hits,
    f"live KEV rows {len(rows)}, Apple rows {len(apple_rows)}, "
    f"scored by the Cisco ios entries: {len(hits)} {hits[:5]}",
)

# counterfactual: the same entries with the scope removed ARE the defect
unscoped = [
    (e.vendor, e.product) + UNSCOPED_IOS.score(Row(e.vendor, e.product))
    for e in apple_rows
    if UNSCOPED_IOS.score(Row(e.vendor, e.product))[0]
]
print(f"      counterfactual: drop the vendor scope and the same entries take "
      f"{len(unscoped)} Apple rows {unscoped[:3]}")

# Cisco's own routers still score off that line
cisco_hits = [
    (e.vendor, e.product) + CISCO_ONLY.score(Row(e.vendor, e.product))
    for e in rows
    if "cisco" in str(getattr(e, "vendor", "")).lower()
    and CISCO_ONLY.score(Row(e.vendor, e.product))[0]
]
print(f"      Cisco rows still scored by the ios line: {len(cisco_hits)} {cisco_hits[:3]}")
print(f"      Apple rows keep their own weight: "
      f"{[(e.vendor, e.product) + TABLE.score(Row(e.vendor, e.product)) for e in apple_rows[:3]]}")

# --------------------------------------------------------------------------- #
# 2-4. three named live CVEs
# --------------------------------------------------------------------------- #
WANTED = ["CVE-2016-15059", "CVE-2020-1472", "CVE-2026-84388"]
items = {i.cve_id.upper(): i for i in fetch_cves_by_id(WANTED)}

expectations = [
    ("2. CVE-2016-15059 Net-IDN-Encode scores 0, not 44 via .net",
     "CVE-2016-15059", lambda w, t: w == 0),
    ("3. CVE-2020-1472 keeps its full windows weight",
     "CVE-2020-1472", lambda w, t: (w, t) == (100, "windows")),
    ("4. CVE-2026-84388 FortiPAM Chrome Extension scores 0, not 98",
     "CVE-2026-84388", lambda w, t: w == 0),
]
for name, cve_id, ok_fn in expectations:
    item = items.get(cve_id)
    if item is None:
        record(name, False, f"{cve_id} not returned by the live NVD API")
        continue
    weight, token = TABLE.score(item)
    record(
        name, ok_fn(weight, token),
        f"{cve_id} reach={weight} match={token!r} "
        f"products={list(item.affected_products)[:4]} "
        f"cna={list(item.cna_products)[:4]}",
    )

print()
bad = [n for n, ok, _ in results if not ok]
print(f"{len(results) - len(bad)}/{len(results)} criteria hold" + (f"; failed: {bad}" if bad else ""))

out = Path(sys.argv[1]) if len(sys.argv) > 1 else None
if out is not None:
    out.write_text(
        json.dumps([{"criterion": n, "ok": ok, "detail": d} for n, ok, d in results], indent=2)
    )
    print(f"wrote {out}")
sys.exit(1 if bad else 0)
