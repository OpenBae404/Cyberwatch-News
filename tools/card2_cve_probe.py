#!/usr/bin/env python3
"""The four CVEs named on the reach card, scored by whatever revision runs this.

    python3 tools/card2_cve_probe.py [--json OUT] [--cache PATH]

Card 2 states four specific behaviours, three of them as "N rather than M".
The "rather than M" half is a claim about the OLD code and cannot be shown by
running the new one, so this file is written to run unchanged inside a
`git archive` tree of the base revision: it imports only `load_reach_table`
and `ReachTable.score`, which both revisions expose identically, and it takes
its input from `--cache` so the base and the tip score the same fetched bytes
rather than two different NVD responses.

It also carries the Cisco-ios-vs-Apple check as its own implementation rather
than importing the implementer's: the entries whose token is an IOS spelling
scoped to Cisco are isolated into a table of their own and scored against
every Apple row of the live KEV catalogue.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.news_rank import load_reach_table  # noqa: E402

WANTED = ["CVE-2016-15059", "CVE-2020-1472", "CVE-2026-84388"]


class Row:
    def __init__(self, vendor, product):
        self.vendor = vendor
        self.product = product
        self.affected_products = ()
        self.vulnerable_cpes = ()
        self.platform_cpes = ()
        self.cna_products = ()
        self.description = ""


class Item:
    """An NVD item replayed from cached JSON, with the fields reach reads."""

    def __init__(self, blob):
        self.cve_id = blob["cve_id"]
        self.affected_products = tuple(blob["affected_products"])
        self.vulnerable_cpes = tuple(blob["vulnerable_cpes"])
        self.platform_cpes = tuple(blob["platform_cpes"])
        self.cna_products = tuple(tuple(p) for p in blob["cna_products"])
        self.description = blob.get("description", "")
        self.vendor = blob.get("vendor", "")
        self.product = blob.get("product", "")


def fetch(cache: Path | None) -> tuple[dict, list[dict]]:
    if cache is not None and cache.exists():
        blob = json.loads(cache.read_text(encoding="utf-8"))
        return blob["cves"], blob["kev_rows"]

    from src.sources.kev import fetch_kev_catalog  # noqa: E402  network
    from src.sources.nvd import fetch_cves_by_id  # noqa: E402  network

    cves = {}
    for item in fetch_cves_by_id(WANTED):
        cves[item.cve_id.upper()] = {
            "cve_id": item.cve_id,
            "affected_products": list(item.affected_products),
            "vulnerable_cpes": list(item.vulnerable_cpes),
            "platform_cpes": list(item.platform_cpes),
            "cna_products": [list(p) for p in item.cna_products],
            "description": getattr(item, "description", ""),
        }
    catalog = fetch_kev_catalog()
    kev_rows = [
        {"cve_id": str(e.cve_id), "vendor": str(e.vendor), "product": str(e.product)}
        for e in getattr(catalog, "entries", catalog)
    ]
    if cache is not None:
        cache.write_text(json.dumps({"cves": cves, "kev_rows": kev_rows}, indent=1),
                         encoding="utf-8")
    return cves, kev_rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="card2_cve_probe.py")
    parser.add_argument("--cache", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--label", default="")
    args = parser.parse_args(argv)

    cves, kev_rows = fetch(Path(args.cache) if args.cache else None)
    table = load_reach_table()

    # 1. Cisco's ios line against every Apple row of the live catalogue.
    cisco_ios = [
        e for e in table.entries
        if getattr(e, "kind", "product") == "product"
        and getattr(e, "scope", "") == "cisco"
        and e.token.startswith("ios")
    ]
    apple_rows = [r for r in kev_rows if "apple" in r["vendor"].lower()]
    if cisco_ios:
        only = type(table)(entries=tuple(cisco_ios), source="cisco-ios-only")
        apple_hits = [
            (r["vendor"], r["product"]) + only.score(Row(r["vendor"], r["product"]))
            for r in apple_rows if only.score(Row(r["vendor"], r["product"]))[0]
        ]
        cisco_hits = [
            r for r in kev_rows if "cisco" in r["vendor"].lower()
            and only.score(Row(r["vendor"], r["product"]))[0]
        ]
        ios_note = f"{len(cisco_ios)} cisco-scoped ios entries"
    else:
        # base revision: no scope field at all, the whole point of the defect
        ios_tokens = [e for e in table.entries if e.token.startswith("ios")]
        only = type(table)(entries=tuple(ios_tokens), source="ios-tokens")
        apple_hits = [
            (r["vendor"], r["product"]) + only.score(Row(r["vendor"], r["product"]))
            for r in apple_rows if only.score(Row(r["vendor"], r["product"]))[0]
        ]
        cisco_hits = [
            r for r in kev_rows if "cisco" in r["vendor"].lower()
            and only.score(Row(r["vendor"], r["product"]))[0]
        ]
        ios_note = f"{len(ios_tokens)} unscoped ios entries (revision has no vendor scope)"

    scores = {}
    for cve_id in WANTED:
        blob = cves.get(cve_id)
        if blob is None:
            scores[cve_id] = {"error": "not returned by NVD"}
            continue
        weight, token = table.score(Item(blob))
        scores[cve_id] = {
            "reach": weight, "match": token,
            "products": list(blob["affected_products"])[:4],
        }

    report = {
        "label": args.label,
        "cisco_ios_entries": ios_note,
        "apple_rows": len(apple_rows),
        "apple_rows_scored_by_cisco_ios": len(apple_hits),
        "apple_hits_sample": apple_hits[:3],
        "cisco_rows_scored_by_that_line": len(cisco_hits),
        "cves": scores,
    }
    print(f"[{args.label or 'this revision'}] {ios_note}")
    print(f"  Apple KEV rows {len(apple_rows)}; scored by Cisco's ios line: "
          f"{len(apple_hits)} {apple_hits[:3]}")
    print(f"  Cisco rows still scored by that line: {len(cisco_hits)}")
    for cve_id, res in scores.items():
        print(f"  {cve_id:16} {res}")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
