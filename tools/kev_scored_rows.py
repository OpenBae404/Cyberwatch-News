#!/usr/bin/env python3
"""How many rows of the live CISA KEV catalogue does the reach table score?

    python3 tools/kev_scored_rows.py --save-rows DIR/kev_rows.json --json DIR/x.json
    python3 tools/kev_scored_rows.py --rows DIR/kev_rows.json --json DIR/y.json

The reach changes (AG-14) narrowed HOW a token matches, so the honest headline
number for the change is not "the tests pass" but "how much of the catalogue
still carries a reach figure, and how much did before". This tool prints that
count for whatever revision it is executed inside -- it imports only
`load_reach_table` and `ReachTable.score`, which both the pre-change base
(a7e051b) and master expose with the same signature, so the SAME file can be
copied into a `git archive` tree of the base and produce a comparable number.

The rows are the catalogue's own `vendor` / `product` fields, presented to the
scorer in a shim with no CPEs and no labels. That is deliberate: a KEV row is
what the newsletter's tier 1 is built from, and vendor/product is all a KEV
row states. `--rows` replays a saved catalogue so both revisions are scored
against identical bytes rather than two fetches minutes apart.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.news_rank import load_reach_table  # noqa: E402


class Row:
    """A KEV row as the ranker sees it: a vendor field and a product field."""

    def __init__(self, vendor, product):
        self.vendor = vendor
        self.product = product
        self.affected_products = ()
        self.vulnerable_cpes = ()
        self.platform_cpes = ()
        self.cna_products = ()
        self.description = ""


def load_rows(path: Path | None) -> list[dict]:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    from src.sources.kev import fetch_kev_catalog  # imported late: network

    catalog = fetch_kev_catalog()
    entries = list(getattr(catalog, "entries", catalog))
    return [
        {
            "cve_id": str(getattr(e, "cve_id", "")),
            "vendor": str(getattr(e, "vendor", "")),
            "product": str(getattr(e, "product", "")),
        }
        for e in entries
    ]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="kev_scored_rows.py")
    parser.add_argument("--rows", default=None, help="replay rows saved by --save-rows")
    parser.add_argument("--save-rows", default=None, help="write the fetched rows here")
    parser.add_argument("--json", default=None, help="write the per-row result here")
    parser.add_argument("--label", default="", help="name this revision in the output")
    args = parser.parse_args(argv)

    rows = load_rows(Path(args.rows) if args.rows else None)
    if args.save_rows:
        Path(args.save_rows).write_text(json.dumps(rows, indent=1), encoding="utf-8")

    table = load_reach_table()
    scored = []
    tokens: Counter[str] = Counter()
    for row in rows:
        weight, token = table.score(Row(row["vendor"], row["product"]))
        scored.append({**row, "reach": weight, "reach_match": token})
        if weight:
            tokens[token] += 1

    hits = [r for r in scored if r["reach"]]
    report = {
        "label": args.label,
        "rows": len(rows),
        "scored": len(hits),
        "unrated": len(rows) - len(hits),
        "distinct_tokens": len(tokens),
        "top_tokens": tokens.most_common(15),
        "per_row": scored,
    }
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"{args.label or 'this revision'}: {len(hits)} of {len(rows)} live KEV rows "
          f"scored ({len(rows) - len(hits)} unrated), {len(tokens)} distinct tokens")
    print(f"  top: {tokens.most_common(10)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
