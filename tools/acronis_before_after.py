#!/usr/bin/env python3
"""Fetch one CVE live and score its reach both ways: old surface vs new.

    python3 tools/acronis_before_after.py CVE-2026-87886 --out DIR

The card's defect is a single record. This pulls that record from the live NVD
API, saves the raw JSON, and scores it twice:

  * **old surface** -- `affected_products` plus `cpe_criteria`, the union of
    vulnerable and platform CPEs, as `_reach_haystack` read it before the fix
  * **new surface** -- what the shipping ranker scores now

The old scoring is reconstructed here, in the tool, from the same reach table;
it is not resurrected in `src/`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.sources import nvd  # noqa: E402
from src.news_rank import _cpe_vendor_product, _normalise, _resolve_reach  # noqa: E402


def old_haystack(item) -> str:
    """`_reach_haystack` as it was before the fix: the union surface."""
    parts = list(item.affected_products)
    for criteria in item.cpe_criteria:
        vendor, product = _cpe_vendor_product(criteria)
        if vendor:
            parts.append(vendor)
        if product:
            parts.append(product)
    joined = " ".join(p for p in (_normalise(x) for x in parts) if p)
    return f" {joined} " if joined else ""


def old_score(table, item) -> tuple[int, str]:
    haystack = old_haystack(item)
    best_weight, best_token = 0, ""
    for entry in table.entries:
        if entry.weight <= best_weight:
            break
        if f" {entry.token} " in haystack:
            best_weight, best_token = entry.weight, entry.token
    return best_weight, best_token


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="acronis_before_after.py")
    parser.add_argument("cve_id")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = nvd._get_json(f"{nvd.API_URL}?cveId={args.cve_id}", None, 45.0)
    (out_dir / f"{args.cve_id}.json").write_text(json.dumps(payload), encoding="utf-8")

    entries = payload.get("vulnerabilities") or []
    if not entries:
        print(f"{args.cve_id}: NVD returned no record", file=sys.stderr)
        return 1
    item = nvd.parse_vulnerability(entries[0])
    if item is None:
        print(f"{args.cve_id}: record did not parse", file=sys.stderr)
        return 1

    table = _resolve_reach(None)
    old_weight, old_token = old_score(table, item)
    new_weight, new_token = table.score(item)

    print(json.dumps({
        "cve_id": item.cve_id,
        "affected_products": list(item.affected_products),
        "vulnerable_cpes": list(item.vulnerable_cpes),
        "platform_cpes": list(item.platform_cpes),
        "old_reach": {"weight": old_weight, "token": old_token},
        "new_reach": {"weight": new_weight, "token": new_token},
        "defect_reproduced_on_old_surface": old_token == "linux kernel",
        "defect_gone_on_new_surface": new_token != "linux kernel",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
