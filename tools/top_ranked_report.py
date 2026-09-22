#!/usr/bin/env python3
"""Show the top N ranked items of a recorded window, with their labels/keys.

    python3 tools/top_ranked_report.py DIR [N]

Answers "would the one-per-product cap have anything to bite on here?" by
printing, for each of the top items the ranker would ship from the recorded
tier-2 pool: the product labels, the vulnerable-CPE product keys, and the
reach token.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.sources import nvd  # noqa: E402
from src.news_rank import rank_news  # noqa: E402

out_dir = Path(sys.argv[1])
count = int(sys.argv[2]) if len(sys.argv) > 2 else 10

items = []
for path in sorted(out_dir.glob("nvd_window_page*.json")):
    payload = json.loads(path.read_text(encoding="utf-8"))
    for entry in payload.get("vulnerabilities") or []:
        item = nvd.parse_vulnerability(entry)
        if item is not None:
            items.append(item)

ranked = rank_news(items, None, limit=len(items))
rows = []
for position, item in enumerate(ranked[:count], start=1):
    rows.append({
        "position": position,
        "cve_id": item.cve_id,
        "severity": item.severity,
        "cvss_score": item.cvss_score,
        "reach": item.reach,
        "reach_match": item.reach_match,
        "product_keys": [list(k) for k in item.product_keys],
        "affected_products": list(item.affected_products)[:4],
    })
print(json.dumps({"parsed": len(items), "top": rows}, indent=2))
