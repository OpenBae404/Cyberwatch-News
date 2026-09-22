#!/usr/bin/env python3
"""What would a quiet-KEV day ship from this recorded window?

    python3 tools/quiet_kev_counterfactual.py DIR [N]

Tier 2 is the path the newsletter falls back to when CISA lists nothing new,
and it is the path the one-per-product cap was written for. This ranks the
recorded window with ``kev=None`` -- no tier-1 items at all -- and prints the
issue that would ship, so the cap's behaviour on tier 2 can be read directly
instead of inferred from a KEV-heavy day.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.sources import nvd  # noqa: E402
from src.news_rank import MAX_ITEMS, rank_news  # noqa: E402

out_dir = Path(sys.argv[1])
limit = int(sys.argv[2]) if len(sys.argv) > 2 else MAX_ITEMS

items = []
for path in sorted(out_dir.glob("nvd_window_page*.json")):
    payload = json.loads(path.read_text(encoding="utf-8"))
    for entry in payload.get("vulnerabilities") or []:
        item = nvd.parse_vulnerability(entry)
        if item is not None:
            items.append(item)

shipped = rank_news(items, None, limit=limit)
labels = Counter()
rows = []
for position, item in enumerate(shipped, start=1):
    first_label = (list(item.affected_products) or [""])[0]
    labels[first_label] += 1
    rows.append({
        "position": position,
        "cve_id": item.cve_id,
        "severity": item.severity,
        "cvss_score": item.cvss_score,
        "reach": item.reach,
        "reach_match": item.reach_match,
        "product_keys": [list(k) for k in item.product_keys],
        "affected_products": list(item.affected_products),
    })

repeats = {label: n for label, n in labels.items() if n > 1}
print(json.dumps({
    "parsed": len(items),
    "shipped": rows,
    "distinct_first_labels": len(labels),
    "first_labels_repeated": repeats,
    "one_product_dominates": bool(repeats),
}, indent=2))
