#!/usr/bin/env python3
"""Why did the cap drop nothing? Count the product keys in a recorded feed.

    python3 tools/cap_coverage.py DIR

Reads the raw NVD pages recorded by ``tools/record_and_replay_cap.py``, parses
them with the shipping parser, and reports how many CVEs carry a vulnerable
CPE at all. An item with no vulnerable CPE has no product key and is exempt
from the one-per-product cap by design, so a feed of mostly key-less items
cannot exercise the cap no matter how many CVEs it holds.
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
from src.news_rank import _vulnerable_vendor_products  # noqa: E402

out_dir = Path(sys.argv[1])
items = []
for path in sorted(out_dir.glob("nvd_window_page*.json")):
    payload = json.loads(path.read_text(encoding="utf-8"))
    for entry in payload.get("vulnerabilities") or []:
        item = nvd.parse_vulnerability(entry)
        if item is not None:
            items.append(item)

keyed = 0
counts: Counter = Counter()
for item in items:
    pairs = [(v.lower(), p.lower()) for v, p in _vulnerable_vendor_products(item)]
    if pairs:
        keyed += 1
    for pair in pairs:
        counts[pair] += 1

repeated = {f"{v}:{p}": n for (v, p), n in counts.items() if n > 1}
print(json.dumps({
    "parsed": len(items),
    "with_vulnerable_cpe": keyed,
    "without_vulnerable_cpe": len(items) - keyed,
    "distinct_product_keys": len(counts),
    "product_keys_seen_more_than_once": repeated,
}, indent=2))
