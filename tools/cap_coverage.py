#!/usr/bin/env python3
"""What does the one-per-product cap actually key on in a recorded feed?

    python3 tools/cap_coverage.py DIR

Reads the raw NVD pages recorded by ``tools/record_and_replay_cap.py``, parses
them with the shipping parser, and reports how many CVEs carry a product key at
all. An item with no key is exempt from the one-per-product cap by design, so a
feed of mostly key-less items cannot exercise the cap no matter how many CVEs
it holds -- which is exactly what a CPE-only key produced on this window.

Both surfaces are counted, so the difference between them is readable:

  * ``with_vulnerable_cpe`` -- CVEs NVD has analysed into a vulnerable CPE
  * ``with_product_key``    -- CVEs the cap can key on now, from any structured
                               source (vulnerable CPEs, CNA affected rows, the
                               KEV row's own vendor/product)
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
from src.news_rank import _vulnerable_vendor_products, product_keys  # noqa: E402

out_dir = Path(sys.argv[1])
items = []
for path in sorted(out_dir.glob("nvd_window_page*.json")):
    payload = json.loads(path.read_text(encoding="utf-8"))
    for entry in payload.get("vulnerabilities") or []:
        item = nvd.parse_vulnerability(entry)
        if item is not None:
            items.append(item)

with_cpe = 0
keyed = 0
counts: Counter = Counter()
for item in items:
    if _vulnerable_vendor_products(item):
        with_cpe += 1
    pairs = product_keys(item)
    if pairs:
        keyed += 1
    for pair in pairs:
        counts[pair] += 1

repeated = {f"{v}:{p}": n for (v, p), n in counts.items() if n > 1}
print(json.dumps({
    "parsed": len(items),
    "with_vulnerable_cpe": with_cpe,
    "without_vulnerable_cpe": len(items) - with_cpe,
    "with_product_key": keyed,
    "without_product_key": len(items) - keyed,
    "distinct_product_keys": len(counts),
    "product_keys_seen_more_than_once": repeated,
}, indent=2))
