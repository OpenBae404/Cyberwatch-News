#!/usr/bin/env python3
"""What does reach actually score on, in a recorded live window?

    python3 tools/reach_surface_census.py DIR

Reads the raw NVD pages recorded by ``tools/record_and_replay_cap.py`` and,
for every parsed CVE, records which surface produced its reach score:

  * ``vulnerable-cpe``  -- the token appears in a CPE NVD marks vulnerable
  * ``cna-label-only``  -- the token appears only in ``affected_products``,
    i.e. in a CNA-supplied ``affected`` row that carries no ``vulnerable``
    flag at all. `nvd.py` puts those rows' CPEs in ``platform`` but still
    lets their vendor/product string become a display label, and the ranker
    reads that field.
  * ``none``            -- reach 0

This is the number that says whether the vulnerable-CPE rule reaches the
tier-2 pool or only the KEV items.
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
from src.news_rank import (  # noqa: E402
    _normalise,
    _resolve_reach,
    _vulnerable_vendor_products,
)

out_dir = Path(sys.argv[1])
items = []
for path in sorted(out_dir.glob("nvd_window_page*.json")):
    payload = json.loads(path.read_text(encoding="utf-8"))
    for entry in payload.get("vulnerabilities") or []:
        item = nvd.parse_vulnerability(entry)
        if item is not None:
            items.append(item)

table = _resolve_reach(None)
verdicts: Counter = Counter()
examples: dict[str, list] = {}
labels_present = 0
for item in items:
    if item.affected_products:
        labels_present += 1
    weight, token = table.score(item)
    if not token:
        verdicts["none"] += 1
        continue
    padded = f" {token} "
    vuln_text = " " + " ".join(
        _normalise(f"{v} {p}") for v, p in _vulnerable_vendor_products(item)
    ) + " "
    verdict = "vulnerable-cpe" if padded in vuln_text else "cna-label-only"
    verdicts[verdict] += 1
    examples.setdefault(verdict, [])
    if len(examples[verdict]) < 5:
        examples[verdict].append({
            "cve_id": item.cve_id,
            "reach": weight,
            "token": token,
            "affected_products": list(item.affected_products)[:3],
            "n_vulnerable_cpes": len(item.vulnerable_cpes),
            "n_platform_cpes": len(item.platform_cpes),
        })

print(json.dumps({
    "parsed": len(items),
    "items_with_any_product_label": labels_present,
    "reach_surface": dict(verdicts),
    "examples": examples,
}, indent=2))
