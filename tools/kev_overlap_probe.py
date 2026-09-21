#!/usr/bin/env python3
"""Can tier 1 ever fire? Measure the overlap the entrypoint depends on.

The issue is built from CVEs published in the last few days, and a CVE is
tier 1 only if it is also in the KEV catalogue. KEV entries are usually
CVEs that were published weeks or months earlier -- CISA lists them when
exploitation is observed, not when they are published.

If the overlap is empty in practice, the two-tier rule is decorative: the
newsletter would lead with severity every single day while claiming to lead
with exploitation.

    PYTHONPATH=. python3 tools/kev_overlap_probe.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.dedupe import dedupe_by_cve_id
from src.sources.kev import fetch_kev_catalog
from src.sources.nvd import fetch_recent_cves


def main() -> int:
    catalog = fetch_kev_catalog()
    print(f"KEV catalogue: {len(catalog)} entries")

    for days in (7, 30, 90):
        recent = catalog.added_since(days)
        print(f"  added in the last {days:>2} day(s): {len(recent)}")
        for entry in recent[:5]:
            print(f"    {entry.date_added}  {entry.cve_id:18} {entry.label}")

    for days in (2, 7):
        feed = list(dedupe_by_cve_id(
            fetch_recent_cves(days=days, max_items=600, by="published")
        ))
        overlap = [item for item in feed if catalog.contains(item.cve_id)]
        print(
            f"\npublished window {days} day(s): {len(feed)} deduped CVEs, "
            f"{len(overlap)} of them in KEV"
        )
        for item in overlap[:10]:
            print(f"    {item.cve_id}  {item.cvss_severity}")

    # The other direction: are the CVEs CISA listed this month recent enough
    # that a published-window fetch would ever have seen them?
    now = datetime.now(timezone.utc).date()
    recent = catalog.added_since(30)
    gaps = [
        (entry.cve_id, entry.date_added, (now - entry.date_added).days)
        for entry in recent if entry.date_added
    ]
    print(f"\nCVEs CISA listed in the last 30 days: {len(gaps)}")
    for cve_id, added, age in gaps[:15]:
        print(f"    {cve_id:18} listed {added} ({age} days ago)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
