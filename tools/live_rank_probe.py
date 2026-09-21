"""Live end-to-end probe: fetch, dedupe, rank, and report what the rule did.

Not part of the test suite -- the suite's rank module is deterministic and
offline on purpose. This is the manual check that the rule behaves against the
real NVD feed and the real CISA catalogue:

    PYTHONPATH=. python3 tools/live_rank_probe.py [days] [max_items]
"""

from __future__ import annotations

import sys
from collections import Counter

from src.dedupe import dedupe_by_cve_id
from src.news_rank import load_reach_table, rank_news
from src.sources.kev import fetch_kev_catalog
from src.sources.nvd import fetch_recent_cves


def main() -> int:
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 21
    max_items = int(sys.argv[2]) if len(sys.argv) > 2 else 600

    feed = dedupe_by_cve_id(fetch_recent_cves(days=days, max_items=max_items))
    kev = fetch_kev_catalog()
    table = load_reach_table()
    print(feed.summary())
    print(f"kev catalogue: {len(kev)} entries | reach table: {len(table)} tokens")

    everything = rank_news(feed.items, kev, limit=10**6)
    print("tier counts:", dict(Counter(r.tier for r in everything)))
    rated = [r for r in everything if r.reach]
    print(f"reach-rated: {len(rated)}/{len(everything)}")
    print("top reach tokens:", Counter(r.reach_match for r in rated).most_common(8))

    print("\ntoday's issue:")
    for position, chosen in enumerate(rank_news(feed.items, kev), start=1):
        print(
            f"{position}. tier {chosen.tier}  {chosen.cve_id:18} "
            f"{chosen.severity or '-':8} {chosen.cvss_score}  "
            f"reach {chosen.reach} {chosen.reach_match or '(unrated)'}"
        )
        print(f"     {chosen.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
