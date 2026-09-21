"""Live proof that tier 1 fires: rank real KEV-listed CVEs against real ones that are not.

The daily feed often contains no KEV-listed CVE at all -- KEV lists CVEs that
are *being exploited*, which is usually months after publication. That is
exactly why tier 2 exists, and it also means the daily probe
(tools/live_rank_probe.py) cannot demonstrate tier 1. This one can: it pulls
the newest KEV entries from CISA, pulls those same CVE records from NVD, mixes
them with the newest high-severity non-KEV CVEs, and prints the ranking.

    PYTHONPATH=. python3 tools/live_kev_tier_probe.py

Not part of the test suite: it needs the network and its input changes daily.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import date

from src.news_rank import rank_news
from src.sources.kev import fetch_kev_catalog
from src.sources.nvd import API_URL, fetch_recent_cves, parse_vulnerability


def fetch_by_id(cve_id: str):
    """One CVE record straight from NVD. Probe-only: the pipeline fetches windows."""
    url = f"{API_URL}?{urllib.parse.urlencode({'cveId': cve_id})}"
    request = urllib.request.Request(
        url, headers={"User-Agent": "cyberwatch-news/0.1", "Accept": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        body = json.loads(response.read().decode("utf-8", "replace"))
    for entry in body.get("vulnerabilities") or []:
        item = parse_vulnerability(entry)
        if item is not None:
            return item
    return None


def main() -> int:
    catalog = fetch_kev_catalog()
    newest = catalog.entries
    newest = sorted(
        (e for e in newest if e.date_added),
        key=lambda e: e.date_added or date.min,
        reverse=True,
    )[:3]
    print(f"KEV catalogue: {len(catalog)} entries; newest {len(newest)} taken as tier 1")

    kev_items = []
    for entry in newest:
        item = fetch_by_id(entry.cve_id)
        if item is not None:
            kev_items.append(item)
            print(
                f"  KEV {entry.cve_id:18} added {entry.date_added}  "
                f"{item.cvss_severity or '-':8} {item.cvss_score}  {entry.label}"
            )

    others = [
        item
        for item in fetch_recent_cves(days=7, max_items=120)
        if (item.cvss_score or 0) >= 9.0 and not catalog.contains(item.cve_id)
    ][:8]
    print(f"\nnon-KEV candidates with CVSS >= 9.0: {len(others)}")

    mixed = others + kev_items       # KEV last, so order cannot flatter the result
    print("\nranked:")
    for position, chosen in enumerate(rank_news(mixed, catalog), start=1):
        print(
            f"{position}. tier {chosen.tier}  {chosen.cve_id:18} "
            f"{chosen.severity or '-':8} {chosen.cvss_score}"
        )
        print(f"     {chosen.reason}")

    ranked = rank_news(mixed, catalog, limit=100)
    tiers = [r.tier for r in ranked]
    print(f"\ntier sequence: {tiers}")
    print("VERDICT:", "tier 1 leads" if tiers == sorted(tiers) and 1 in tiers
          else "TIER RULE DID NOT FIRE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
