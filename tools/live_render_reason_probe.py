"""Live proof that the reason line is right on REAL data, not fixtures.

Pulls the newest CISA KEV entries and those same CVE records from NVD, mixes
them with real non-KEV high-severity CVEs, ranks them, renders the issue, and
checks the rendered markdown:

  * every item block carries a "Why this is here" line;
  * the known-exploited items -- and only those -- carry the badge;
  * no block leaks the ranker's "tier N" vocabulary into the reason line.

    PYTHONPATH=. python3 tools/live_render_reason_probe.py

Not part of the test suite: it needs the network and its input changes daily.
The offline assertions live in tests/test_render_reason.py.
"""

from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_kev_tier_probe import fetch_by_id  # noqa: E402  (same tools/ dir)

from src.news_rank import rank_news  # noqa: E402
from src.render import (  # noqa: E402
    KEV_BADGE,
    KEV_LEAD,
    REASON_LABEL,
    SEVERITY_LEAD,
    render_issue,
)
from src.sources.kev import fetch_kev_catalog  # noqa: E402
from src.sources.nvd import fetch_recent_cves  # noqa: E402

_HEADING = re.compile(r"^## ", re.MULTILINE)


def blocks(document: str) -> list[str]:
    return _HEADING.split(document)[1:]


def reason_line(block: str) -> str:
    match = re.search(
        rf"^\*\*{re.escape(REASON_LABEL)}:\*\*[ \t]*(.*)$", block, re.MULTILINE
    )
    return match.group(1).strip() if match else ""


def main() -> int:
    catalog = fetch_kev_catalog()
    newest = sorted(
        (e for e in catalog.entries if e.date_added),
        key=lambda e: e.date_added or date.min,
        reverse=True,
    )[:2]

    kev_items = [item for item in (fetch_by_id(e.cve_id) for e in newest) if item]
    others = [
        item
        for item in fetch_recent_cves(days=7, max_items=120)
        if (item.cvss_score or 0) >= 9.0 and not catalog.contains(item.cve_id)
    ][:5]
    print(f"KEV catalogue: {len(catalog)} entries")
    print(f"real KEV records fetched: {[i.cve_id for i in kev_items]}")
    print(f"real non-KEV CVSS>=9.0 records: {[i.cve_id for i in others]}")

    if not kev_items:
        print("VERDICT: INCONCLUSIVE -- NVD returned no record for the newest KEV ids")
        return 1

    chosen = rank_news(others + kev_items, catalog)
    document = render_issue(chosen, use_llm=False)
    print("\n" + document)

    problems: list[str] = []
    kev_ids = {i.cve_id for i in kev_items}
    for position, block in enumerate(blocks(document), start=1):
        line = reason_line(block)
        cve = re.search(r"CVE-\d{4}-\d+", block)
        cve_id = cve.group(0) if cve else "?"
        if not line:
            problems.append(f"item #{position} {cve_id}: no reason line")
            continue
        if re.search(r"(?i)\btier\s*\d", line):
            problems.append(f"item #{position} {cve_id}: leaks tier vocabulary")
        is_kev = cve_id in kev_ids
        says_kev = KEV_LEAD.lower() in line.lower()
        if is_kev != says_kev:
            problems.append(
                f"item #{position} {cve_id}: KEV={is_kev} but the line says "
                f"{'known-exploited' if says_kev else SEVERITY_LEAD.lower()}"
            )
        if (KEV_BADGE in block) != is_kev:
            problems.append(f"item #{position} {cve_id}: badge does not match KEV={is_kev}")

    if problems:
        print("VERDICT: FAILED")
        for problem in problems:
            print("  -", problem)
        return 1
    print(f"VERDICT: OK -- {len(blocks(document))} real items, each labelled correctly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
