#!/usr/bin/env python3
"""Print one sample issue: a known-exploited item next to a severity-chosen one.

    PYTHONPATH=. python3 tools/render_reason_sample.py

Manual eyeball check, not a suite member: the automated assertions live in
tests/test_render_reason.py. This exists so a human can see, on one page,
that the two kinds of item do not look alike.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.news_rank import rank_news  # noqa: E402
from src.render import render_issue  # noqa: E402

UTC = timezone.utc


@dataclass(frozen=True)
class Item:
    cve_id: str
    description: str
    cvss_severity: str
    cvss_score: float
    affected_products: tuple[str, ...] = ()
    published: datetime = datetime(2026, 9, 20, 6, 0, tzinfo=UTC)
    cvss_version: str = "3.1"
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cpe_criteria: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    url: str = ""


@dataclass(frozen=True)
class Kev:
    cve_id: str
    label: str = "Acme Widget Server"
    date_added: date = date(2026, 9, 19)
    known_ransomware: bool = True


ITEMS = [
    Item("CVE-2026-1111", "Authentication bypass in Acme Widget Server.",
         "MEDIUM", 5.5, ("Acme Widget Server",)),
    Item("CVE-2026-2222", "Heap overflow in the nginx HTTP/3 module.",
         "CRITICAL", 9.8, ("F5 nginx",)),
    Item("CVE-2026-3333", "Privilege escalation in the Docker daemon.",
         "HIGH", 7.8, ("Docker Docker",)),
]


def main() -> int:
    chosen = rank_news(ITEMS, [Kev("CVE-2026-1111")])
    print(render_issue(chosen, use_llm=False, issue_date=date(2026, 9, 21),
                       total_considered=412))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
