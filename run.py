#!/usr/bin/env python3
"""Build today's CyberWatch Newsletter issue. One command, no arguments.

    python3 run.py

It wires the four stages that already exist in this repo:

    1. CISA KEV catalogue   src/sources/kev.py    tier 1 -- known exploited
    2. NVD, published window src/sources/nvd.py   tier 2 candidates
    3. dedupe + rank        src/dedupe.py, src/news_rank.py
    4. render               src/render.py

and writes ONE dated markdown file under ``issues/``.

Two rules this file exists to enforce, because nothing downstream can:

**A KEV outage is a hard failure.** ``rank_news`` accepts ``kev=None`` and
happily returns five items -- all of them tier 2. That is the correct
behaviour for a ranker and the wrong behaviour for a run: an issue built
without the catalogue is a severity-only issue that still *claims* nothing is
known-exploited. So the catalogue is fetched first, a failure or an
implausibly small catalogue aborts the run with a non-zero exit, and no file
is written. A quiet KEV day (a full catalogue with nothing new) is not an
outage -- that is exactly what tier 2 is for.

**The published window only — for tier 2.** ``lastMod`` puts a CVE from July
in today's issue because somebody edited its description (Plans.md). The
severity fetch is pinned to ``by="published"`` here and is never given the
choice. Tier 1 is fetched a different way on purpose: a CVE CISA listed this
week is news *because of the listing*, whatever its publication date, and it
is fetched by id. Measured on 2026-09-21: 0 of 181 CVEs in a 2-day published
window were in KEV, and 1 of 600 in a 7-day window, while CISA had listed 7
CVEs that week. A published-window-only run makes tier 1 unreachable and the
issue leads with severity every day while claiming to lead with exploitation.

Exit codes, so a scheduler can tell the failures apart:

    0  an issue was written
    2  KEV outage -- catalogue unreachable, malformed, or implausibly small
    3  NVD feed failure
    4  nothing to ship: the feeds worked and produced no candidate at all
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.dedupe import dedupe_by_cve_id                      # noqa: E402
from src.news_rank import MAX_ITEMS, rank_news               # noqa: E402
from src.render import LLMClient, render_issue               # noqa: E402
from src.sources.kev import KevError, fetch_kev_catalog      # noqa: E402
from src.sources.nvd import (                                # noqa: E402
    NvdError,
    fetch_cves_by_id,
    fetch_recent_cves,
)

__all__ = [
    "EmptyIssue",
    "FeedFailure",
    "IssueRun",
    "KevOutage",
    "RunFailure",
    "build_issue",
    "collect_candidates",
    "collect_kev_candidates",
    "load_kev",
    "main",
    "write_issue",
]

ISSUES_DIR = ROOT / "issues"
TITLE = "CyberWatch Newsletter"

# The published window, widened only if a short one is thin. Two days covers a
# normal day including a quiet weekend; seven is the last try before we admit
# there is nothing to ship.
WINDOW_DAYS = (2, 4, 7)
MAX_NVD_ITEMS = 600

# How far back a KEV *listing* still counts as today's news, and how many of
# those listings we are willing to spend NVD requests on. Seven days matches
# the newsletter's weekly rhythm: CISA lists a handful a week, and a CVE
# listed on Friday is still the story on Monday.
KEV_LOOKBACK_DAYS = 7
MAX_KEV_LOOKUPS = 12

# The live KEV catalogue has carried well over a thousand entries for years. A
# parse that succeeds but yields a handful of rows is a truncated or replaced
# document, not a quiet day -- treat it as an outage rather than silently
# ranking against a catalogue that has lost its contents.
MIN_KEV_ENTRIES = 100

# Card says the newsletter's LLM lives here. Overridable, because the renderer
# already falls back to raw NVD text when it is not reachable.
DEFAULT_LLM_BASE_URL = os.environ.get(
    "CYBERWATCH_LLM_BASE_URL", "http://localhost:8001/v1"
)


# --------------------------------------------------------------------------- #
# failures
# --------------------------------------------------------------------------- #

class RunFailure(RuntimeError):
    """A run that must not write an issue. Carries its own exit code."""

    exit_code = 1


class KevOutage(RunFailure):
    """Tier 1 was unavailable. Never degrade to a severity-only issue."""

    exit_code = 2


class FeedFailure(RunFailure):
    """NVD could not be read."""

    exit_code = 3


class EmptyIssue(RunFailure):
    """Both feeds worked and produced no candidate at all."""

    exit_code = 4


# --------------------------------------------------------------------------- #
# the result of one run
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class IssueRun:
    """Everything one run produced, so callers can report it without re-deriving."""

    markdown: str
    items: tuple[Any, ...]
    issue_date: date
    kev_entries: int
    window_days: int
    considered: int
    deduped: int
    known_exploited: int
    kev_recent: int = 0
    kev_fetched: int = 0
    path: Path | None = None

    def summary(self) -> str:
        return (
            f"{len(self.items)} item(s) "
            f"({self.known_exploited} known-exploited, "
            f"{len(self.items) - self.known_exploited} severity-chosen) "
            f"from {self.deduped} deduped CVEs of {self.considered} published in "
            f"the last {self.window_days} day(s); "
            f"KEV catalogue: {self.kev_entries} entries, {self.kev_recent} listed "
            f"in the last {KEV_LOOKBACK_DAYS} day(s), {self.kev_fetched} of those "
            f"pulled from NVD by id."
        )


# --------------------------------------------------------------------------- #
# stage 1 -- tier 1, and the loud failure
# --------------------------------------------------------------------------- #

def load_kev(
    fetch: Callable[..., Any] = fetch_kev_catalog,
    *,
    minimum: int = MIN_KEV_ENTRIES,
    timeout: float = 45.0,
) -> Any:
    """Fetch the KEV catalogue or raise :class:`KevOutage`.

    Returning ``None`` here would be the silent failure this whole file exists
    to prevent, so this function has exactly two outcomes: a catalogue, or a
    raise. It never hands the ranker an absent tier 1.
    """
    try:
        catalog = fetch(timeout=timeout)
    except KevError as exc:
        raise KevOutage(f"CISA KEV catalogue unavailable: {exc}") from exc
    except (OSError, ValueError) as exc:
        raise KevOutage(
            f"CISA KEV catalogue unreadable: {exc.__class__.__name__}: {exc}"
        ) from exc

    if catalog is None:
        raise KevOutage("CISA KEV fetch returned nothing")

    try:
        size = len(catalog)
    except TypeError as exc:
        raise KevOutage(f"CISA KEV fetch returned {type(catalog).__name__}") from exc

    if size < minimum:
        raise KevOutage(
            f"CISA KEV catalogue has only {size} entries (expected at least "
            f"{minimum}) -- treating it as truncated, not as a quiet day"
        )
    return catalog


# --------------------------------------------------------------------------- #
# stage 2a -- tier 1 candidates: the CVEs CISA listed this week
# --------------------------------------------------------------------------- #

def collect_kev_candidates(
    catalog: Any,
    fetch: Callable[..., Any] = fetch_cves_by_id,
    *,
    lookback_days: int = KEV_LOOKBACK_DAYS,
    max_lookups: int = MAX_KEV_LOOKUPS,
    timeout: float = 45.0,
) -> tuple[list[Any], int]:
    """NVD records for the CVEs CISA listed recently. Returns (items, listed).

    Without this, tier 1 is unreachable and the two-tier rule is decorative:
    KEV listings almost never coincide with the published window, because CISA
    lists a CVE when exploitation is observed, typically weeks or months after
    publication.

    A failure here is NOT fatal. The catalogue was fetched, so the run can
    still tell a KEV item from a non-KEV one; missing the by-id records only
    costs us the tier-1 candidates NVD's published window did not already
    carry. That is a thinner issue, not a dishonest one, and the severity-only
    failure mode `load_kev` guards against is already excluded by then.
    """
    try:
        recent = list(catalog.added_since(lookback_days))
    except (AttributeError, TypeError, ValueError):
        return [], 0

    cve_ids = [entry.cve_id for entry in recent if getattr(entry, "cve_id", "")]
    if not cve_ids:
        return [], 0

    try:
        items = list(fetch(cve_ids, max_ids=max_lookups, timeout=timeout) or [])
    except (NvdError, OSError, ValueError) as exc:
        print(
            f"run.py: warning: could not pull {len(cve_ids)} KEV-listed CVE(s) "
            f"from NVD by id ({exc}); the issue will only carry KEV items that "
            f"the published window also returned.",
            file=sys.stderr,
        )
        return [], len(cve_ids)
    return items, len(cve_ids)


# --------------------------------------------------------------------------- #
# stage 2b -- tier 2 candidates, published window only
# --------------------------------------------------------------------------- #

def collect_candidates(
    fetch: Callable[..., Any] = fetch_recent_cves,
    *,
    windows: Sequence[int] = WINDOW_DAYS,
    max_items: int = MAX_NVD_ITEMS,
    want: int = MAX_ITEMS,
    timeout: float = 45.0,
) -> tuple[list[Any], int, int]:
    """Published-window CVEs, widening the window until there are enough.

    Returns ``(deduped_items, window_days, considered)``. ``by="published"`` is
    hard-coded: a ``lastMod`` window would date the issue by when somebody last
    edited a record, not by when the vulnerability became news.
    """
    if not windows:
        raise ValueError("windows must not be empty")

    best: list[Any] = []
    best_days = windows[0]
    best_considered = 0

    for days in windows:
        try:
            raw = fetch(
                days=days,
                max_items=max_items,
                timeout=timeout,
                by="published",
            )
        except NvdError as exc:
            raise FeedFailure(f"NVD feed failed over a {days}-day window: {exc}") from exc
        except (OSError, ValueError) as exc:
            raise FeedFailure(
                f"NVD feed unreadable: {exc.__class__.__name__}: {exc}"
            ) from exc

        raw = list(raw or [])
        deduped = list(dedupe_by_cve_id(raw))
        if len(deduped) > len(best):
            best, best_days, best_considered = deduped, days, len(raw)
        if len(deduped) >= want:
            return deduped, days, len(raw)

    return best, best_days, best_considered


# --------------------------------------------------------------------------- #
# stages 3 and 4 -- rank and render
# --------------------------------------------------------------------------- #

def build_issue(
    *,
    kev_fetch: Callable[..., Any] = fetch_kev_catalog,
    nvd_fetch: Callable[..., Any] = fetch_recent_cves,
    kev_item_fetch: Callable[..., Any] = fetch_cves_by_id,
    windows: Sequence[int] = WINDOW_DAYS,
    max_items: int = MAX_ITEMS,
    issue_date: date | None = None,
    use_llm: bool = True,
    llm_base_url: str = DEFAULT_LLM_BASE_URL,
    timeout: float = 45.0,
) -> IssueRun:
    """Fetch, rank and render one issue. Raises :class:`RunFailure` instead of
    returning a degraded document."""
    catalog = load_kev(kev_fetch, timeout=timeout)

    # Tier 1 first, and by id -- the published window cannot see these.
    kev_items, kev_recent = collect_kev_candidates(
        catalog, kev_item_fetch, timeout=timeout,
    )

    window_items, window_days, considered = collect_candidates(
        nvd_fetch, windows=windows, max_items=MAX_NVD_ITEMS, want=max_items,
        timeout=timeout,
    )

    # One dedupe over both sources: a KEV-listed CVE that the published window
    # also returned must not appear twice.
    candidates = list(dedupe_by_cve_id(kev_items + window_items))
    if not candidates:
        raise EmptyIssue(
            f"NVD published no usable CVE in the last {max(windows)} days and "
            "returned none of the KEV-listed CVEs -- no issue written"
        )

    chosen = rank_news(candidates, catalog, limit=max_items)
    if not chosen:
        raise EmptyIssue(
            f"{len(candidates)} candidates survived dedupe but the ranker "
            "returned none -- no issue written"
        )

    client = LLMClient(llm_base_url) if use_llm else None
    markdown = render_issue(
        chosen,
        max_items=max_items,
        client=client,
        use_llm=use_llm,
        title=TITLE,
        issue_date=issue_date,
        total_considered=considered + len(kev_items),
    )

    return IssueRun(
        markdown=markdown,
        items=tuple(chosen),
        issue_date=issue_date or datetime.now(timezone.utc).date(),
        kev_entries=len(catalog),
        window_days=window_days,
        considered=considered,
        deduped=len(candidates),
        known_exploited=sum(1 for item in chosen if getattr(item, "kev_listed", False)),
        kev_recent=kev_recent,
        kev_fetched=len(kev_items),
    )


def write_issue(run: IssueRun, issues_dir: Path | str = ISSUES_DIR) -> Path:
    """Write the issue to ``<issues_dir>/YYYY-MM-DD.md`` and return the path."""
    directory = Path(issues_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run.issue_date:%Y-%m-%d}.md"
    path.write_text(run.markdown, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# command line
# --------------------------------------------------------------------------- #

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Build today's CyberWatch Newsletter issue (no arguments needed).",
    )
    parser.add_argument(
        "--issues-dir", default=str(ISSUES_DIR),
        help=f"where the dated markdown file goes (default: {ISSUES_DIR})",
    )
    parser.add_argument(
        "--days", type=int, default=None,
        help="pin the published window instead of widening 2 -> 4 -> 7 days",
    )
    parser.add_argument(
        "--max-items", type=int, default=MAX_ITEMS,
        help=f"cap on items in the issue (default: {MAX_ITEMS})",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="skip the LLM and write the fields from raw NVD text",
    )
    parser.add_argument(
        "--llm-url", default=DEFAULT_LLM_BASE_URL,
        help=f"OpenAI-compatible base URL (default: {DEFAULT_LLM_BASE_URL})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the issue to stdout instead of writing it",
    )
    return parser


def main(argv: Sequence[str] | None = None, **overrides: Any) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    windows = (args.days,) if args.days else WINDOW_DAYS

    try:
        run = build_issue(
            windows=windows,
            max_items=max(1, args.max_items),
            use_llm=not args.no_llm,
            llm_base_url=args.llm_url,
            **overrides,
        )
    except RunFailure as exc:
        print(f"run.py: {exc}", file=sys.stderr)
        print("run.py: no issue written.", file=sys.stderr)
        return exc.exit_code

    if args.dry_run:
        print(run.markdown)
        print(f"run.py: {run.summary()} (dry run, nothing written)", file=sys.stderr)
        return 0

    path = write_issue(run, args.issues_dir)
    print(f"run.py: wrote {path}")
    print(f"run.py: {run.summary()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
