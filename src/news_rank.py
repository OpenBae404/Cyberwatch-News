"""Pick the five items for one newsletter issue.

This is the ranker described in Plans.md, and it is NOT the CyberWatch profile
matcher. Nothing here asks "does this CVE hit *your* stack" -- there is no
profile, no inventory, no CPE equality test against a machine. The question is
"would a security reader want to know about this today", and it is answered in
two tiers:

  tier 1  the CVE is in the CISA KEV catalogue -- someone is being attacked
          with it right now. That outranks any CVSS score, including a KEV
          MEDIUM over a non-KEV 9.8.
  tier 2  everything else, ordered by severity and then by how many readers
          run the affected software (data/software_reach.txt).

Tier 2 exists so an issue always ships: KEV goes quiet for days at a time, and
a newsletter that skips those days is not a newsletter.

Within a tier the order is severity band first, then reach, then the raw CVSS
score, then publication date, then the CVE id so the output is stable. Severity
comes before reach on purpose: reach breaks ties between comparably serious
bugs, it does not promote a LOW in Windows over a CRITICAL in nginx.

Every returned item carries `reason` -- the sentence that says why it is in the
issue. An item nobody can explain is an item that should not have been picked.

After sorting, the issue keeps at most one item per CPE vendor+product pair:
five CVEs in one product is a changelog, not an issue. That cap makes issues
shorter, never longer -- padding the freed slot with an item the ranker already
judged less worth knowing is how a newsletter starts lying.

Deliberately out of scope: fetching (src/sources/), collapsing revisions
(src/dedupe.py), wording and markdown (src/render.py). This module is a pure
function over an already-deduped feed, so it stays inspectable and its tests
need no network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "DEFAULT_REACH_FILE",
    "MAX_ITEMS",
    "ReachEntry",
    "ReachTable",
    "RankedItem",
    "load_reach_table",
    "rank_news",
    "severity_band",
]

# The named file. Tier ordering is only as defensible as this table, so it
# lives in the repo as reviewable text rather than as a dict in the code.
DEFAULT_REACH_FILE = Path(__file__).resolve().parents[1] / "data" / "software_reach.txt"

MAX_ITEMS = 5

KEV_TIER = 1
FALLBACK_TIER = 2

# CVSS bands, highest first. Anything unscored sorts below LOW -- unknown is
# not a severity, and it must never outrank a measured one.
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Used only when NVD gave a score but no band (old v2 records do this).
_SCORE_BANDS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"))

_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


# --------------------------------------------------------------------------- #
# the reach table
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ReachEntry:
    """One line of the reach file: how many readers run this software."""

    token: str
    weight: int
    note: str = ""


@dataclass(frozen=True)
class ReachTable:
    """The parsed reach file, plus the lookup the ranker uses."""

    entries: tuple[ReachEntry, ...]
    source: str = ""

    def score(self, item: Any) -> tuple[int, str]:
        """Highest reach weight this item matches, and the token that matched.

        No match is ``(0, "")`` -- unknown reach, not zero reach. It only ever
        costs an item a tie-break, never a tier.
        """
        haystack = _reach_haystack(item)
        if not haystack:
            return 0, ""
        best_weight = 0
        best_token = ""
        for entry in self.entries:
            if entry.weight <= best_weight:
                # entries are sorted heaviest first, so nothing left can win
                break
            if f" {entry.token} " in haystack:
                best_weight = entry.weight
                best_token = entry.token
        return best_weight, best_token

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)


def _resolve_reach(reach: ReachTable | str | Path | None) -> ReachTable:
    if isinstance(reach, ReachTable):
        return reach
    if reach is None:
        return load_reach_table()
    return load_reach_table(reach)


def load_reach_table(path: str | Path = DEFAULT_REACH_FILE) -> ReachTable:
    """Parse the reach file. Raises if it is missing -- silence would be worse.

    A ranker that quietly ran with an empty table would still produce five
    items every day, all of them ordered by nothing, and no reader would ever
    see the difference. So a missing or empty file is an error.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(f"reach table not readable at {path}: {exc}") from exc

    entries: list[ReachEntry] = []
    seen: set[str] = set()
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        body, _, note = line.partition("#")
        parts = body.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"{path}:{lineno}: expected '<weight> <token>', got {raw_line!r}")
        try:
            weight = int(parts[0])
        except ValueError as exc:
            raise ValueError(f"{path}:{lineno}: weight {parts[0]!r} is not an integer") from exc
        if not 0 <= weight <= 100:
            raise ValueError(f"{path}:{lineno}: weight {weight} is outside 0-100")
        token = _normalise(parts[1])
        if not token:
            raise ValueError(f"{path}:{lineno}: token is empty after normalisation")
        if token in seen:
            raise ValueError(f"{path}:{lineno}: duplicate token {token!r}")
        seen.add(token)
        entries.append(ReachEntry(token=token, weight=weight, note=note.strip()))

    if not entries:
        raise ValueError(f"{path}: reach table has no entries")

    entries.sort(key=lambda e: (-e.weight, e.token))
    return ReachTable(entries=tuple(entries), source=str(path))


# --------------------------------------------------------------------------- #
# the ranked item
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RankedItem:
    """One chosen item: the feed record, its tier, and why it was chosen.

    Attribute reads fall through to the wrapped item, so a `RankedItem` can go
    straight to `src/render.py` where an `NvdItem` would.
    """

    item: Any
    tier: int
    reason: str
    severity: str | None = None
    severity_rank: int = 0
    cvss_score: float | None = None
    reach: int = 0
    reach_match: str = ""
    kev: Any = None                      # KevEntry when tier 1, else None
    reach_source: str = field(default="", repr=False)
    # (vendor, product) of every CPE NVD marks vulnerable, lowercased. The key
    # the one-per-product cap dedupes on; empty when the item names no
    # vulnerable CPE, which exempts it from the cap entirely.
    product_keys: tuple[tuple[str, str], ...] = ()

    @property
    def kev_listed(self) -> bool:
        return self.tier == KEV_TIER

    @property
    def cve_id(self) -> str:
        return str(_get(self.item, "cve_id", "") or "")

    def __getattr__(self, name: str) -> Any:
        # Only reached for names the dataclass does not define.
        if name.startswith("__"):
            raise AttributeError(name)
        try:
            return getattr(object.__getattribute__(self, "item"), name)
        except AttributeError:
            raise AttributeError(name) from None


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #

def rank_news(
    items: Iterable[Any],
    kev: Any = None,
    *,
    reach: ReachTable | str | Path | None = None,
    limit: int = MAX_ITEMS,
) -> list[RankedItem]:
    """Return at most `limit` items for today's issue, best first.

    `items` is a deduped NVD feed (a list of `NvdItem`, a `DedupeResult`, or
    any iterable of NvdItem-shaped objects or mappings).

    `kev` is the tier-1 oracle: a `KevCatalog`, a mapping of CVE id to entry,
    any iterable of CVE ids, or a callable taking a CVE id. `None` means no KEV
    data was available on this run -- every item then falls to tier 2 and the
    issue still ships, which is the whole point of the second tier.

    `reach` is the reach table, or a path to one; the file at
    `DEFAULT_REACH_FILE` is used when it is omitted.

    Fewer than `limit` candidates returns fewer items, and so does the
    one-per-product cap. Padding an issue is how a newsletter starts lying.
    """
    if limit < 0:
        raise ValueError("limit must be >= 0")
    table = _resolve_reach(reach)
    lookup = _kev_lookup(kev)

    ranked = [_rank_one(item, lookup, table) for item in items if item is not None]
    ranked.sort(key=_sort_key)
    return _cap_one_per_product(ranked, limit)


def _cap_one_per_product(ranked: Sequence[RankedItem], limit: int) -> list[RankedItem]:
    """At most one item per CPE vendor+product pair, applied after sorting.

    Five CVEs in one product is a changelog, not an issue, so once a product
    has its slot the rest of its revisions are dropped and the issue ships
    shorter. Ship short, never pad: the alternative is filling the gap with an
    item the ranker already judged less worth knowing.

    The keys come from `vulnerable_cpes` only, and an item with none has no
    product key at all -- it is never capped against anything, because the
    ranker cannot tell whether two unlabelled items are the same software.
    """
    chosen: list[RankedItem] = []
    used: set[tuple[str, str]] = set()
    for candidate in ranked:
        if len(chosen) >= limit:
            break
        keys = candidate.product_keys
        if keys and used.intersection(keys):
            continue
        used.update(keys)
        chosen.append(candidate)
    return chosen


def severity_band(item: Any) -> tuple[str | None, int, float | None]:
    """(band, rank, score) for one item. Unscored entries rank 0."""
    severity = str(_get(item, "cvss_severity", "") or "").strip().upper()
    raw_score = _get(item, "cvss_score", None)
    score = float(raw_score) if isinstance(raw_score, (int, float)) else None
    if not severity and score is not None:
        severity = _band_for_score(score)
    return (severity or None), _SEVERITY_ORDER.get(severity, 0), score


# --------------------------------------------------------------------------- #
# ranking internals
# --------------------------------------------------------------------------- #

def _rank_one(item: Any, lookup, table: ReachTable) -> RankedItem:
    cve_id = str(_get(item, "cve_id", "") or "").strip().upper()
    kev_entry = lookup(cve_id) if cve_id else None
    severity, severity_rank, score = severity_band(item)
    reach, reach_match = table.score(item)

    tier = KEV_TIER if kev_entry is not None else FALLBACK_TIER
    return RankedItem(
        item=item,
        tier=tier,
        reason=_reason(tier, kev_entry, severity, score, reach, reach_match),
        severity=severity,
        severity_rank=severity_rank,
        cvss_score=score,
        reach=reach,
        reach_match=reach_match,
        kev=kev_entry,
        reach_source=table.source,
        product_keys=tuple(
            (vendor.lower(), product.lower())
            for vendor, product in _vulnerable_vendor_products(item)
        ),
    )


def _sort_key(ranked: RankedItem):
    """Tier first, then severity, then reach. Everything after is tie-breaking."""
    return (
        ranked.tier,                              # 1 (KEV) before 2
        -ranked.severity_rank,                    # CRITICAL before HIGH
        -ranked.reach,                            # widely deployed first
        -(ranked.cvss_score or 0.0),              # raw score as a tie-break
        -_published_ordinal(ranked.item),         # newer first
        ranked.cve_id,                            # stable, deterministic tail
    )


def _reason(
    tier: int,
    kev_entry: Any,
    severity: str | None,
    score: float | None,
    reach: int,
    reach_match: str,
) -> str:
    """The sentence a reader gets for why this item is in the issue."""
    severity_text = _severity_text(severity, score)
    reach_text = (
        f"reach {reach}/100 via \"{reach_match}\"" if reach_match
        else "reach unrated (no entry in the reach table)"
    )

    if tier == KEV_TIER:
        listed = _get(kev_entry, "date_added", None)
        when = f" on {listed}" if isinstance(listed, date) else ""
        label = str(_get(kev_entry, "label", "") or "").strip()
        target = f" in {label}" if label else ""
        ransomware = (
            " Known use in ransomware campaigns."
            if _get(kev_entry, "known_ransomware", False) else ""
        )
        return (
            f"Tier 1: CISA lists this as known-exploited{target}{when}, so it is "
            f"being used against people now -- that outranks severity.{ransomware} "
            f"{severity_text}; {reach_text}."
        )

    return (
        f"Tier 2: not in the CISA KEV catalogue, selected on severity and reach. "
        f"{severity_text}; {reach_text}."
    )


def _severity_text(severity: str | None, score: float | None) -> str:
    if severity and score is not None:
        return f"{severity} (CVSS {score})"
    if severity:
        return f"{severity} (no CVSS score published)"
    if score is not None:
        return f"CVSS {score}, no severity band published"
    return "NVD has not scored it"


def _band_for_score(score: float) -> str:
    for floor, band in _SCORE_BANDS:
        if score >= floor:
            return band
    return "LOW"


def _published_ordinal(item: Any) -> float:
    value = _get(item, "published", None)
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return _EPOCH.timestamp()
        moment = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    return _EPOCH.timestamp()


# --------------------------------------------------------------------------- #
# KEV oracle
# --------------------------------------------------------------------------- #

def _kev_lookup(kev: Any):
    """Normalise whatever tier-1 source was handed in into one lookup callable."""
    if kev is None:
        return lambda cve_id: None

    by_cve_id = getattr(kev, "by_cve_id", None)
    if callable(by_cve_id):                      # a KevCatalog
        return lambda cve_id: by_cve_id(cve_id)

    if isinstance(kev, Mapping):
        normalised = {str(k).strip().upper(): v for k, v in kev.items()}
        return lambda cve_id: normalised.get(cve_id)

    if callable(kev):
        return lambda cve_id: kev(cve_id) or None

    if isinstance(kev, (str, bytes)):
        raise TypeError("kev must be a catalogue, mapping, iterable of ids or callable")

    if isinstance(kev, Iterable):
        # An iterable of ids, or of entries carrying one. Entries win, because
        # a KevEntry gives the reason line a catalogue date to quote.
        table: dict[str, Any] = {}
        for element in kev:
            if isinstance(element, str):
                key, value = element.strip().upper(), element.strip().upper()
            else:
                key = str(_get(element, "cve_id", "") or "").strip().upper()
                value = element
            if key:
                table.setdefault(key, value)
        return lambda cve_id: table.get(cve_id)

    raise TypeError(f"unsupported kev source: {type(kev).__name__}")


# --------------------------------------------------------------------------- #
# item access and text normalisation
# --------------------------------------------------------------------------- #

def _get(item: Any, name: str, default: Any = None) -> Any:
    if item is None:
        return default
    if isinstance(item, Mapping):
        value = item.get(name, default)
    else:
        value = getattr(item, name, default)
    return default if value is None else value


def _normalise(text: Any) -> str:
    """Lowercase, punctuation to spaces, whitespace collapsed.

    Both the reach tokens and the item text go through this, so "node.js"
    matches "Node.js" and "internet explorer" matches the CPE spelling
    "internet_explorer" without a regex per token.
    """
    return _NON_ALNUM.sub(" ", str(text).lower()).strip()


def _reach_haystack(item: Any) -> str:
    """The text the reach tokens are matched against, space-padded for whole-word hits.

    Product labels and the vendor/product fields of the item's VULNERABLE CPEs
    -- never the description, and never a platform CPE. `src/sources/nvd.py`
    splits the two: platform CPEs are "context, never a match surface". Scoring
    reach against the union is how CVE-2026-87886 (Acronis Backup) scored reach
    100 through a `vulnerable: false` linux:linux_kernel entry -- the Linux
    kernel is what the agent runs on, not what the bug is in.
    """
    parts: list[str] = []
    parts.extend(_as_strings(_get(item, "affected_products", ())))
    for vendor, product in _vulnerable_vendor_products(item):
        if vendor:
            parts.append(vendor)
        if product:
            parts.append(product)
    # KEV rows name the software directly; they are the most reliable label we get.
    for name in ("vendor", "product"):
        value = _get(item, name, "")
        if isinstance(value, str) and value.strip():
            parts.append(value)

    normalised = [_normalise(p) for p in parts]
    joined = " ".join(p for p in normalised if p)
    return f" {joined} " if joined else ""


def _as_strings(value: Any) -> list[str]:
    if value in (None, "", ()):
        return []
    if isinstance(value, (str, bytes)):
        return [str(value)]
    if isinstance(value, Sequence) or isinstance(value, Iterable):
        return [str(v) for v in value if str(v).strip()]
    return [str(value)]


def _cpe_vendor_product(criteria: str) -> tuple[str, str]:
    parts = str(criteria).split(":")
    if len(parts) >= 5 and parts[0] == "cpe":
        return parts[3], parts[4]
    return "", ""


def _vulnerable_vendor_products(item: Any) -> list[tuple[str, str]]:
    """(vendor, product) for each CPE NVD marks vulnerable, in feed order.

    Only `vulnerable_cpes` is read. An item that carries none -- a KEV row, a
    mapping fixture, a CVE with no applicability data -- yields an empty list,
    and both callers treat that as "no product known" rather than guessing one
    from the platform CPEs.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for criteria in _as_strings(_get(item, "vulnerable_cpes", ())):
        vendor, product = _cpe_vendor_product(criteria)
        if not vendor and not product:
            continue
        key = (vendor.lower(), product.lower())
        if key in seen:
            continue
        seen.add(key)
        pairs.append((vendor, product))
    return pairs


if __name__ == "__main__":  # manual smoke check against the live feeds
    from src.dedupe import dedupe_by_cve_id
    from src.sources.kev import fetch_kev_catalog
    from src.sources.nvd import fetch_recent_cves

    feed = dedupe_by_cve_id(fetch_recent_cves(days=3, max_items=200))
    catalog = fetch_kev_catalog()
    print(feed.summary())
    for position, chosen in enumerate(rank_news(feed.items, catalog), start=1):
        print(f"\n{position}. [tier {chosen.tier}] {chosen.cve_id}")
        print(f"   {chosen.reason}")
