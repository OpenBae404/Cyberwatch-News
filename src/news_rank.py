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
    "product_keys",
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
# See `_normalise_name`: separators end a word, everything else binds one.
_NAME_SEPARATORS = frozenset(" \t\r\n_,;/|")
_RUN_OF_JOINERS = re.compile(r"-+")
_JOINER_AT_A_BOUNDARY = re.compile(r"(?:-+ +-*)|(?:-* +-+)")


# --------------------------------------------------------------------------- #
# the reach table
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ReachEntry:
    """One token of the reach file: how many readers run this software.

    `kind` is what the token names, and it decides what the token may match:

      * ``"product"`` -- a piece of software. It matches a product name from
        the START, at a word boundary: "windows" matches "Windows Server
        2019", "exchange" matches "Exchange Server". It never matches from the
        middle, so "chrome" does not match "FortiPAM Chrome Extension", and
        the head has to be the whole first WORD, so ".net" does not match
        "Net-IDN-Encode" and "nginx" does not match "nginx-ignition".
      * ``"vendor"``  -- a company, written ``vendor:apple`` in the file. A
        vendor is not software: it only scores when the feed names no specific
        product ("Apple / Multiple Products"), because otherwise every one of
        that vendor's products, however niche, would inherit the vendor's
        reach.
      * ``"brand"``   -- a company whose whole catalogue carries the weight,
        written ``brand:d-link``. It matches any item of that vendor, named
        product or not. Only defensible when the weight is already set at the
        level of the vendor's WEAKEST product: "d-link" is 26 because one
        household runs each piece of D-Link kit, and that is true of every
        D-Link box. "cisco" can never be a brand, because Cisco's 60 is
        IOS-scale and a Cisco webcam is not.

    `scope` qualifies a product token with the vendor it belongs to, written
    ``cisco/ios`` in the file. Two vendors genuinely ship different software
    under one name -- Cisco IOS is a router OS, Apple iOS is a phone OS -- and
    an unqualified token hands every row of one to the other's weight.
    """

    token: str
    weight: int
    note: str = ""
    kind: str = "product"
    scope: str = ""


@dataclass(frozen=True)
class ReachTable:
    """The parsed reach file, plus the lookup the ranker uses."""

    entries: tuple[ReachEntry, ...]
    source: str = ""

    def score(self, item: Any) -> tuple[int, str]:
        """Highest reach weight this item matches, and the token that matched.

        A product token matches a product name from its START, at a word
        boundary -- never from the middle, and never as part of a word.
        "Windows Server 2019" is Windows and "Exchange Server" is Exchange,
        because a product name is written head-first: the software comes
        first and the edition, platform or wrapper follows. The reverse is not
        true, which is the defect this rule replaces: "Fortinet FortiPAM
        Chrome Extension" is a FortiPAM thing, not Chrome. And the head has to
        be the whole first word: "Net-IDN-Encode" is a Perl module, not
        Microsoft .NET, and "nginx-ignition" is not nginx.

        A vendor name is only a name when the feed gives no product (a KEV row
        reading "Apple / Multiple Products"). A brand (`brand:d-link`) matches
        any item of that vendor, because its weight is the weight of its
        weakest product. A scoped token (`cisco/ios`) matches only under the
        vendor that ships it, so Apple's iOS is never scored as Cisco's.

        No match is ``(0, "")`` -- unknown reach, not zero reach. It only ever
        costs an item a tie-break, never a tier.
        """
        surface = _reach_surfaces(item)
        if not (surface.candidates or surface.bare_vendors):
            return 0, ""
        best_weight = 0
        best_token = ""
        for entry in self.entries:
            if entry.weight <= best_weight:
                # entries are sorted heaviest first, so nothing left can win
                break
            if entry.kind == "vendor":
                matched = entry.token in surface.bare_vendors
            elif entry.kind == "brand":
                # A brand is a company whose whole catalogue carries this
                # weight, so it scores that vendor's items whether or not they
                # name a product. It never matches a NAME: "Android TV" is a
                # Google product, and it is 97 only when the feed files it
                # under the Android vendor itself.
                matched = entry.token in surface.bare_vendors or any(
                    candidate.vendor == entry.token for candidate in surface.candidates
                )
            else:
                # A product token matches the product name, or the name with
                # its vendor in front ("google chrome"), and in both cases
                # only from the start. Whether a company word may lead such a
                # match is decided in the FILE, not here: a company whose
                # catalogue runs from the core of the internet down to a
                # webcam is written `vendor:cisco` and never reaches this
                # branch.
                matched = any(
                    (not entry.scope or candidate.vendor == entry.scope)
                    and candidate.leads_with(entry.token)
                    for candidate in surface.candidates
                )
            if matched:
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

    One line is ``<weight> <token>[, <token>...]``. Several tokens on a line
    are spellings of ONE reach claim at ONE weight -- "edge, microsoft edge",
    "apple/ios, apple/ipados, iphone os". They share the line on purpose: the
    weights in this file are the ranker's tie-break scale and are not this
    module's to re-tune, so a matching change adds spellings to existing
    weights rather than inventing new ones.

    A token may be written:

      ``windows``        a product (see `ReachEntry`)
      ``cisco/ios``      a product, only under that vendor
      ``vendor:apple``   a company; only a row that names no product
      ``brand:d-link``   a company; every row it files
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(f"reach table not readable at {path}: {exc}") from exc

    entries: list[ReachEntry] = []
    seen: set[tuple[str, str, str]] = set()
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

        spellings = [chunk.strip() for chunk in parts[1].split(",")]
        if not any(spellings):
            raise ValueError(f"{path}:{lineno}: token is empty after normalisation")
        for raw_token in spellings:
            if not raw_token:
                raise ValueError(f"{path}:{lineno}: empty token in {raw_line!r}")
            entry = _parse_reach_token(raw_token, weight, note.strip(), path, lineno, raw_line)
            key = (entry.kind, entry.scope, entry.token)
            if key in seen:
                raise ValueError(f"{path}:{lineno}: duplicate token {entry.token!r}")
            seen.add(key)
            entries.append(entry)

    if not entries:
        raise ValueError(f"{path}: reach table has no entries")

    entries.sort(key=lambda e: (-e.weight, e.token))
    return ReachTable(entries=tuple(entries), source=str(path))


def _parse_reach_token(
    raw_token: str, weight: int, note: str, path: Path, lineno: int, raw_line: str
) -> ReachEntry:
    """One written token -> one `ReachEntry`, kind and scope decoded."""
    kind = "product"
    lowered = raw_token.lower()
    if lowered.startswith("vendor:"):
        # "vendor:apple" -- a company, not software. It scores only for an item
        # that names no product at all; see ReachEntry.
        kind = "vendor"
        raw_token = raw_token.split(":", 1)[1]
    elif lowered.startswith("brand:"):
        # "brand:d-link" -- a company whose whole catalogue is worth the same,
        # so the weight is honest for any product of it.
        kind = "brand"
        raw_token = raw_token.split(":", 1)[1]

    scope = ""
    if kind == "product" and "/" in raw_token:
        # "cisco/ios" -- this token means this software under this vendor only.
        # Apple's iOS is a different operating system.
        scope_text, _, raw_token = raw_token.partition("/")
        scope = _normalise_name(scope_text)
        if not scope:
            raise ValueError(f"{path}:{lineno}: scope is empty in {raw_line!r}")

    token = _normalise_name(raw_token)
    if not token:
        raise ValueError(f"{path}:{lineno}: token is empty after normalisation")
    return ReachEntry(token=token, weight=weight, note=note, kind=kind, scope=scope)


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
    # Normalised (vendor, product) pairs naming the software this CVE is in,
    # from every structured source the feed offers: the vulnerable CPEs, the
    # CNA `affected` rows, and the KEV row's own vendor/product. The key the
    # one-per-product cap dedupes on; empty when no source names a product,
    # which exempts the item from the cap entirely.
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

    The keys come from `product_keys` -- the vulnerable CPEs, the CNA affected
    rows, and the KEV row's vendor/product. An item that no source names has no
    product key at all and is never capped against anything, because the ranker
    cannot tell whether two unlabelled items are the same software.
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
        product_keys=product_keys(item),
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


def _normalise_name(text: Any) -> str:
    """Like `_normalise`, but it keeps the difference between two punctuations.

    Reach is anchored to the HEAD of a product name, so the matcher has to know
    where one word ends. Flattening every punctuation mark to a space loses
    exactly that: ".NET Framework" and "Net-IDN-Encode" both become "net ...",
    and a Perl module gets scored as Microsoft's runtime -- one of the two
    defects this card exists to kill, one character wide.

    So the two kinds of punctuation are kept apart:

      * SEPARATORS -- whitespace, `_`, `,`, `;`, `/`, `|`. A CPE writes
        "internet_explorer" and KEV writes "iOS, iPadOS, and macOS"; both are
        lists of words, so these become spaces.
      * JOINERS -- everything else (`-`, `.`, `'`, `&`, brackets). These bind
        the characters on either side into ONE word: "net-idn-encode" and
        "nginx-ignition" are single names, not a name plus a qualifier, and a
        table token may not stop in the middle of one. They become "-".

    A joiner next to a separator is dropped, so "Acrobat (Classic)" is
    "acrobat classic" rather than "acrobat -classic-".
    """
    out = []
    for char in str(text).lower():
        if char.isalnum():
            out.append(char)
        elif char in _NAME_SEPARATORS:
            out.append(" ")
        else:
            out.append("-")
    joined = "".join(out)
    joined = _RUN_OF_JOINERS.sub("-", joined)
    joined = _JOINER_AT_A_BOUNDARY.sub(" ", joined)
    return joined.strip(" -")


# Product fields that name no product: a feed row saying "everything this
# vendor ships". CISA KEV writes 53 Apple rows this way. An item like this is
# the one case where a vendor line in the reach table is the only thing that
# can describe it.
_UNSPECIFIC_PRODUCTS = frozenset({
    "multiple products",
    "multiple product",
    "multiple",
    "various products",
    "various",
    "all products",
    "several products",
})


def _name_leads_with(name: str, token: str) -> bool:
    """Does this product name START with `token`, at a word boundary?

    "windows server 2019" leads with "windows"; "fortipam chrome extension"
    does not lead with "chrome". Product names are written head-first -- the
    software, then the edition, platform or wrapper -- so the head is the
    identity and everything after it narrows. Matching anywhere else is the
    defect this replaces: a word in the middle usually says what the product
    plugs INTO, not what it is.
    """
    if not name or not token:
        return False
    return name == token or name.startswith(f"{token} ")


@dataclass(frozen=True)
class _ReachCandidate:
    """One named product of one vendor, as the several names it goes by.

    vendor     the normalised vendor word ("cisco", "apple"), or "" when the
               feed gives none. A scoped table token (`cisco/ios`) matches only
               when this is its vendor, which is how Apple's iOS stays off
               Cisco's line.
    names      the product as the feed writes it, plus narrow rewrites (version
               tail dropped, leading vendor repeat dropped). A product token
               matches any of them from the START.
    qualified  the same names with the vendor in front, so a table entry
               spelled "google chrome" or "linux kernel" matches. A token that
               is only the vendor word never matches here: "Red Hat Build of
               Keycloak" must not score as "red hat", or the vendor over-reach
               the `vendor:` mechanism exists to forbid simply comes back in
               through the front of the name.
    """

    vendor: str
    names: frozenset[str]
    qualified: frozenset[str] = frozenset()

    def leads_with(self, token: str) -> bool:
        if any(_name_leads_with(name, token) for name in self.names):
            return True
        if not self.vendor or not token.startswith(f"{self.vendor} "):
            # only a token that reaches PAST the vendor word may use the
            # vendor-qualified spelling
            return False
        return any(_name_leads_with(name, token) for name in self.qualified)


@dataclass(frozen=True)
class _ReachSurface:
    """What a reach token is allowed to be matched against, for one item.

    candidates    one `_ReachCandidate` per named product the feed states. A
                  product token matches a candidate's names from the start; a
                  scoped token also has to match the candidate's vendor.
    bare_vendors  vendors of rows that name NO product ("Apple / Multiple
                  Products"). A `vendor:` table line matches only these, and a
                  `brand:` line matches these and named rows alike.
    """

    candidates: tuple[_ReachCandidate, ...]
    bare_vendors: set[str]


def _reach_surfaces(item: Any) -> _ReachSurface:
    """The names a reach token may match for this item, normalised.

    Reach answers "how many readers run this software", so it is matched
    against the item's PRODUCT identity:

      * the product field of every (vendor, product) pair the feed vouches for
        -- from a CPE NVD marks VULNERABLE, and from a KEV row's own
        vendor/product fields, which name the software directly;
      * the vendor+product of such a pair as one name, so a table entry spelled
        "google chrome", "microsoft edge" or "linux kernel" still matches;
      * for an item that carries no such pair (a mapping fixture, an
        unanalysed CVE), the display labels in `affected_products`, taken whole
        and with a leading vendor word optionally stripped -- the old "vendor
        product" convention those labels are written in.

    A product token matches any of those names from the START only (see
    `_name_leads_with`), never from the middle and never mid-word.

    A bare vendor is a separate, much narrower surface: it exists only when the
    row names no specific product ("Apple / Multiple Products"), and only a
    `vendor:` or `brand:` line in the reach table can match it. Letting a
    company name lead a named product is the substring bug one level up --
    every Fortinet product would inherit 62, which is how "Fortinet FortiPAM
    Chrome Extension" would keep a reach figure after losing "chrome".

    Each named product is kept as its own candidate, with its vendor attached,
    because a token can be scoped to a vendor (`cisco/ios`). Pooling the names
    of every pair into one bag would let a Cisco row satisfy an Apple-scoped
    token whenever one item names both.

    `cna_products` is deliberately NOT read here. It is a structured field the
    one-per-product CAP keys on (see `product_keys`), added because a freshly
    published CVE has no CPE at all; it is not evidence NVD has vouched for,
    and putting it on this surface is a separate decision from this card's.

    Platform CPEs are never a surface either: `src/sources/nvd.py` splits them
    off, and scoring reach against the union is how CVE-2026-87886 (Acronis
    Backup) scored reach 100 through a `vulnerable: false` linux:linux_kernel
    entry -- the kernel is what the agent runs on, not what the bug is in.
    """
    candidates: list[_ReachCandidate] = []
    bare_vendors: set[str] = set()

    def add_candidate(vendor: str, names: set[str], qualified: set[str]) -> None:
        names = {n for n in names if n}
        qualified = {n for n in qualified if n}
        if names or qualified:
            candidates.append(
                _ReachCandidate(
                    vendor=vendor,
                    names=frozenset(names),
                    qualified=frozenset(qualified),
                )
            )

    pairs = _raw_reach_pairs(item)
    for raw_vendor, raw_product in pairs:
        vendor = _normalise_name(raw_vendor)
        product = _normalise_name(raw_product)
        if product and _normalise(product) not in _UNSPECIFIC_PRODUCTS:
            add_candidate(vendor, *_name_variants(vendor, product))
        elif vendor:
            bare_vendors.add(vendor)

    if not pairs:
        # Compatibility surface: items that never went through the NVD parser,
        # and CVEs NVD has not analysed, carry only a joined "vendor product"
        # display label. Take the label whole, and take it again with a leading
        # vendor word removed -- the convention these labels are written in.
        for label in _as_strings(_get(item, "affected_products", ())):
            name = _normalise_name(label)
            if not name:
                continue
            head, _, tail = name.partition(" ")
            if tail and _normalise(tail) in _UNSPECIFIC_PRODUCTS:
                bare_vendors.add(head)
                continue
            names = {tail, _drop_version_tail(tail)} if tail else {name}
            add_candidate(head, names, {name, _drop_version_tail(name)})

    bare_vendors.discard("")
    return _ReachSurface(tuple(candidates), bare_vendors)


def _name_variants(vendor: str, product: str) -> tuple[set[str], set[str]]:
    """(plain names, vendor-qualified names) one (vendor, product) goes by.

    The plain set is the product as the feed writes it, plus two narrow
    rewrites that exist because feeds do not write product names the way a
    reach table does:

      * a trailing version is dropped, so "Windows 10" is Windows;
      * a leading repeat of the vendor is dropped, so Google's "Google Chrome"
        is also "chrome".

    The qualified set is the same names with the vendor in front, so a table
    entry spelled "google chrome" or "linux kernel" matches. It is kept apart
    because a token that is only the vendor word must not match it -- see
    `_ReachCandidate.leads_with`.

    Both rewrites remove text from an END of the name. Nothing is ever taken
    from the middle -- "FortiPAM Chrome Extension" has no variant that starts
    with "chrome", and that is the whole point.
    """
    plain: set[str] = set()
    qualified: set[str] = set()
    if not product:
        return plain, qualified

    def add(bucket: set[str], name: str) -> None:
        bucket.add(name)
        bucket.add(_drop_version_tail(name))

    add(plain, product)
    if vendor:
        add(qualified, f"{vendor} {product}".strip())
        if product.startswith(f"{vendor} "):
            add(plain, product[len(vendor) + 1:])

    plain.discard("")
    qualified.discard("")
    return plain, qualified


def _is_version_word(word: str) -> bool:
    """Is this trailing word a version rather than part of the name?"""
    return bool(word) and (
        word.isdigit()
        or word in ("version", "v")
        or (word[0].isdigit() and any(c.isdigit() for c in word))
    )


def _drop_version_tail(name: str) -> str:
    """"windows 10" -> "windows"; "fortipam chrome extension" unchanged.

    Only trailing version words go. A name that is nothing but a version is
    returned unchanged rather than emptied.
    """
    words = name.split()
    while len(words) > 1 and _is_version_word(words[-1]):
        words.pop()
    return " ".join(words)


def _raw_reach_pairs(item: Any) -> list[tuple[str, str]]:
    """The (vendor, product) pairs reach may be scored on, as the feed wrote them.

    Two sources, both of them claims a feed vouches for:

      * `vulnerable_cpes` -- CPEs NVD marks vulnerable, the authoritative set;
      * a KEV row's own `vendor`/`product` fields, which name the software
        directly and are how the live catalogue describes 1721 exploited bugs.

    `cna_products` is NOT here: it is the cap's evidence, not reach's -- see
    `_reach_surfaces`. A platform CPE is not here either; it is the stack the
    vulnerable product runs on, not the software with the bug.

    Punctuation is kept as the feed wrote it, because the caller has to tell
    "Net-IDN-Encode" from ".NET Framework" and `_normalise` cannot. Two pairs
    are the same pair when they normalise the same way, so a CPE and a KEV row
    naming one product are not listed twice.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(vendor: Any, product: Any) -> None:
        vendor, product = str(vendor or ""), str(product or "")
        key = (_normalise(vendor), _normalise(product))
        if key == ("", "") or key in seen:
            return
        seen.add(key)
        pairs.append((vendor, product))

    for criteria in _as_strings(_get(item, "vulnerable_cpes", ())):
        add(*_cpe_vendor_product(criteria))

    kev_vendor = _get(item, "vendor", "")
    kev_product = _get(item, "product", "")
    if isinstance(kev_vendor, str) or isinstance(kev_product, str):
        add(kev_vendor if isinstance(kev_vendor, str) else "",
            kev_product if isinstance(kev_product, str) else "")

    return pairs


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


def product_keys(item: Any) -> tuple[tuple[str, str], ...]:
    """Normalised (vendor, product) keys naming the software this CVE is in.

    Read from every STRUCTURED source the feed offers, in order of how much
    NVD has vouched for it:

      1. `vulnerable_cpes` -- NVD's own applicability analysis, best evidence
      2. `cna_products`    -- the vendor/product fields of the CNA's `affected`
                              rows, which exist on a CVE long before NVD has
                              analysed it into CPEs
      3. `vendor`/`product` -- the KEV row's own fields, for items fetched by id

    Keying the cap on (1) alone left it inert on exactly the days it is needed:
    on the AG-8 recorded window not one of 600 CVEs carried a vulnerable CPE,
    so a quiet KEV day shipped four Adobe Connect advisories as four of five
    items. (2) is a structured field, not free text -- it is read here for the
    cap and never added to the reach match surface, which is the separate
    defect AG-14 owns.

    Normalisation is `_normalise`, the same one the reach tokens use, so the
    CPE spelling `adobe:adobe_connect` and the CNA spelling `Adobe` /
    `Adobe Connect` produce the same key and collide as they should.

    An item no source names -- no CPE, no CNA row, no KEV fields -- returns an
    empty tuple and is exempt from the cap: the ranker cannot tell whether two
    unlabelled items are the same software, and guessing would drop real news.
    """
    keys: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(vendor: Any, product: Any) -> None:
        key = (_normalise(vendor), _normalise(product))
        if not key[0] and not key[1]:
            return
        if key in seen:
            return
        seen.add(key)
        keys.append(key)

    for vendor, product in _vulnerable_vendor_products(item):
        add(vendor, product)

    for pair in _get(item, "cna_products", ()) or ():
        if isinstance(pair, (tuple, list)) and len(pair) == 2:
            add(pair[0], pair[1])

    kev_vendor = _get(item, "vendor", "")
    kev_product = _get(item, "product", "")
    if isinstance(kev_vendor, str) and isinstance(kev_product, str):
        add(kev_vendor, kev_product)

    return tuple(keys)


def _vulnerable_vendor_products(item: Any) -> list[tuple[str, str]]:
    """(vendor, product) for each CPE NVD marks vulnerable, in feed order.

    Only `vulnerable_cpes` is read -- the CPE half of `product_keys`, and the
    whole of the reach match surface. A platform CPE is never either.
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
