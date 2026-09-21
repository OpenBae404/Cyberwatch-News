"""CISA Known Exploited Vulnerabilities (KEV) catalogue source.

Pulls the live catalogue from

    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

and returns plain dataclass items for the newsletter pipeline. Tier 1 of the
selection rule in Plans.md: a CVE in this catalogue is being exploited in the
wild, which outranks any CVSS score.

Deliberate constraints, the same ones `nvd.py` works under:
  * no disk cache, no fixture mode -- every call hits the live feed
  * stdlib only (urllib), so the collector has no install step
  * ranking, dedupe and rendering live elsewhere; this module only normalises

The catalogue is the whole history (1700+ entries, ~2 MB), not a window. Use
:meth:`KevCatalog.added_since` for "what is new today" and
:meth:`KevCatalog.by_cve_id` as the ranker's lookup. `dateAdded` is the
catalogue date -- when CISA listed it -- and is the only date that says
anything about today's news; a CVE's publication date can be years earlier.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterator

FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

_USER_AGENT = "cyberwatch-news/0.1"
_RETRY_SLEEP = 2.0
_ATTEMPTS = 3


class KevError(RuntimeError):
    """Raised when the KEV catalogue is unreachable or answers with junk.

    Both failure modes are one named error on purpose: a caller can only do
    one thing about either -- fall back to tier 2 -- and the distinction
    belongs in the message, not in the type.
    """


@dataclass(frozen=True)
class KevEntry:
    """One normalised catalogue row. Plain data -- no behaviour, no handles."""

    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    description: str
    date_added: date | None           # catalogue date: when CISA listed it
    due_date: date | None             # federal remediation deadline
    required_action: str = ""
    known_ransomware: bool = False
    notes: str = ""
    cwes: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"

    @property
    def label(self) -> str:
        """"vendor product" for display, without repeating a vendor-as-product."""
        if self.vendor and self.product and self.vendor.lower() != self.product.lower():
            return f"{self.vendor} {self.product}"
        return self.product or self.vendor or self.cve_id


@dataclass(frozen=True)
class KevCatalog:
    """The catalogue as fetched, plus the lookups the ranker needs."""

    title: str
    version: str
    date_released: datetime | None
    entries: tuple[KevEntry, ...]
    _index: dict[str, KevEntry] = field(default_factory=dict, repr=False, compare=False)

    # -- lookups ---------------------------------------------------------- #

    def by_cve_id(self, cve_id: str) -> KevEntry | None:
        """Return the entry for `cve_id`, or None. The ranker's accessor."""
        if not cve_id:
            return None
        return self._index.get(cve_id.strip().upper())

    def contains(self, cve_id: str) -> bool:
        """True when `cve_id` is known-exploited. Tier 1 of the selection rule."""
        return self.by_cve_id(cve_id) is not None

    def added_since(self, cutoff: date | datetime | int) -> list[KevEntry]:
        """Entries catalogued on or after `cutoff`, newest first.

        `cutoff` may be a date, a datetime, or a number of days back from
        today (UTC). Entries with no parseable `dateAdded` are excluded --
        an undated row cannot be claimed as today's news.
        """
        if isinstance(cutoff, int) and not isinstance(cutoff, bool):
            if cutoff < 0:
                raise ValueError("days must be >= 0")
            cutoff = datetime.now(timezone.utc).date() - timedelta(days=cutoff)
        elif isinstance(cutoff, datetime):
            cutoff = cutoff.date()
        elif not isinstance(cutoff, date):
            raise TypeError("cutoff must be a date, datetime or number of days")

        recent = [e for e in self.entries if e.date_added and e.date_added >= cutoff]
        recent.sort(key=lambda e: (e.date_added or date.min, e.cve_id), reverse=True)
        return recent

    # -- container sugar --------------------------------------------------- #

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[KevEntry]:
        return iter(self.entries)

    def __contains__(self, cve_id: object) -> bool:
        return isinstance(cve_id, str) and self.contains(cve_id)


# --------------------------------------------------------------------------- #
# public entry points
# --------------------------------------------------------------------------- #

def fetch_kev_catalog(
    *,
    timeout: float = 45.0,
    url: str = FEED_URL,
) -> KevCatalog:
    """Fetch and parse the live KEV catalogue.

    Raises :class:`KevError` if CISA is unreachable, answers with a non-JSON
    body, or returns a document that is not a KEV catalogue. A catalogue that
    parses but lists nothing new is not an error -- that is a quiet day, and
    tier 2 handles it.
    """
    return parse_catalog(_get_json(url, timeout))


def fetch_recent_kev(
    days: int = 7,
    *,
    timeout: float = 45.0,
    url: str = FEED_URL,
) -> list[KevEntry]:
    """Entries added to the catalogue in the last `days`, newest first."""
    if days < 0:
        raise ValueError("days must be >= 0")
    return fetch_kev_catalog(timeout=timeout, url=url).added_since(days)


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #

def parse_catalog(payload: Any) -> KevCatalog:
    """Turn a decoded KEV document into a :class:`KevCatalog`.

    Malformed input raises :class:`KevError`. "Malformed" means the document
    is not a KEV catalogue at all -- an individual unusable row is dropped,
    because one bad row should not cost us the other 1700.
    """
    if not isinstance(payload, dict):
        raise KevError(
            f"KEV catalogue is not a JSON object (got {type(payload).__name__})"
        )
    rows = payload.get("vulnerabilities")
    if not isinstance(rows, list):
        raise KevError("KEV catalogue has no 'vulnerabilities' list")

    entries: list[KevEntry] = []
    index: dict[str, KevEntry] = {}
    for row in rows:
        entry = parse_entry(row)
        if entry is None:
            continue
        entries.append(entry)
        # First listing wins: CISA does not repeat a CVE, but if it ever does,
        # the earlier catalogue date is the one that is true.
        index.setdefault(entry.cve_id, entry)

    if rows and not entries:
        raise KevError("KEV catalogue listed rows but none carried a CVE id")

    return KevCatalog(
        title=str(payload.get("title") or ""),
        version=str(payload.get("catalogVersion") or ""),
        date_released=_parse_datetime(payload.get("dateReleased")),
        entries=tuple(entries),
        _index=index,
    )


def parse_entry(row: Any) -> KevEntry | None:
    """Normalise one `vulnerabilities[]` row (None if it carries no CVE id)."""
    if not isinstance(row, dict):
        return None
    cve_id = str(row.get("cveID") or "").strip().upper()
    if not cve_id:
        return None

    cwes = tuple(
        str(c).strip() for c in (row.get("cwes") or []) if isinstance(c, str) and c.strip()
    )

    return KevEntry(
        cve_id=cve_id,
        vendor=str(row.get("vendorProject") or "").strip(),
        product=str(row.get("product") or "").strip(),
        vulnerability_name=str(row.get("vulnerabilityName") or "").strip(),
        description=str(row.get("shortDescription") or "").strip(),
        date_added=_parse_date(row.get("dateAdded")),
        due_date=_parse_date(row.get("dueDate")),
        required_action=str(row.get("requiredAction") or "").strip(),
        known_ransomware=str(row.get("knownRansomwareCampaignUse") or "").strip().lower()
        == "known",
        notes=str(row.get("notes") or "").strip(),
        cwes=cwes,
        raw=row,
    )


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        # CISA emits sub-second precision Python's parser rejects on some
        # versions (".0974Z"); the date is what matters, so fall back to it.
        day = _parse_date(text)
        return datetime(day.year, day.month, day.day, tzinfo=timezone.utc) if day else None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #

def _get_json(url: str, timeout: float) -> Any:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )

    last_error: Exception | None = None
    for attempt in range(_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
            return json.loads(body)
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code in (429, 500, 502, 503, 504) and attempt < _ATTEMPTS - 1:
                time.sleep(_RETRY_SLEEP * (attempt + 1))
                continue
            raise KevError(f"CISA returned HTTP {exc.code} for {url}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt < _ATTEMPTS - 1:
                time.sleep(_RETRY_SLEEP * (attempt + 1))
                continue
        except json.JSONDecodeError as exc:
            raise KevError(f"CISA returned a non-JSON body for {url}") from exc
    raise KevError(f"could not reach the KEV catalogue at {url}: {last_error}")


if __name__ == "__main__":  # manual smoke check against the live feed
    catalog = fetch_kev_catalog()
    print(f"{catalog.title} {catalog.version} -- {len(catalog)} entries")
    for item in catalog.added_since(30)[:10]:
        flag = " [ransomware]" if item.known_ransomware else ""
        print(f"  {item.date_added}  {item.cve_id:18} {item.label}{flag}")
