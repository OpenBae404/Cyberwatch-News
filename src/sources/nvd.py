"""NVD CVE 2.0 JSON source.

Pulls live data from https://services.nvd.nist.gov/rest/json/cves/2.0 and returns
plain dataclass items for the rest of the CyberWatch pipeline.

Deliberate constraints (spike scope):
  * no disk caching, no fixture mode -- every call hits the live API
  * stdlib only (urllib), so the collector has no install step
  * an empty API window returns [] instead of raising

Ranking and dedupe live elsewhere; this module only normalises the feed.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD caps a single page at 2000 CVEs and a published-date window at 120 days.
MAX_RESULTS_PER_PAGE = 2000
MAX_WINDOW_DAYS = 120

# Public rate limit is 5 requests / 30s without a key, 50 / 30s with one.
_SLEEP_NO_KEY = 6.5
_SLEEP_WITH_KEY = 0.7

# Preference order when a CVE carries several CVSS generations.
_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


class NvdError(RuntimeError):
    """Raised when NVD is unreachable or answers with something unparseable."""


@dataclass(frozen=True)
class NvdItem:
    """One normalised CVE record. Plain data -- no behaviour, no API handles."""

    cve_id: str
    published: datetime | None
    last_modified: datetime | None
    description: str
    cvss_severity: str | None          # CRITICAL / HIGH / MEDIUM / LOW / None
    cvss_score: float | None
    cvss_version: str | None           # "4.0", "3.1", "3.0", "2.0"
    cvss_vector: str | None
    affected_products: tuple[str, ...] = ()   # "vendor product" strings, DISPLAY ONLY
    vulnerable_cpes: tuple[str, ...] = ()     # cpeMatch entries NVD marks vulnerable
    platform_cpes: tuple[str, ...] = ()       # every other CPE -- context, never a match surface
    cpe_criteria: tuple[str, ...] = ()        # raw cpe:2.3:... strings (vulnerable + platform)
    vuln_status: str | None = None
    source_identifier: str | None = None
    references: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #

def fetch_recent_cves(
    days: int = 7,
    *,
    max_items: int | None = 200,
    results_per_page: int = 200,
    api_key: str | None = None,
    timeout: float = 45.0,
    base_url: str = API_URL,
    by: str = "published",
) -> list[NvdItem]:
    """Return CVEs from the last `days` as a list of :class:`NvdItem`.

    `by` selects the NVD window: "published" (new CVEs) or "modified"
    (includes republished/revised entries -- what the dedupe stage wants).
    An empty window yields an empty list. Network or protocol failures raise
    :class:`NvdError`; a well-formed "nothing here" never does.
    """
    if days < 1:
        raise ValueError("days must be >= 1")
    if days > MAX_WINDOW_DAYS:
        raise ValueError(f"NVD allows a window of at most {MAX_WINDOW_DAYS} days")

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return fetch_window(
        start,
        end,
        max_items=max_items,
        results_per_page=results_per_page,
        api_key=api_key,
        timeout=timeout,
        base_url=base_url,
        by=by,
    )


def fetch_window(
    start: datetime,
    end: datetime,
    *,
    max_items: int | None = 200,
    results_per_page: int = 200,
    api_key: str | None = None,
    timeout: float = 45.0,
    base_url: str = API_URL,
    by: str = "published",
) -> list[NvdItem]:
    """Fetch an explicit [start, end] window, paginating until it is exhausted."""
    if by not in ("published", "modified"):
        raise ValueError("by must be 'published' or 'modified'")
    if end < start:
        raise ValueError("end must not precede start")

    prefix = "pub" if by == "published" else "lastMod"
    page_size = max(1, min(results_per_page, MAX_RESULTS_PER_PAGE))
    if max_items is not None:
        page_size = min(page_size, max_items)

    items: list[NvdItem] = []
    start_index = 0
    pause = _SLEEP_WITH_KEY if api_key else _SLEEP_NO_KEY

    while True:
        params = {
            f"{prefix}StartDate": _to_nvd_time(start),
            f"{prefix}EndDate": _to_nvd_time(end),
            "resultsPerPage": str(page_size),
            "startIndex": str(start_index),
        }
        payload = _get_json(f"{base_url}?{urllib.parse.urlencode(params)}", api_key, timeout)

        vulns = payload.get("vulnerabilities") or []
        for entry in vulns:
            item = parse_vulnerability(entry)
            if item is not None:
                items.append(item)
                if max_items is not None and len(items) >= max_items:
                    return items

        total = int(payload.get("totalResults") or 0)
        returned = len(vulns)
        start_index += returned
        if returned == 0 or start_index >= total:
            return items
        time.sleep(pause)


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #

def parse_vulnerability(entry: dict[str, Any]) -> NvdItem | None:
    """Turn one `vulnerabilities[]` element into an NvdItem (None if unusable)."""
    cve = (entry or {}).get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    severity, score, version, vector = _best_metric(cve.get("metrics") or {})
    products, vulnerable_cpes, platform_cpes = _extract_products(cve)

    return NvdItem(
        cve_id=cve_id,
        published=_parse_time(cve.get("published")),
        last_modified=_parse_time(cve.get("lastModified")),
        description=_english_description(cve.get("descriptions") or []),
        cvss_severity=severity,
        cvss_score=score,
        cvss_version=version,
        cvss_vector=vector,
        affected_products=products,
        vulnerable_cpes=vulnerable_cpes,
        platform_cpes=platform_cpes,
        # Union of both sets, order preserved: the existing ranker and renderer
        # still read this. Task 4 of the plan retires it; until then it must not
        # change shape.
        cpe_criteria=tuple(dict.fromkeys(vulnerable_cpes + platform_cpes)),
        vuln_status=cve.get("vulnStatus"),
        source_identifier=cve.get("sourceIdentifier"),
        references=tuple(
            dict.fromkeys(
                r["url"] for r in (cve.get("references") or []) if isinstance(r, dict) and r.get("url")
            )
        ),
        raw=cve,
    )


def _english_description(descriptions: Iterable[dict[str, Any]]) -> str:
    fallback = ""
    for d in descriptions:
        value = (d.get("value") or "").strip()
        if not value:
            continue
        if (d.get("lang") or "").lower().startswith("en"):
            return value
        fallback = fallback or value
    return fallback


def _best_metric(
    metrics: dict[str, Any],
) -> tuple[str | None, float | None, str | None, str | None]:
    """Pick the highest-confidence CVSS record available, newest generation first."""
    for key in _METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next(
            (e for e in entries if (e.get("type") or "").upper() == "PRIMARY"), entries[0]
        )
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        # CVSS v2 keeps the severity band outside cvssData.
        severity = data.get("baseSeverity") or chosen.get("baseSeverity")
        return (
            str(severity).upper() if severity else None,
            float(score) if isinstance(score, (int, float)) else None,
            str(data.get("version")) if data.get("version") else None,
            data.get("vectorString"),
        )
    return None, None, None, None


def _extract_products(
    cve: dict[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Split a CVE's CPEs by NVD's `vulnerable` flag.

    Returns ``(products, vulnerable, platform)``:

      * ``products``  -- human-readable "vendor product" labels, display only
      * ``vulnerable`` -- cpeMatch entries NVD marks ``vulnerable: true``
      * ``platform``   -- every other CPE: the stack the vulnerable product runs
                          on, plus CNA-supplied CPEs that carry no flag at all

    A missing flag is treated as NOT vulnerable. Assuming otherwise is how a
    platform CPE ends up on the match surface and a Dell agent gets reported
    as an Ubuntu vulnerability.
    """
    products: list[str] = []
    vulnerable: list[str] = []
    platform: list[str] = []

    # CNA-supplied vendor/product blocks. Live NVD 2.0 records nest the rows
    # under `affected[].affectedData[]`; some carry vendor/product directly.
    for block in cve.get("affected") or []:
        if not isinstance(block, dict):
            continue
        rows = block.get("affectedData")
        if not isinstance(rows, list):
            rows = [block]
        for row in rows:
            if not isinstance(row, dict):
                continue
            label = _label(row.get("vendor"), row.get("product") or row.get("packageName"))
            if label:
                products.append(label)
            # CNA rows carry no `vulnerable` flag, so they cannot be trusted as
            # a match surface -- they land in platform with the rest.
            for criteria in row.get("cpes") or []:
                if isinstance(criteria, str) and criteria:
                    platform.append(criteria)

    # CPE configurations -- the authoritative applicability data. NVD 2.0 uses
    # `configurations` on older records and `cpeApplicability` on newer ones.
    for config in (cve.get("configurations") or []) + (cve.get("cpeApplicability") or []):
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria")
                if not criteria:
                    continue
                # NVD marks the vulnerable product true and the platform it runs
                # on false. Absent means not vulnerable -- never assume otherwise.
                if match.get("vulnerable") is True:
                    vulnerable.append(criteria)
                else:
                    platform.append(criteria)
                label = _label(*_cpe_vendor_product(criteria))
                if label:
                    products.append(label)

    return (
        tuple(dict.fromkeys(products)),
        tuple(dict.fromkeys(vulnerable)),
        tuple(dict.fromkeys(platform)),
    )


def _label(vendor: Any, product: Any) -> str:
    vendor = _clean(vendor)
    product = _clean(product)
    if vendor and product:
        return f"{vendor} {product}" if vendor != product else product
    return product or vendor or ""


def _clean(value: Any) -> str:
    text = str(value or "").strip()
    if text.lower() in ("", "n/a", "*", "-", "unknown"):
        return ""
    return text.replace("_", " ")


def _cpe_vendor_product(criteria: str) -> tuple[str, str]:
    # cpe:2.3:part:vendor:product:version:...
    parts = criteria.split(":")
    if len(parts) >= 5 and parts[0] == "cpe":
        return parts[3], parts[4]
    return "", ""


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # NVD emits naive timestamps that are UTC in practice.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _to_nvd_time(moment: datetime) -> str:
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000")


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #

def _get_json(url: str, api_key: str | None, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cyberwatch-spike/0.1", "Accept": "application/json"},
    )
    if api_key:
        request.add_header("apiKey", api_key)

    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
            return json.loads(body)
        except urllib.error.HTTPError as exc:
            last_error = exc
            # 403/503 from NVD usually means "you went too fast" -- back off once.
            if exc.code in (403, 429, 503) and attempt < 2:
                time.sleep(_SLEEP_NO_KEY * (attempt + 1))
                continue
            raise NvdError(f"NVD returned HTTP {exc.code} for {url}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
        except json.JSONDecodeError as exc:
            raise NvdError("NVD returned a non-JSON body") from exc
    raise NvdError(f"could not reach NVD: {last_error}")


if __name__ == "__main__":  # manual smoke check against the live API
    found = fetch_recent_cves(days=2, max_items=5)
    print(f"{len(found)} item(s)")
    for entry in found:
        print(
            f"  {entry.cve_id}  {entry.cvss_severity or '-':8} "
            f"{entry.published:%Y-%m-%d}  {entry.affected_products[:2]}"
        )
