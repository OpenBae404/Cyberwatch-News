"""Render ranked CVE items into one markdown issue.

Contract of this stage (spike scope):

  * input  -- an ordered sequence of ranked items (most relevant first). An item
              is anything NvdItem-shaped: an object with attributes, or a plain
              dict. Nothing here imports the fetch/rank modules, so this stage
              can be exercised on its own.
  * output -- ONE markdown document, at most five items, every item carrying
              exactly four labelled fields:

                  What happened / Who is affected / How serious / What to do

              plus one line saying, in plain words, why the item is in the
              issue: known-exploited (CISA KEV, tier 1) or severity-chosen
              (tier 2). A known-exploited item is rendered in a shape the
              others do not use, so it cannot be skimmed past.

  * LLM    -- the four fields are written by the local OpenAI-compatible server
              at http://127.0.0.1:8000/v1 when it is reachable AND serving a
              model. When it is missing, unreachable, model-less, slow or
              answers with junk, every field falls back to data already on the
              item (raw NVD description, product list, CVSS, references).
              Rendering never raises because of the LLM.

Ranking stays inspectable elsewhere; this module only phrases and formats.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Iterable, Sequence

# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #

DEFAULT_LLM_BASE_URL = os.environ.get(
    "CYBERWATCH_LLM_BASE_URL", "http://127.0.0.1:8000/v1"
)
DEFAULT_LLM_MODEL = os.environ.get("CYBERWATCH_LLM_MODEL") or None
DEFAULT_TIMEOUT = float(os.environ.get("CYBERWATCH_LLM_TIMEOUT", "30"))

MAX_ITEMS = 5

# The four fields are fixed. Order and labels are part of the acceptance.
FIELD_LABELS = (
    ("what_happened", "What happened"),
    ("who_is_affected", "Who is affected"),
    ("how_serious", "How serious"),
    ("what_to_do", "What to do"),
)

# --------------------------------------------------------------------------- #
# why an item is in the issue
# --------------------------------------------------------------------------- #
#
# The ranker (src/news_rank.py) decides selection in two tiers and hands every
# item a `tier` and a `reason`. "Tier 1" means nothing to a reader, so this
# module never prints it: it prints the plain words "Known exploited" or
# "Severity-chosen", and a known-exploited item is rendered in a shape the rest
# of the issue does not use -- a badge in the tag line and a blockquote callout
# -- so it cannot be mistaken for an ordinary entry while skimming.

REASON_LABEL = "Why this is here"
KEV_BADGE = "KNOWN EXPLOITED"
KEV_LEAD = "Known exploited"
SEVERITY_LEAD = "Severity-chosen"

_KEV_DEFAULT_BODY = (
    "CISA lists this CVE in its Known Exploited Vulnerabilities catalogue, so "
    "it is being used in attacks now."
)
_SEVERITY_DEFAULT_BODY = (
    "It is not in the CISA KEV catalogue; it is here for its severity and for "
    "how widely the affected software is deployed."
)
_UNRECORDED_NOTE = (
    "Selection reason not recorded for this item -- it did not come through "
    "the ranker, so this issue cannot say whether it is known-exploited."
)

# The ranker's own sentences open with "Tier 1: " / "Tier 2: ". That is
# internal vocabulary; strip it and say it in words instead.
_TIER_PREFIX = re.compile(r"^\s*tier\s*\d+\s*[:.\-]?\s*", re.IGNORECASE)

_SEVERITY_NOTE = {
    "CRITICAL": "Critical -- treat as urgent.",
    "HIGH": "High -- patch on the next maintenance window.",
    "MEDIUM": "Medium -- schedule it, no fire drill.",
    "LOW": "Low -- housekeeping.",
}


# --------------------------------------------------------------------------- #
# item access (works for dataclasses, objects and dicts)
# --------------------------------------------------------------------------- #

def _get(item: Any, name: str, default: Any = None) -> Any:
    """Read `name` off an object attribute or a dict key. Never raises."""
    if isinstance(item, dict):
        value = item.get(name, default)
    else:
        value = getattr(item, name, default)
    return default if value is None else value


def _text(value: Any) -> str:
    return " ".join(str(value).split())


def _seq(value: Any) -> tuple[str, ...]:
    if value in (None, "", ()):
        return ()
    if isinstance(value, (str, bytes)):
        return (_text(value),)
    if isinstance(value, Iterable):
        return tuple(_text(v) for v in value if str(v).strip())
    return (_text(value),)


# --------------------------------------------------------------------------- #
# summary value object
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ItemSummary:
    """The four fields for one item, plus where they came from."""

    what_happened: str
    who_is_affected: str
    how_serious: str
    what_to_do: str
    source: str  # "llm" or "raw"

    def as_dict(self) -> dict[str, str]:
        return {key: getattr(self, key) for key, _ in FIELD_LABELS}


@dataclass(frozen=True)
class SelectionReason:
    """Why one item is in the issue, in words a reader can act on.

    `known_exploited` is a tri-state on purpose:

        True   the ranker put it in tier 1 -- CISA KEV, exploited now
        False  the ranker put it in tier 2 -- severity and reach
        None   nothing on the item says which; the document admits that
               instead of guessing, because guessing here would either
               invent an attack or hide one.
    """

    known_exploited: bool | None
    lead: str
    text: str

    @property
    def recorded(self) -> bool:
        return self.known_exploited is not None

    def sentence(self) -> str:
        """The one line that goes on the page under REASON_LABEL."""
        if self.known_exploited is None:
            return self.text
        return f"{self.lead} -- {self.text}"

    def headline(self) -> str:
        """The first sentence of `text`, for the known-exploited callout.

        The callout sits above the four fields and the full reason sits below
        them; repeating the whole paragraph in both places trains a reader to
        skip the callout, which is the one line that must not be skipped.
        """
        match = re.match(r"^(.+?[.!?])(?:\s|$)", self.text)
        return (match.group(1) if match else self.text).strip()


def _reason_flags(item: Any) -> tuple[bool | None, str]:
    """(known_exploited, ranker sentence) read off a ranked item. Never raises."""
    raw_reason = _text(_get(item, "reason", ""))

    flag = _get(item, "kev_listed", None)
    if isinstance(flag, bool):
        return flag, raw_reason

    tier = _get(item, "tier", None)
    if isinstance(tier, bool):  # a stray bool is not a tier number
        tier = None
    if isinstance(tier, int):
        return tier <= 1, raw_reason
    if isinstance(tier, str) and tier.strip().isdigit():
        return int(tier.strip()) <= 1, raw_reason

    # No tier at all: a KEV record hanging off the item still settles it.
    if _get(item, "kev", None) is not None:
        return True, raw_reason

    # An unranked item with a reason string is the last resort. Only the
    # ranker's own tier vocabulary is trusted here -- never free text, which
    # could say "exploited" about anything.
    match = re.match(r"\s*tier\s*(\d+)\b", raw_reason, re.IGNORECASE)
    if match:
        return int(match.group(1)) <= 1, raw_reason

    return None, raw_reason


def selection_reason(item: Any) -> SelectionReason:
    """Say, in plain words, whether this item is known-exploited or severity-chosen."""
    known_exploited, raw_reason = _reason_flags(item)
    body = _TIER_PREFIX.sub("", raw_reason).strip()

    if known_exploited is None:
        return SelectionReason(None, "", _UNRECORDED_NOTE)

    if known_exploited:
        return SelectionReason(True, KEV_LEAD, body or _KEV_DEFAULT_BODY)
    return SelectionReason(False, SEVERITY_LEAD, body or _SEVERITY_DEFAULT_BODY)


# --------------------------------------------------------------------------- #
# fallback: phrase the four fields straight from the item's own data
# --------------------------------------------------------------------------- #

def raw_summary(item: Any) -> ItemSummary:
    """Four fields built only from NVD data. This is the no-LLM path."""
    cve_id = _text(_get(item, "cve_id", "")) or "this CVE"
    description = _text(_get(item, "description", "")) or (
        "NVD published no description for this entry yet."
    )

    products = _seq(_get(item, "affected_products", ()))
    cpes = _seq(_get(item, "cpe_criteria", ()))
    matched = _seq(_get(item, "matched_terms", ())) or _seq(_get(item, "matches", ()))

    who_parts: list[str] = []
    if products:
        who_parts.append("Affected products per NVD: " + ", ".join(products[:6]) + ".")
    elif cpes:
        who_parts.append("Affected CPEs per NVD: " + ", ".join(cpes[:3]) + ".")
    else:
        who_parts.append("NVD lists no affected product for this entry yet.")
    if matched:
        who_parts.append("Matches this homelab on: " + ", ".join(matched[:6]) + ".")
    who = " ".join(who_parts)

    severity = _text(_get(item, "cvss_severity", "")).upper()
    score = _get(item, "cvss_score", None)
    version = _text(_get(item, "cvss_version", ""))
    vector = _text(_get(item, "cvss_vector", ""))
    serious_parts: list[str] = []
    if severity or score is not None:
        head = severity or "Unrated"
        if score is not None:
            head += f" (CVSS {score}"
            head += f", v{version})" if version else ")"
        serious_parts.append(head + ".")
        if severity in _SEVERITY_NOTE:
            serious_parts.append(_SEVERITY_NOTE[severity])
    else:
        serious_parts.append("NVD has not scored this entry yet; severity unknown.")
    if vector:
        serious_parts.append(f"Vector: {vector}.")
    rank_score = _get(item, "score", None)
    if rank_score is not None:
        serious_parts.append(f"Homelab relevance score: {rank_score}.")
    serious = " ".join(serious_parts)

    refs = _seq(_get(item, "references", ()))
    url = _text(_get(item, "url", "")) or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    todo_parts = [
        f"Check whether the listed versions run here, then apply the vendor fix for {cve_id}."
    ]
    todo_parts.append(f"Details: {url}")
    if refs:
        todo_parts.append("References: " + ", ".join(refs[:3]))
    todo = " ".join(todo_parts)

    return ItemSummary(
        what_happened=description,
        who_is_affected=who,
        how_serious=serious,
        what_to_do=todo,
        source="raw",
    )


# --------------------------------------------------------------------------- #
# LLM client (stdlib only, fails soft by design)
# --------------------------------------------------------------------------- #

class LLMClient:
    """Minimal OpenAI-compatible chat client.

    Every failure mode -- no server, no model loaded, HTTP error, timeout,
    unparseable body -- surfaces as `available is False` or a `None` answer.
    It never raises at the caller.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_LLM_BASE_URL,
        *,
        model: str | None = DEFAULT_LLM_MODEL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.model = model
        self.error: str | None = None
        self.available = self._probe()

    # -- plumbing -------------------------------------------------------- #

    def _request(self, path: str, payload: dict | None = None) -> Any:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST" if data else "GET",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    def _probe(self) -> bool:
        """True only if the server answers AND has a usable model."""
        try:
            body = self._request("/models")
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
            self.error = f"unreachable: {exc.__class__.__name__}: {exc}"
            return False
        # A reachable server may answer with any JSON shape at all. Anything
        # that is not an OpenAI-style {"data": [...]} object is "no usable
        # model", never an exception escaping the constructor.
        try:
            if not isinstance(body, dict):
                self.error = (
                    f"server reachable but /models answered with "
                    f"{type(body).__name__}, not an object"
                )
                return False
            data = body.get("data")
            if not isinstance(data, list):
                self.error = (
                    f"server reachable but /models has no model list "
                    f"(data is {type(data).__name__})"
                )
                return False
            names = [m.get("id") for m in data if isinstance(m, dict) and m.get("id")]
        except (AttributeError, TypeError, KeyError, IndexError) as exc:
            self.error = f"unusable /models body: {exc.__class__.__name__}: {exc}"
            return False
        if self.model:
            return True
        if not names:
            self.error = "server reachable but serving no models"
            return False
        self.model = names[0]
        return True

    # -- use ------------------------------------------------------------- #

    def complete(self, system: str, user: str, *, max_tokens: int = 600) -> str | None:
        if not self.available:
            return None
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }
        try:
            body = self._request("/chat/completions", payload)
            content = body["choices"][0]["message"]["content"]
        except (
            urllib.error.URLError,
            OSError,
            ValueError,
            KeyError,
            IndexError,
            TypeError,
            json.JSONDecodeError,
        ) as exc:
            self.error = f"completion failed: {exc.__class__.__name__}: {exc}"
            return None
        # A reachable, model-serving server may still answer with a non-string
        # content (the OpenAI content-part array, an object, a number). Treat
        # it as no answer instead of letting it reach .strip() downstream.
        if not isinstance(content, str):
            self.error = (
                f"completion answered with content of type "
                f"{type(content).__name__}, not a string"
            )
            return None
        return content

    def describe(self) -> str:
        if self.available:
            return f"local LLM at {self.base_url} (model: {self.model})"
        return f"no LLM ({self.base_url}: {self.error})"


# --------------------------------------------------------------------------- #
# LLM summarisation
# --------------------------------------------------------------------------- #

_SYSTEM = (
    "You rewrite CVE records for a homelab operator running Proxmox, "
    "Debian/Ubuntu, Docker, Tailscale, a UGREEN NAS and nginx. "
    "Answer with a JSON object and nothing else. Keys, all required: "
    "what_happened, who_is_affected, how_serious, what_to_do. "
    "Each value is one or two plain sentences, no markdown, no bullet points. "
    "Use only facts from the record; never invent versions, dates or patches."
)


def _prompt_for(item: Any) -> str:
    fields = {
        "cve_id": _text(_get(item, "cve_id", "")),
        "published": str(_get(item, "published", "") or ""),
        "description": _text(_get(item, "description", "")),
        "cvss_severity": _text(_get(item, "cvss_severity", "")),
        "cvss_score": _get(item, "cvss_score", None),
        "cvss_vector": _text(_get(item, "cvss_vector", "")),
        "affected_products": list(_seq(_get(item, "affected_products", ()))[:10]),
        "matched_profile_terms": list(
            (_seq(_get(item, "matched_terms", ())) or _seq(_get(item, "matches", ())))[:10]
        ),
        "references": list(_seq(_get(item, "references", ()))[:5]),
    }
    return "CVE record:\n" + json.dumps(fields, indent=2, default=str)


def _parse_summary(text: Any) -> dict[str, str] | None:
    """Pull the four fields out of an LLM answer. None if it is unusable."""
    if not isinstance(text, str):
        return None  # a non-string answer is no answer, never a .strip() crash
    if not text or not text.strip():
        return None
    blob = text.strip()
    if blob.startswith("```"):
        blob = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", blob).strip()
    if not blob.startswith("{"):
        match = re.search(r"\{.*\}", blob, re.DOTALL)
        blob = match.group(0) if match else blob
    try:
        data = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    out: dict[str, str] = {}
    for key, _label in FIELD_LABELS:
        value = data.get(key)
        if isinstance(value, (list, tuple)):
            value = " ".join(str(v) for v in value)
        if value is None or not str(value).strip():
            return None  # partial answers are not trusted -- fall back wholesale
        out[key] = _text(value)
    return out


def summarise_item(item: Any, client: LLMClient | None = None) -> ItemSummary:
    """Four fields for one item. Falls back to `raw_summary` on any trouble."""
    fallback = raw_summary(item)
    if client is None or not client.available:
        return fallback
    answer = client.complete(_SYSTEM, _prompt_for(item))
    parsed = _parse_summary(answer or "")
    if parsed is None:
        return fallback
    return ItemSummary(source="llm", **parsed)


# --------------------------------------------------------------------------- #
# markdown rendering
# --------------------------------------------------------------------------- #

def render_item(item: Any, summary: ItemSummary | None = None, *, index: int | None = None) -> str:
    """One markdown block: heading, the four labelled fields, and why it is here.

    A known-exploited item is shaped differently from a severity-chosen one --
    the badge in the tag line and the blockquote callout appear on tier-1 items
    only -- so the difference survives skimming, not just reading.
    """
    if summary is None:
        summary = raw_summary(item)

    cve_id = _text(_get(item, "cve_id", "")) or "UNKNOWN-CVE"
    url = _text(_get(item, "url", "")) or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    severity = _text(_get(item, "cvss_severity", "")).upper()
    score = _get(item, "cvss_score", None)
    reason = selection_reason(item)

    number = f"{index}. " if index is not None else ""
    marker = f"{KEV_BADGE} -- " if reason.known_exploited else ""
    heading = f"## {number}{marker}[{cve_id}]({url})"
    tags = []
    if reason.known_exploited:
        # First tag, so the badge is the first thing after the title.
        tags.append(KEV_BADGE)
    if severity:
        tags.append(severity)
    if score is not None:
        tags.append(f"CVSS {score}")
    published = _get(item, "published", None)
    if isinstance(published, datetime):
        tags.append(f"published {published:%Y-%m-%d}")
    if tags:
        heading += "  \n`" + "` `".join(tags) + "`"

    lines = [heading, ""]
    if reason.known_exploited:
        # Callout above the fields: a reader who stops at the first line still
        # learns this one is being exploited.
        lines.append(f"> **{KEV_BADGE}.** {reason.headline()}")
        lines.append("")
    values = summary.as_dict()
    for key, label in FIELD_LABELS:
        lines.append(f"**{label}:** {values[key]}")
        lines.append("")
    lines.append(f"**{REASON_LABEL}:** {reason.sentence()}")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_issue(
    items: Sequence[Any],
    *,
    max_items: int = MAX_ITEMS,
    client: LLMClient | None = None,
    use_llm: bool = True,
    title: str = "CyberWatch",
    issue_date: date | None = None,
    total_considered: int | None = None,
) -> str:
    """Join per-item blocks into ONE markdown issue document.

    `client` is built on demand when `use_llm` is true; pass one in to reuse a
    probe, or pass `use_llm=False` to force the raw path.
    """
    chosen = list(items)[: max(0, max_items)]
    issue_date = issue_date or datetime.now(timezone.utc).date()

    # Zero matches is a result, not a failure. Say so and stop: no LLM probe
    # (there is nothing to summarise), no item blocks, no near-misses. The
    # branch returns early so no later line can accidentally pad the page.
    if not chosen:
        return _zero_match_issue(title, issue_date, total_considered)

    if client is None and use_llm:
        client = LLMClient()

    summaries = [summarise_item(it, client) for it in chosen]
    llm_used = sum(1 for s in summaries if s.source == "llm")

    reasons = [selection_reason(it) for it in chosen]

    header = [
        f"# {title} -- {issue_date:%Y-%m-%d}",
        "",
        _intro(len(chosen), total_considered, max_items),
        "",
        _selection_note(reasons),
        "",
    ]

    blocks = [
        render_item(it, summary, index=n)
        for n, (it, summary) in enumerate(zip(chosen, summaries), start=1)
    ]

    if client is not None and client.available and llm_used:
        note = f"Summaries: {llm_used}/{len(chosen)} written by {client.describe()}."
    elif client is not None and client.available:
        note = f"Summaries: raw NVD text -- {client.describe()} returned nothing usable."
    else:
        detail = client.describe() if client is not None else "LLM disabled"
        note = f"Summaries: raw NVD text -- {detail}."

    footer = ["---", "", f"_{note}_", "_Source: NVD CVE 2.0 API._", ""]

    return "\n".join(header) + "\n---\n\n" + "\n---\n\n".join(blocks) + "\n" + "\n".join(footer)


def _zero_match_issue(
    title: str, issue_date: date, total_considered: int | None
) -> str:
    """The whole document for a run where nothing matched.

    Built separately from the item path on purpose: there is no item, so there
    is nothing to summarise, nothing to cap and no LLM to ask. What the reader
    needs instead is the outcome in words, the size of the haystack, and no
    consolation prize -- a near-miss shown here would be read as a finding.
    """
    if total_considered is not None:
        considered = (
            f"No CVE matched the homelab profile. "
            f"{total_considered} CVE{'s' if total_considered != 1 else ''} "
            f"considered in this window."
        )
    else:
        considered = (
            "No CVE matched the homelab profile. The number of CVEs considered "
            "was not recorded for this run."
        )

    return "\n".join(
        [
            f"# {title} -- {issue_date:%Y-%m-%d}",
            "",
            considered,
            "",
            "Nothing to do. This is a real result, not a broken run: the feed "
            "was read and ranked, and no entry cleared the relevance bar. "
            "Entries that scored below the bar are deliberately left out -- "
            "anything listed here would read as something to act on.",
            "",
            "---",
            "",
            "_Summaries: none written -- there was nothing to summarise._",
            "_Source: NVD CVE 2.0 API._",
            "",
        ]
    )


def _selection_note(reasons: Sequence[SelectionReason]) -> str:
    """One line saying how many items are known-exploited and how many are not.

    Counted from the same `SelectionReason` objects the item blocks use, so the
    summary cannot drift away from the per-item wording.
    """
    exploited = sum(1 for r in reasons if r.known_exploited is True)
    severity = sum(1 for r in reasons if r.known_exploited is False)
    unknown = sum(1 for r in reasons if r.known_exploited is None)

    parts: list[str] = []
    if exploited:
        parts.append(
            f"{exploited} known-exploited (in the CISA KEV catalogue, attacks "
            f"are happening now)"
        )
    if severity:
        parts.append(f"{severity} severity-chosen (not known-exploited)")
    if unknown:
        parts.append(f"{unknown} with no recorded selection reason")

    if not parts:
        return "No item carries a selection reason."
    if exploited == 0 and unknown == 0:
        return (
            "Nothing in today's issue is known-exploited: all "
            f"{severity} item{'s are' if severity != 1 else ' is'} "
            "severity-chosen. Each item says so under "
            f"\"{REASON_LABEL}\"."
        )
    joined = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    return f"Selection: {joined}. Each item says which under \"{REASON_LABEL}\"."


def _intro(shown: int, total_considered: int | None, max_items: int) -> str:
    if total_considered is not None:
        return (
            f"{shown} item{'s' if shown != 1 else ''} out of {total_considered} "
            f"considered, ranked against the homelab profile (cap {max_items})."
        )
    return (
        f"{shown} item{'s' if shown != 1 else ''} ranked against the homelab "
        f"profile (cap {max_items})."
    )
