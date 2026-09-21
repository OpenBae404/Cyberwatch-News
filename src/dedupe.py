"""Collapse NVD republished entries by CVE id.

The NVD feed hands the same CVE back more than once as soon as you pull more
than one window -- a CVE published on Monday and revised on Wednesday shows up
in both the `published` window and the `lastMod` window, and a long-running
collector re-reads overlapping windows anyway. Those are the *same* finding at
two revisions, and an issue that lists both is an issue nobody trusts.

This module does exactly one thing: group items by CVE id and keep the most
recently published entry of each group.

Deliberately OUT OF SCOPE (spike boundary, see Plans.md):
  * cross-id dedupe (GHSA/DSA/vendor advisory pointing at the same flaw)
  * near-duplicate text clustering or description similarity
  * merging fields from several revisions into one synthetic record

Nothing here touches the network and nothing is cached; it is a pure function
over a list, so the ranker downstream stays inspectable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

__all__ = [
    "DedupeResult",
    "DuplicateGroup",
    "dedupe_by_cve_id",
    "recency_key",
]

# Sorts strictly below any real NVD timestamp, so an entry with no date never
# beats one that has a date.
_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class DuplicateGroup:
    """One CVE id that arrived more than once, and what happened to it."""

    cve_id: str
    kept: Any
    dropped: tuple[Any, ...]

    @property
    def revisions(self) -> int:
        return 1 + len(self.dropped)


@dataclass(frozen=True)
class DedupeResult:
    """Survivors plus the counts the acceptance test asserts on."""

    items: list[Any]
    pre_count: int
    post_count: int
    groups: tuple[DuplicateGroup, ...] = field(default=())

    @property
    def removed(self) -> int:
        """How many entries the collapse dropped (pre_count - post_count)."""
        return self.pre_count - self.post_count

    @property
    def collapsed_ids(self) -> tuple[str, ...]:
        """CVE ids that actually had more than one entry in the input."""
        return tuple(g.cve_id for g in self.groups)

    def __len__(self) -> int:
        return self.post_count

    def __iter__(self):
        return iter(self.items)

    def summary(self) -> str:
        return (
            f"dedupe: {self.pre_count} in -> {self.post_count} out "
            f"({self.removed} republished entr{'y' if self.removed == 1 else 'ies'} "
            f"collapsed across {len(self.groups)} CVE id"
            f"{'' if len(self.groups) == 1 else 's'})"
        )


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #

def dedupe_by_cve_id(items: Iterable[Any]) -> DedupeResult:
    """Keep one entry per CVE id -- the most recently published one.

    Accepts :class:`src.sources.nvd.NvdItem` instances, or any object/mapping
    exposing a CVE id and (optionally) `published` / `last_modified`.

    Ordering rules, in order of application:
      1. newest `published` wins;
      2. on an equal (or missing) `published`, newest `last_modified` wins --
         that is the revision case, where NVD keeps the original publication
         date and only bumps the modification date;
      3. on a full tie, the entry seen LAST wins, because a concatenated fetch
         appends the fresher pull after the older one.

    Entries with no recoverable CVE id are passed through untouched rather than
    dropped: losing a record silently would be worse than a scruffy one, and
    the ranker downstream can still judge it.

    Input order of the survivors is preserved -- this returns a filtered feed,
    not a re-sorted one.
    """
    ordered = list(items)
    pre_count = len(ordered)

    # position -> chosen entry, so survivors come back in first-seen order.
    best_index: dict[str, int] = {}
    revisions: dict[str, list[Any]] = {}
    passthrough: list[int] = []
    chosen: dict[int, Any] = {}

    for position, entry in enumerate(ordered):
        cve_id = _cve_id(entry)
        if not cve_id:
            passthrough.append(position)
            chosen[position] = entry
            continue

        revisions.setdefault(cve_id, []).append(entry)
        previous_index = best_index.get(cve_id)
        if previous_index is None:
            best_index[cve_id] = position
            chosen[position] = entry
            continue

        incumbent = chosen[previous_index]
        # `>=` implements rule 3: a later entry wins an exact tie.
        if recency_key(entry) >= recency_key(incumbent):
            chosen[previous_index] = entry

    survivors = [chosen[i] for i in sorted(set(best_index.values()) | set(passthrough))]

    groups = tuple(
        DuplicateGroup(
            cve_id=cve_id,
            kept=chosen[best_index[cve_id]],
            dropped=tuple(e for e in entries if e is not chosen[best_index[cve_id]]),
        )
        for cve_id, entries in revisions.items()
        if len(entries) > 1
    )

    return DedupeResult(
        items=survivors,
        pre_count=pre_count,
        post_count=len(survivors),
        groups=groups,
    )


def recency_key(entry: Any) -> tuple[datetime, datetime]:
    """Sortable (published, last_modified) key; missing dates sort lowest."""
    return (
        _as_utc(_field(entry, "published", "publishedDate", "published_at")),
        _as_utc(_field(entry, "last_modified", "lastModified", "lastModifiedDate")),
    )


# --------------------------------------------------------------------------- #
# attribute plumbing -- tolerant of dataclasses and raw NVD mappings
# --------------------------------------------------------------------------- #

def _cve_id(entry: Any) -> str:
    raw = _field(entry, "cve_id", "cveId", "id")
    if raw is None and isinstance(entry, dict):
        # A raw `vulnerabilities[]` element from the API.
        cve = entry.get("cve")
        if isinstance(cve, dict):
            raw = cve.get("id")
    return str(raw).strip().upper() if raw else ""


def _field(entry: Any, *names: str) -> Any:
    for name in names:
        if isinstance(entry, dict):
            if name in entry and entry[name] is not None:
                return entry[name]
            continue
        value = getattr(entry, name, None)
        if value is not None:
            return value
    return None


def _as_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return _EPOCH
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return _EPOCH


def counts(items: Sequence[Any]) -> tuple[int, int]:
    """Convenience for tests: (pre_count, post_count) for one feed."""
    result = dedupe_by_cve_id(items)
    return result.pre_count, result.post_count
