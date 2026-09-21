"""Dedupe test against the LIVE NVD feed.

    python3 tests/test_dedupe_live.py

Acceptance covered here: pre-count > post-count on data from the live feed.

This test pulls the real API. That is the point -- a fixture would only prove
that dedupe collapses duplicates someone hand-wrote into a file. The thing
worth knowing is whether NVD actually republishes entries in the feed this
pipeline consumes, and whether the collapse survives real data.

The cost is that this test is slow (~40-90s) and can fail for reasons that are
not the code's fault. It does NOT silently skip on those: an unreachable feed
is reported as an error, not as a pass, because a green suite that never
reached the network is a lie. What it does do is retry once on NVD's rate
limit, which is the one failure mode that is both common and harmless.

The duplication is produced the same way run.py produces it: two pulls over
the same window, one by publication date and one by modification date,
concatenated oldest-first. Entries published in the window are necessarily
also modified in it, so they arrive twice. That is the republication the
pipeline has to survive.
"""

from __future__ import annotations

import sys
import time
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.dedupe import dedupe_by_cve_id  # noqa: E402
from src.sources.nvd import NvdError, fetch_window  # noqa: E402

WINDOW_HOURS = 24
CEILING = 8000
PER_PAGE = 2000
RATE_LIMIT_BACKOFF = 35.0  # NVD without a key: 5 requests / 30s


class LiveFeedUnavailable(RuntimeError):
    """The live feed could not be reached. Not a pass, not a code defect."""


def pull_live_feed():
    """Fetch the same concatenated feed run.py builds. Returns (feed, parts)."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=WINDOW_HOURS)

    def window(by: str):
        try:
            return fetch_window(
                start, end, max_items=CEILING, results_per_page=PER_PAGE, by=by
            )
        except NvdError as exc:
            if "429" in str(exc) or "rate" in str(exc).lower():
                time.sleep(RATE_LIMIT_BACKOFF)
                return fetch_window(
                    start, end, max_items=CEILING, results_per_page=PER_PAGE, by=by
                )
            raise LiveFeedUnavailable(f"NVD {by} window unreachable: {exc}") from exc

    published = window("published")
    modified = window("modified")
    # Oldest pull first: on a tie dedupe keeps the entry seen last, and the
    # lastMod pull carries the fresher revision.
    return published + modified, {"published": published, "modified": modified}


# Pulled once for the whole class -- one network trip, not one per assertion.
_FEED = None
_PARTS = None
_ERROR = None


def setUpModule():
    global _FEED, _PARTS, _ERROR
    try:
        _FEED, _PARTS = pull_live_feed()
    except LiveFeedUnavailable as exc:
        _ERROR = exc
    except Exception as exc:  # noqa: BLE001 -- any other failure is still a failure
        _ERROR = LiveFeedUnavailable(f"{exc.__class__.__name__}: {exc}")


class TestDedupeOnLiveFeed(unittest.TestCase):
    def setUp(self):
        if _ERROR is not None:
            self.fail(
                f"live NVD feed unavailable, so this test proved nothing: {_ERROR}. "
                "This is reported as a failure on purpose -- a skip here would let "
                "a green suite claim a live check that never happened."
            )
        self.feed = _FEED
        self.parts = _PARTS

    # -- the acceptance assertion ------------------------------------------ #

    def test_pre_count_exceeds_post_count_on_live_data(self):
        result = dedupe_by_cve_id(self.feed)
        print(
            f"\n  live feed: published={len(self.parts['published'])} "
            f"modified={len(self.parts['modified'])} "
            f"concatenated={result.pre_count} -> after dedupe={result.post_count} "
            f"({result.removed} collapsed across {len(result.groups)} CVE id(s))"
        )
        self.assertGreater(
            result.pre_count, 0,
            "the live window returned nothing at all -- nothing was tested",
        )
        self.assertGreater(
            result.pre_count, result.post_count,
            f"live feed of {result.pre_count} entries contained no republished "
            f"CVE at all, so the collapse was never exercised",
        )

    # -- what the collapse must additionally be true about ----------------- #

    def test_survivors_are_unique_by_cve_id(self):
        result = dedupe_by_cve_id(self.feed)
        ids = [i.cve_id for i in result.items if getattr(i, "cve_id", None)]
        repeats = [cve for cve, n in Counter(ids).items() if n > 1]
        self.assertEqual(repeats, [], f"dedupe left duplicates behind: {repeats[:5]}")

    def test_accounting_is_self_consistent(self):
        result = dedupe_by_cve_id(self.feed)
        self.assertEqual(result.pre_count, len(self.feed))
        self.assertEqual(result.post_count, len(result.items))
        self.assertEqual(result.removed, result.pre_count - result.post_count)
        self.assertEqual(
            result.removed, sum(len(g.dropped) for g in result.groups),
            "removed count does not match what the groups say was dropped",
        )

    def test_nothing_was_invented(self):
        """Every survivor is an object that was in the input -- by identity."""
        originals = {id(entry) for entry in self.feed}
        for survivor in dedupe_by_cve_id(self.feed).items:
            self.assertIn(id(survivor), originals)

    def test_no_cve_id_disappeared(self):
        """Collapsing revisions must not lose an id entirely."""
        before = {i.cve_id for i in self.feed if getattr(i, "cve_id", None)}
        after = {i.cve_id for i in dedupe_by_cve_id(self.feed).items
                 if getattr(i, "cve_id", None)}
        self.assertEqual(before - after, set(), "ids vanished during dedupe")

    def test_each_kept_revision_is_the_newest_of_its_group(self):
        from src.dedupe import recency_key

        result = dedupe_by_cve_id(self.feed)
        for group in result.groups:
            newest = max(recency_key(e) for e in (group.kept,) + group.dropped)
            self.assertEqual(
                recency_key(group.kept), newest,
                f"{group.cve_id}: dedupe kept an older revision",
            )

    def test_input_list_not_mutated(self):
        snapshot = list(self.feed)
        dedupe_by_cve_id(self.feed)
        self.assertEqual(self.feed, snapshot)


class TestTheLiveCheckCanFail(unittest.TestCase):
    """Prove the acceptance assertion is capable of failing on this same data."""

    def setUp(self):
        if _ERROR is not None:
            self.fail(f"live NVD feed unavailable: {_ERROR}")

    def test_a_passthrough_dedupe_fails_the_live_assertion(self):
        """A 'dedupe' that returns its input unchanged must not pass."""

        class Passthrough:
            def __init__(self, items):
                self.items = list(items)
                self.pre_count = len(self.items)
                self.post_count = len(self.items)

        broken = Passthrough(_FEED)
        with self.assertRaises(AssertionError):
            self.assertGreater(broken.pre_count, broken.post_count)

    def test_the_live_feed_really_contains_repeats(self):
        """Guard the premise: without repeats in the input, a passing collapse
        would mean nothing."""
        ids = [i.cve_id for i in _FEED if getattr(i, "cve_id", None)]
        repeated = [cve for cve, n in Counter(ids).items() if n > 1]
        self.assertTrue(
            repeated,
            "the live feed had no repeated CVE id, so the collapse assertion "
            "would have been vacuous",
        )
        print(f"\n  live repeats: {len(repeated)} CVE id(s) arrived more than once")


if __name__ == "__main__":
    unittest.main(verbosity=2)
