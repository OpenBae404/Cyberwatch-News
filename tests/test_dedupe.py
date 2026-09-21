"""Offline unit tests for src/dedupe.py -- deterministic, no network.

Run:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.dedupe import DedupeResult, dedupe_by_cve_id, recency_key  # noqa: E402

UTC = timezone.utc
T0 = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


@dataclass(frozen=True)
class FakeItem:
    """Same attribute surface as NvdItem, minus everything dedupe ignores."""

    cve_id: str
    published: datetime | None = None
    last_modified: datetime | None = None
    tag: str = ""


class TestCounts(unittest.TestCase):
    def test_empty_feed(self):
        result = dedupe_by_cve_id([])
        self.assertEqual((result.pre_count, result.post_count), (0, 0))
        self.assertEqual(result.items, [])
        self.assertEqual(result.groups, ())
        self.assertEqual(result.removed, 0)

    def test_no_duplicates_is_a_no_op(self):
        feed = [FakeItem(f"CVE-2026-{n:04d}", T0) for n in range(5)]
        result = dedupe_by_cve_id(feed)
        self.assertEqual(result.pre_count, 5)
        self.assertEqual(result.post_count, 5)
        self.assertEqual(result.items, feed)
        self.assertEqual(result.groups, ())

    def test_pre_count_exceeds_post_count_when_republished(self):
        feed = [
            FakeItem("CVE-2026-0001", T0, T0, tag="v1"),
            FakeItem("CVE-2026-0002", T0, T0, tag="other"),
            FakeItem("CVE-2026-0001", T0, T0 + timedelta(days=2), tag="v2"),
        ]
        result = dedupe_by_cve_id(feed)
        self.assertGreater(result.pre_count, result.post_count)
        self.assertEqual((result.pre_count, result.post_count), (3, 2))
        self.assertEqual(result.removed, 1)
        self.assertEqual(result.collapsed_ids, ("CVE-2026-0001",))


class TestKeepsNewest(unittest.TestCase):
    def test_newest_published_wins_regardless_of_input_order(self):
        older = FakeItem("CVE-2026-0001", T0, T0, tag="older")
        newer = FakeItem("CVE-2026-0001", T0 + timedelta(days=1), T0, tag="newer")
        for feed in ([older, newer], [newer, older]):
            with self.subTest(order=[i.tag for i in feed]):
                result = dedupe_by_cve_id(feed)
                self.assertEqual(result.post_count, 1)
                self.assertEqual(result.items[0].tag, "newer")

    def test_equal_published_falls_back_to_last_modified(self):
        stale = FakeItem("CVE-2026-0001", T0, T0, tag="rev1")
        fresh = FakeItem("CVE-2026-0001", T0, T0 + timedelta(hours=6), tag="rev2")
        result = dedupe_by_cve_id([fresh, stale])
        self.assertEqual(result.items[0].tag, "rev2")

    def test_entry_with_a_date_beats_one_without(self):
        dated = FakeItem("CVE-2026-0001", T0, T0, tag="dated")
        undated = FakeItem("CVE-2026-0001", None, None, tag="undated")
        result = dedupe_by_cve_id([dated, undated])
        self.assertEqual(result.items[0].tag, "dated")

    def test_exact_tie_keeps_the_later_entry(self):
        first = FakeItem("CVE-2026-0001", T0, T0, tag="first")
        second = FakeItem("CVE-2026-0001", T0, T0, tag="second")
        result = dedupe_by_cve_id([first, second])
        self.assertEqual(result.items[0].tag, "second")

    def test_three_revisions_collapse_to_the_newest(self):
        feed = [
            FakeItem("CVE-2026-0001", T0, T0, tag="v1"),
            FakeItem("CVE-2026-0001", T0, T0 + timedelta(days=5), tag="v3"),
            FakeItem("CVE-2026-0001", T0, T0 + timedelta(days=1), tag="v2"),
        ]
        result = dedupe_by_cve_id(feed)
        self.assertEqual(result.post_count, 1)
        self.assertEqual(result.items[0].tag, "v3")
        self.assertEqual(result.groups[0].revisions, 3)
        self.assertEqual({d.tag for d in result.groups[0].dropped}, {"v1", "v2"})


class TestOrderAndShape(unittest.TestCase):
    def test_survivor_order_follows_first_sighting(self):
        feed = [
            FakeItem("CVE-2026-0003", T0, tag="c"),
            FakeItem("CVE-2026-0001", T0, tag="a"),
            FakeItem("CVE-2026-0003", T0 + timedelta(days=1), tag="c2"),
            FakeItem("CVE-2026-0002", T0, tag="b"),
        ]
        result = dedupe_by_cve_id(feed)
        self.assertEqual([i.cve_id for i in result.items],
                         ["CVE-2026-0003", "CVE-2026-0001", "CVE-2026-0002"])
        self.assertEqual(result.items[0].tag, "c2")

    def test_ids_are_matched_case_insensitively_and_trimmed(self):
        feed = [
            FakeItem("cve-2026-0001 ", T0, T0),
            FakeItem("CVE-2026-0001", T0, T0 + timedelta(days=1)),
        ]
        self.assertEqual(dedupe_by_cve_id(feed).post_count, 1)

    def test_id_less_entries_pass_through_instead_of_vanishing(self):
        feed = [
            FakeItem("", T0, tag="nameless-1"),
            FakeItem("CVE-2026-0001", T0),
            FakeItem("", T0, tag="nameless-2"),
        ]
        result = dedupe_by_cve_id(feed)
        self.assertEqual(result.post_count, 3)
        self.assertEqual([i.tag for i in result.items if not i.cve_id],
                         ["nameless-1", "nameless-2"])

    def test_accepts_raw_nvd_mappings(self):
        feed = [
            {"cve": {"id": "CVE-2026-0001", "published": "2026-09-01T12:00:00.000",
                     "lastModified": "2026-09-01T12:00:00.000"}},
            {"cve": {"id": "CVE-2026-0001", "published": "2026-09-01T12:00:00.000",
                     "lastModified": "2026-09-04T09:00:00.000"}},
        ]
        result = dedupe_by_cve_id(feed)
        self.assertEqual((result.pre_count, result.post_count), (2, 1))
        self.assertEqual(result.items[0]["cve"]["lastModified"], "2026-09-04T09:00:00.000")

    def test_result_is_iterable_and_sized_like_the_survivors(self):
        result = dedupe_by_cve_id([FakeItem("CVE-2026-0001", T0),
                                   FakeItem("CVE-2026-0001", T0)])
        self.assertIsInstance(result, DedupeResult)
        self.assertEqual(len(result), 1)
        self.assertEqual(len(list(result)), 1)
        self.assertIn("2 in -> 1 out", result.summary())

    def test_naive_timestamps_do_not_raise(self):
        naive = datetime(2026, 9, 2, 8, 0)
        feed = [FakeItem("CVE-2026-0001", T0, T0, tag="aware"),
                FakeItem("CVE-2026-0001", naive, naive, tag="naive")]
        self.assertEqual(dedupe_by_cve_id(feed).items[0].tag, "naive")

    def test_recency_key_is_total_and_sortable(self):
        keys = [recency_key(FakeItem("x")), recency_key(FakeItem("x", T0))]
        self.assertLess(keys[0], keys[1])


class TestScopeBoundary(unittest.TestCase):
    """Out of scope: anything that is not a same-CVE-id republish."""

    def test_different_ids_describing_one_flaw_are_both_kept(self):
        feed = [
            FakeItem("CVE-2026-0001", T0, tag="nvd"),
            FakeItem("GHSA-aaaa-bbbb-cccc", T0, tag="ghsa-for-the-same-flaw"),
        ]
        result = dedupe_by_cve_id(feed)
        self.assertEqual(result.post_count, 2)
        self.assertEqual(result.groups, ())


if __name__ == "__main__":
    unittest.main(verbosity=2)
