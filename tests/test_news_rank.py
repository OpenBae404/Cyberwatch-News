"""Tests for src/news_rank.py -- the two-tier newsletter selection.

Offline and deterministic: no network, no live feed, no clock dependence. The
fixtures are hand-built NvdItem-shaped records, so every assertion is about the
ranking rule and nothing else.

The test this module exists for is
`test_kev_moderate_outranks_non_kev_higher_cvss`: a KEV MEDIUM beating a
non-KEV CRITICAL is the whole selection rule in one assertion. If that ever
goes green by accident, the ranker has quietly become a severity sorter.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.news_rank import (
    DEFAULT_REACH_FILE,
    FALLBACK_TIER,
    KEV_TIER,
    MAX_ITEMS,
    RankedItem,
    ReachTable,
    load_reach_table,
    rank_news,
    severity_band,
)

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class FakeItem:
    """NvdItem-shaped, only the fields the ranker reads."""

    cve_id: str
    cvss_severity: str | None = None
    cvss_score: float | None = None
    affected_products: tuple[str, ...] = ()
    vulnerable_cpes: tuple[str, ...] = ()
    platform_cpes: tuple[str, ...] = ()
    cpe_criteria: tuple[str, ...] = ()
    published: datetime | None = NOW
    description: str = ""


@dataclass(frozen=True)
class FakeKevEntry:
    """KevEntry-shaped: what the reason line quotes."""

    cve_id: str
    vendor: str = ""
    product: str = ""
    date_added: date | None = date(2026, 9, 20)
    known_ransomware: bool = False

    @property
    def label(self) -> str:
        if self.vendor and self.product and self.vendor.lower() != self.product.lower():
            return f"{self.vendor} {self.product}"
        return self.product or self.vendor or self.cve_id


def kev_catalog(*entries: FakeKevEntry):
    """A minimal stand-in for KevCatalog: the ranker only calls by_cve_id."""

    class _Catalog:
        def __init__(self, rows):
            self._rows = {r.cve_id.upper(): r for r in rows}

        def by_cve_id(self, cve_id: str):
            return self._rows.get(str(cve_id).strip().upper())

    return _Catalog(entries)


REACH_TEXT = """
# test reach table
100  windows
90   nginx
50   jenkins
10   obscurecms
"""


def small_table() -> ReachTable:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(REACH_TEXT)
        path = handle.name
    return load_reach_table(path)


# --------------------------------------------------------------------------- #
# the acceptance test: tier beats severity
# --------------------------------------------------------------------------- #

class TestTierBeatsSeverity(unittest.TestCase):
    def test_kev_moderate_outranks_non_kev_higher_cvss(self):
        """A KEV MEDIUM 5.3 must outrank a non-KEV CRITICAL 9.8.

        This is the selection rule from Plans.md stated as an assertion:
        being exploited in the wild is a stronger signal than a self-reported
        score. A severity sorter fails this test, which is the point.
        """
        kev_medium = FakeItem(
            cve_id="CVE-2026-1000",
            cvss_severity="MEDIUM",
            cvss_score=5.3,
            affected_products=("obscurecms obscurecms",),
        )
        non_kev_critical = FakeItem(
            cve_id="CVE-2026-2000",
            cvss_severity="CRITICAL",
            cvss_score=9.8,
            affected_products=("microsoft windows",),
        )

        ranked = rank_news(
            [non_kev_critical, kev_medium],           # worst-case input order
            kev_catalog(FakeKevEntry("CVE-2026-1000", "ObscureCMS", "ObscureCMS")),
            reach=small_table(),
        )

        self.assertEqual(
            [r.cve_id for r in ranked],
            ["CVE-2026-1000", "CVE-2026-2000"],
            "the KEV MEDIUM must come first: exploited outranks scored",
        )
        self.assertEqual(ranked[0].tier, KEV_TIER)
        self.assertEqual(ranked[1].tier, FALLBACK_TIER)
        # And it must not be an accident of reach: the loser has the higher reach.
        self.assertGreater(ranked[1].reach, ranked[0].reach)

    def test_kev_low_outranks_non_kev_critical(self):
        """The same rule at the extreme: KEV LOW 2.1 over non-KEV CRITICAL 10.0."""
        ranked = rank_news(
            [
                FakeItem("CVE-2026-3000", "CRITICAL", 10.0, ("microsoft windows",)),
                FakeItem("CVE-2026-3001", "LOW", 2.1, ("obscurecms obscurecms",)),
            ],
            kev_catalog(FakeKevEntry("CVE-2026-3001")),
            reach=small_table(),
        )
        self.assertEqual(ranked[0].cve_id, "CVE-2026-3001")

    def test_every_kev_item_precedes_every_non_kev_item(self):
        """Tier is absolute, not a weight that a big enough score can overcome."""
        items = [FakeItem(f"CVE-2026-40{n:02d}", "CRITICAL", 9.9) for n in range(6)]
        items += [FakeItem(f"CVE-2026-41{n:02d}", "LOW", 1.0) for n in range(3)]
        listed = {i.cve_id for i in items[-3:]}

        ranked = rank_news(
            items,
            kev_catalog(*(FakeKevEntry(c) for c in listed)),
            reach=small_table(),
            limit=20,
        )
        tiers = [r.tier for r in ranked]
        self.assertEqual(tiers, sorted(tiers), "tier 1 items must all precede tier 2")


# --------------------------------------------------------------------------- #
# ordering inside a tier
# --------------------------------------------------------------------------- #

class TestWithinTierOrder(unittest.TestCase):
    def test_severity_orders_before_reach(self):
        """CRITICAL in obscure software beats HIGH in Windows.

        Reach breaks ties between comparably serious bugs; it does not promote
        a less serious one.
        """
        ranked = rank_news(
            [
                FakeItem("CVE-2026-5001", "HIGH", 8.8, ("microsoft windows",)),
                FakeItem("CVE-2026-5002", "CRITICAL", 9.1, ("obscurecms obscurecms",)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(ranked[0].cve_id, "CVE-2026-5002")
        self.assertEqual(ranked[0].reach, 10)
        self.assertEqual(ranked[1].reach, 100)

    def test_reach_breaks_a_severity_tie(self):
        """Same band: the software more readers run goes first."""
        ranked = rank_news(
            [
                FakeItem("CVE-2026-6001", "HIGH", 7.5, ("obscurecms obscurecms",)),
                FakeItem("CVE-2026-6002", "HIGH", 7.5, ("nginx nginx",)),
                FakeItem("CVE-2026-6003", "HIGH", 7.5, ("microsoft windows",)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(
            [r.cve_id for r in ranked],
            ["CVE-2026-6003", "CVE-2026-6002", "CVE-2026-6001"],
        )
        self.assertEqual([r.reach for r in ranked], [100, 90, 10])

    def test_reach_matches_vulnerable_cpe_vendor_and_product(self):
        """A vulnerable CPE is a reach signal even with no product label."""
        ranked = rank_news(
            [FakeItem("CVE-2026-6100", "HIGH", 7.0,
                      vulnerable_cpes=("cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*",))],
            None,
            reach=small_table(),
        )
        self.assertEqual(ranked[0].reach, 90)
        self.assertEqual(ranked[0].reach_match, "nginx")

    def test_platform_cpes_are_not_a_reach_surface(self):
        """The live defect: a `vulnerable: false` CPE must not score reach.

        CVE-2026-87886 (Acronis Backup) carries a platform linux:linux_kernel
        CPE. The kernel is what the agent runs on, not what the bug is in, so
        it scored reach 100 for software the CVE does not affect.
        """
        acronis = FakeItem(
            "CVE-2026-87886", "HIGH", 7.8,
            vulnerable_cpes=("cpe:2.3:a:acronis:backup:12.5:*:*:*:*:*:*:*",),
            platform_cpes=("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",),
            cpe_criteria=(
                "cpe:2.3:a:acronis:backup:12.5:*:*:*:*:*:*:*",
                "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
            ),
        )
        ranked = rank_news([acronis], None, reach=small_table())
        self.assertEqual(ranked[0].reach, 0)
        self.assertEqual(ranked[0].reach_match, "")

    def test_reach_ignores_the_description(self):
        """"Also affects Windows" in prose is not reach -- only product data is."""
        ranked = rank_news(
            [FakeItem("CVE-2026-6200", "HIGH", 7.0,
                      affected_products=("obscurecms obscurecms",),
                      description="A flaw that also affects windows machines.")],
            None,
            reach=small_table(),
        )
        self.assertEqual(ranked[0].reach, 10)

    def test_unknown_reach_only_loses_a_tie(self):
        """Software absent from the table scores 0 but still ships when it is the news."""
        ranked = rank_news(
            [
                FakeItem("CVE-2026-6300", "CRITICAL", 9.5, ("weird vendor thing",)),
                FakeItem("CVE-2026-6301", "HIGH", 8.0, ("microsoft windows",)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(ranked[0].cve_id, "CVE-2026-6300")
        self.assertEqual(ranked[0].reach, 0)

    def test_unscored_sorts_below_low(self):
        """No CVSS is not a severity, and must never outrank a measured one."""
        ranked = rank_news(
            [
                FakeItem("CVE-2026-6400"),                       # no severity at all
                FakeItem("CVE-2026-6401", "LOW", 1.5),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(ranked[0].cve_id, "CVE-2026-6401")

    def test_score_alone_recovers_a_band(self):
        """Old v2 records carry a score with no band; derive it rather than drop it."""
        band, rank, score = severity_band(FakeItem("CVE-2026-6500", None, 9.4))
        self.assertEqual(band, "CRITICAL")
        self.assertEqual(score, 9.4)
        self.assertGreater(rank, 0)

    def test_order_is_deterministic_on_a_full_tie(self):
        """Identical items order by CVE id, so two runs never disagree."""
        items = [
            FakeItem("CVE-2026-7003", "HIGH", 7.0, ("nginx nginx",)),
            FakeItem("CVE-2026-7001", "HIGH", 7.0, ("nginx nginx",)),
            FakeItem("CVE-2026-7002", "HIGH", 7.0, ("nginx nginx",)),
        ]
        first = [r.cve_id for r in rank_news(items, None, reach=small_table())]
        second = [r.cve_id for r in rank_news(list(reversed(items)), None, reach=small_table())]
        self.assertEqual(first, second)
        self.assertEqual(first, ["CVE-2026-7001", "CVE-2026-7002", "CVE-2026-7003"])

    def test_newer_publication_breaks_a_deeper_tie(self):
        older = FakeItem("CVE-2026-8001", "HIGH", 7.0, ("nginx nginx",),
                         published=NOW - timedelta(days=3))
        newer = FakeItem("CVE-2026-8002", "HIGH", 7.0, ("nginx nginx",), published=NOW)
        ranked = rank_news([older, newer], None, reach=small_table())
        self.assertEqual(ranked[0].cve_id, "CVE-2026-8002")


# --------------------------------------------------------------------------- #
# the cap, and the quiet-KEV day
# --------------------------------------------------------------------------- #

class TestIssueSize(unittest.TestCase):
    def test_at_most_five_items(self):
        items = [FakeItem(f"CVE-2026-90{n:02d}", "HIGH", 7.0) for n in range(25)]
        ranked = rank_news(items, None, reach=small_table())
        self.assertEqual(len(ranked), MAX_ITEMS)
        self.assertEqual(len(ranked), 5)

    def test_zero_kev_matches_still_returns_five_tier_two_items(self):
        """A quiet KEV day still ships an issue -- that is why tier 2 exists."""
        items = [
            FakeItem(f"CVE-2026-91{n:02d}", "HIGH", 7.0 + n / 10, ("nginx nginx",))
            for n in range(12)
        ]
        ranked = rank_news(items, kev_catalog(), reach=small_table())

        self.assertEqual(len(ranked), 5)
        self.assertTrue(all(r.tier == FALLBACK_TIER for r in ranked))
        self.assertTrue(all("Tier 2" in r.reason for r in ranked))

    def test_kev_unavailable_behaves_like_a_quiet_day(self):
        """KEV fetch failed -> kev=None -> the issue still ships from tier 2."""
        items = [FakeItem(f"CVE-2026-92{n:02d}", "HIGH", 7.0) for n in range(7)]
        ranked = rank_news(items, None, reach=small_table())
        self.assertEqual(len(ranked), 5)
        self.assertTrue(all(r.tier == FALLBACK_TIER for r in ranked))

    def test_fewer_candidates_are_not_padded(self):
        ranked = rank_news([FakeItem("CVE-2026-9300", "HIGH", 7.0)], None, reach=small_table())
        self.assertEqual(len(ranked), 1)

    def test_empty_feed_returns_empty(self):
        self.assertEqual(rank_news([], kev_catalog(), reach=small_table()), [])

    def test_one_kev_item_fills_the_rest_from_tier_two(self):
        items = [FakeItem(f"CVE-2026-94{n:02d}", "HIGH", 7.0) for n in range(9)]
        ranked = rank_news(
            items, kev_catalog(FakeKevEntry("CVE-2026-9404")), reach=small_table()
        )
        self.assertEqual(len(ranked), 5)
        self.assertEqual(ranked[0].cve_id, "CVE-2026-9404")
        self.assertEqual([r.tier for r in ranked[1:]], [FALLBACK_TIER] * 4)


# --------------------------------------------------------------------------- #
# one item per product
# --------------------------------------------------------------------------- #

def cpe(vendor: str, product: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:1.0:*:*:*:*:*:*:*"


class TestOneItemPerProduct(unittest.TestCase):
    """One item per CPE vendor+product pair. Ship short, never pad."""

    def test_three_products_return_three_items_not_five(self):
        """A feed of revisions in three products is a three-item issue."""
        items = []
        for n, (vendor, product) in enumerate(
            [("f5", "nginx"), ("f5", "nginx"), ("jenkins", "jenkins"),
             ("jenkins", "jenkins"), ("microsoft", "windows"),
             ("microsoft", "windows"), ("microsoft", "windows")]
        ):
            items.append(
                FakeItem(f"CVE-2026-95{n:02d}", "HIGH", 7.0,
                         vulnerable_cpes=(cpe(vendor, product),))
            )
        ranked = rank_news(items, None, reach=small_table())
        self.assertEqual(len(ranked), 3)
        self.assertEqual(
            sorted(r.product_keys[0] for r in ranked),
            [("f5", "nginx"), ("jenkins", "jenkins"), ("microsoft", "windows")],
        )

    def test_one_vendor_two_products_both_survive(self):
        """The key is vendor AND product -- Microsoft is not one slot."""
        ranked = rank_news(
            [
                FakeItem("CVE-2026-9601", "HIGH", 7.0,
                         vulnerable_cpes=(cpe("microsoft", "windows"),)),
                FakeItem("CVE-2026-9602", "HIGH", 7.0,
                         vulnerable_cpes=(cpe("microsoft", "exchange_server"),)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(
            [r.cve_id for r in ranked], ["CVE-2026-9601", "CVE-2026-9602"]
        )

    def test_items_with_no_vulnerable_cpe_are_never_capped(self):
        """No vulnerable CPE, no product key: the ranker cannot tell them apart."""
        items = [FakeItem(f"CVE-2026-97{n:02d}", "HIGH", 7.0) for n in range(5)]
        ranked = rank_news(items, None, reach=small_table())
        self.assertEqual(len(ranked), 5)
        self.assertTrue(all(r.product_keys == () for r in ranked))

    def test_a_platform_cpe_does_not_create_a_product_key(self):
        """Two unrelated CVEs sharing a platform CPE must both ship."""
        ranked = rank_news(
            [
                FakeItem("CVE-2026-9801", "HIGH", 7.0,
                         vulnerable_cpes=(cpe("acronis", "backup"),),
                         platform_cpes=(cpe("linux", "linux_kernel"),)),
                FakeItem("CVE-2026-9802", "HIGH", 7.0,
                         vulnerable_cpes=(cpe("veeam", "backup"),),
                         platform_cpes=(cpe("linux", "linux_kernel"),)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(len(ranked), 2)

    def test_the_cap_keeps_the_better_ranked_item(self):
        """Dropping a duplicate must never drop the stronger one."""
        ranked = rank_news(
            [
                FakeItem("CVE-2026-9901", "LOW", 2.0,
                         vulnerable_cpes=(cpe("f5", "nginx"),)),
                FakeItem("CVE-2026-9902", "CRITICAL", 9.8,
                         vulnerable_cpes=(cpe("f5", "nginx"),)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual([r.cve_id for r in ranked], ["CVE-2026-9902"])

    def test_the_cap_applies_across_tiers(self):
        """A KEV item claims the product slot; the tier-2 revision is dropped."""
        ranked = rank_news(
            [
                FakeItem("CVE-2026-9911", "HIGH", 7.0,
                         vulnerable_cpes=(cpe("f5", "nginx"),)),
                FakeItem("CVE-2026-9912", "MEDIUM", 5.0,
                         vulnerable_cpes=(cpe("f5", "nginx"),)),
            ],
            kev_catalog(FakeKevEntry("CVE-2026-9912", "F5", "nginx")),
            reach=small_table(),
        )
        self.assertEqual([r.cve_id for r in ranked], ["CVE-2026-9912"])

    def test_the_cap_is_case_insensitive(self):
        ranked = rank_news(
            [
                FakeItem("CVE-2026-9921", "HIGH", 7.0,
                         vulnerable_cpes=(cpe("F5", "NGINX"),)),
                FakeItem("CVE-2026-9922", "HIGH", 7.0,
                         vulnerable_cpes=(cpe("f5", "nginx"),)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(len(ranked), 1)

    def test_an_item_naming_several_products_claims_all_of_them(self):
        ranked = rank_news(
            [
                FakeItem("CVE-2026-9931", "CRITICAL", 9.0,
                         vulnerable_cpes=(cpe("f5", "nginx"), cpe("jenkins", "jenkins"))),
                FakeItem("CVE-2026-9932", "HIGH", 7.0,
                         vulnerable_cpes=(cpe("jenkins", "jenkins"),)),
                FakeItem("CVE-2026-9933", "HIGH", 7.0,
                         vulnerable_cpes=(cpe("microsoft", "windows"),)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(
            [r.cve_id for r in ranked], ["CVE-2026-9931", "CVE-2026-9933"]
        )

    def test_the_cap_never_exceeds_the_issue_limit(self):
        items = [
            FakeItem(f"CVE-2026-9{n:03d}", "HIGH", 7.0,
                     vulnerable_cpes=(cpe(f"vendor{n}", f"product{n}"),))
            for n in range(20)
        ]
        self.assertEqual(len(rank_news(items, None, reach=small_table())), MAX_ITEMS)


# --------------------------------------------------------------------------- #
# every item carries its reason
# --------------------------------------------------------------------------- #

class TestReasons(unittest.TestCase):
    def test_every_returned_item_carries_a_reason(self):
        items = [FakeItem(f"CVE-2026-95{n:02d}", "HIGH", 7.0, ("nginx nginx",)) for n in range(8)]
        ranked = rank_news(
            items, kev_catalog(FakeKevEntry("CVE-2026-9501")), reach=small_table()
        )
        for chosen in ranked:
            self.assertIsInstance(chosen.reason, str)
            self.assertGreater(len(chosen.reason.strip()), 20, chosen.cve_id)

    def test_kev_reason_names_the_catalogue_and_the_date(self):
        ranked = rank_news(
            [FakeItem("CVE-2026-9600", "MEDIUM", 5.0)],
            kev_catalog(FakeKevEntry("CVE-2026-9600", "Acme", "Router",
                                     date_added=date(2026, 9, 19))),
            reach=small_table(),
        )
        reason = ranked[0].reason
        self.assertIn("Tier 1", reason)
        self.assertIn("known-exploited", reason)
        self.assertIn("Acme Router", reason)
        self.assertIn("2026-09-19", reason)

    def test_kev_reason_flags_ransomware_use(self):
        ranked = rank_news(
            [FakeItem("CVE-2026-9610", "HIGH", 8.0)],
            kev_catalog(FakeKevEntry("CVE-2026-9610", known_ransomware=True)),
            reach=small_table(),
        )
        self.assertIn("ransomware", ranked[0].reason.lower())

    def test_tier_two_reason_names_severity_and_reach(self):
        ranked = rank_news(
            [FakeItem("CVE-2026-9700", "HIGH", 8.1, ("microsoft windows",))],
            kev_catalog(),
            reach=small_table(),
        )
        reason = ranked[0].reason
        self.assertIn("Tier 2", reason)
        self.assertIn("HIGH", reason)
        self.assertIn("8.1", reason)
        self.assertIn("windows", reason)

    def test_unrated_reach_says_so_instead_of_claiming_zero(self):
        ranked = rank_news(
            [FakeItem("CVE-2026-9800", "HIGH", 7.0, ("nobody ships this",))],
            None,
            reach=small_table(),
        )
        self.assertIn("unrated", ranked[0].reason)


# --------------------------------------------------------------------------- #
# the KEV oracle accepts what callers actually have
# --------------------------------------------------------------------------- #

class TestKevSources(unittest.TestCase):
    def setUp(self):
        self.items = [
            FakeItem("CVE-2026-1111", "LOW", 2.0),
            FakeItem("CVE-2026-2222", "CRITICAL", 9.9),
        ]

    def _first(self, kev):
        return rank_news(self.items, kev, reach=small_table())[0].cve_id

    def test_accepts_a_catalog(self):
        self.assertEqual(self._first(kev_catalog(FakeKevEntry("CVE-2026-1111"))), "CVE-2026-1111")

    def test_accepts_a_mapping(self):
        self.assertEqual(
            self._first({"cve-2026-1111": FakeKevEntry("CVE-2026-1111")}), "CVE-2026-1111"
        )

    def test_accepts_a_set_of_ids(self):
        self.assertEqual(self._first({"CVE-2026-1111"}), "CVE-2026-1111")

    def test_accepts_a_list_of_entries(self):
        self.assertEqual(self._first([FakeKevEntry("CVE-2026-1111")]), "CVE-2026-1111")

    def test_accepts_a_callable(self):
        self.assertEqual(self._first(lambda cve: cve == "CVE-2026-1111"), "CVE-2026-1111")

    def test_lookup_is_case_and_whitespace_insensitive(self):
        items = [FakeItem(" cve-2026-1111 ", "LOW", 2.0), self.items[1]]
        ranked = rank_news(items, {"CVE-2026-1111"}, reach=small_table())
        self.assertEqual(ranked[0].tier, KEV_TIER)

    def test_a_bare_string_is_rejected(self):
        """"CVE-2026-1111" as `kev` would iterate characters. Refuse it loudly."""
        with self.assertRaises(TypeError):
            rank_news(self.items, "CVE-2026-1111", reach=small_table())

    def test_an_unsupported_source_is_rejected(self):
        with self.assertRaises(TypeError):
            rank_news(self.items, 42, reach=small_table())


# --------------------------------------------------------------------------- #
# the reach file
# --------------------------------------------------------------------------- #

class TestReachTable(unittest.TestCase):
    def test_the_shipped_table_loads_and_is_ordered(self):
        table = load_reach_table()
        self.assertGreater(len(table), 20)
        weights = [e.weight for e in table]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_the_default_file_is_the_named_file_in_the_repo(self):
        self.assertTrue(DEFAULT_REACH_FILE.exists(), DEFAULT_REACH_FILE)
        self.assertEqual(DEFAULT_REACH_FILE.name, "software_reach.txt")

    def test_a_missing_file_raises_instead_of_ranking_by_nothing(self):
        with self.assertRaises(FileNotFoundError):
            load_reach_table(Path(tempfile.gettempdir()) / "no_such_reach_table.txt")

    def test_an_empty_table_raises(self):
        path = self._write("# only comments\n\n")
        with self.assertRaises(ValueError):
            load_reach_table(path)

    def test_a_malformed_line_raises_with_the_line_number(self):
        path = self._write("100 windows\nnonsense\n")
        with self.assertRaises(ValueError) as caught:
            load_reach_table(path)
        self.assertIn(":2:", str(caught.exception))

    def test_a_non_integer_weight_raises(self):
        path = self._write("high windows\n")
        with self.assertRaises(ValueError):
            load_reach_table(path)

    def test_an_out_of_range_weight_raises(self):
        path = self._write("500 windows\n")
        with self.assertRaises(ValueError):
            load_reach_table(path)

    def test_a_duplicate_token_raises(self):
        path = self._write("100 windows\n50 windows\n")
        with self.assertRaises(ValueError):
            load_reach_table(path)

    def test_a_path_can_be_passed_straight_to_rank_news(self):
        path = self._write("100 nginx\n")
        ranked = rank_news([FakeItem("CVE-2026-9900", "HIGH", 7.0, ("nginx nginx",))],
                           None, reach=path)
        self.assertEqual(ranked[0].reach, 100)

    def test_tokens_match_whole_words_only(self):
        path = self._write("100 git\n")
        table = load_reach_table(path)
        self.assertEqual(table.score(FakeItem("CVE-1", affected_products=("gitlab gitlab",)))[0], 0)
        self.assertEqual(table.score(FakeItem("CVE-2", affected_products=("git git",)))[0], 100)

    def test_underscored_cpe_names_match_spaced_tokens(self):
        path = self._write("100 internet explorer\n")
        table = load_reach_table(path)
        weight, token = table.score(
            FakeItem("CVE-3", vulnerable_cpes=("cpe:2.3:a:microsoft:internet_explorer:11:*:*:*:*:*:*:*",))
        )
        self.assertEqual((weight, token), (100, "internet explorer"))

    @staticmethod
    def _write(text: str) -> str:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write(text)
            return handle.name


# --------------------------------------------------------------------------- #
# this is not the profile matcher
# --------------------------------------------------------------------------- #

class TestNotAProfileMatcher(unittest.TestCase):
    def test_ranking_needs_no_profile_argument(self):
        """Selection is for an audience. There is nowhere to put one machine."""
        import inspect

        from src import news_rank

        parameters = set(inspect.signature(news_rank.rank_news).parameters)
        for forbidden in ("profile", "inventory", "host", "stack", "homelab"):
            self.assertNotIn(forbidden, parameters)

    def test_software_nobody_in_the_room_runs_is_still_ranked(self):
        """A profile matcher returns nothing here. A newsletter must return five."""
        items = [
            FakeItem(f"CVE-2026-99{n:02d}", "CRITICAL", 9.0,
                     (f"vendor{n} product{n}",))
            for n in range(9)
        ]
        ranked = rank_news(items, kev_catalog(), reach=small_table())
        self.assertEqual(len(ranked), 5)
        self.assertTrue(all(r.reach == 0 for r in ranked))

    def test_no_profile_module_was_added(self):
        repo = Path(__file__).resolve().parents[1]
        for banned in ("src/rank.py", "src/profile.py", "profile.yaml", "src/profile.yaml"):
            self.assertFalse((repo / banned).exists(), f"{banned} must not exist here")


# --------------------------------------------------------------------------- #
# the ranked item stays usable downstream
# --------------------------------------------------------------------------- #

class TestRankedItemPassthrough(unittest.TestCase):
    def test_attributes_fall_through_to_the_wrapped_item(self):
        ranked = rank_news(
            [FakeItem("CVE-2026-9950", "HIGH", 7.7, ("nginx nginx",),
                      description="a description the renderer needs")],
            None,
            reach=small_table(),
        )[0]
        self.assertIsInstance(ranked, RankedItem)
        self.assertEqual(ranked.description, "a description the renderer needs")
        self.assertEqual(ranked.affected_products, ("nginx nginx",))

    def test_render_issue_accepts_ranked_items(self):
        from src.render import render_issue

        ranked = rank_news(
            [FakeItem("CVE-2026-9960", "HIGH", 7.7, ("nginx nginx",), description="x")],
            None,
            reach=small_table(),
        )
        document = render_issue(ranked, use_llm=False, title="CyberWatch Newsletter")
        self.assertIn("CVE-2026-9960", document)

    def test_a_missing_attribute_still_raises_attribute_error(self):
        ranked = rank_news([FakeItem("CVE-2026-9970", "HIGH", 7.0)], None, reach=small_table())[0]
        with self.assertRaises(AttributeError):
            _ = ranked.definitely_not_a_field

    def test_mappings_are_accepted_as_feed_items(self):
        ranked = rank_news(
            [{"cve_id": "CVE-2026-9980", "cvss_severity": "HIGH", "cvss_score": 7.0,
              "affected_products": ["nginx nginx"]}],
            None,
            reach=small_table(),
        )
        self.assertEqual(ranked[0].cve_id, "CVE-2026-9980")
        self.assertEqual(ranked[0].reach, 90)

    def test_a_dedupe_result_can_be_ranked_directly(self):
        from src.dedupe import dedupe_by_cve_id

        feed = dedupe_by_cve_id([
            FakeItem("CVE-2026-9990", "HIGH", 7.0, ("nginx nginx",)),
            FakeItem("CVE-2026-9990", "HIGH", 7.0, ("nginx nginx",)),
            FakeItem("CVE-2026-9991", "LOW", 2.0),
        ])
        ranked = rank_news(feed.items, None, reach=small_table())
        self.assertEqual([r.cve_id for r in ranked], ["CVE-2026-9990", "CVE-2026-9991"])


# --------------------------------------------------------------------------- #
# the live defect, end to end through the real NVD parser
# --------------------------------------------------------------------------- #

def acronis_entry() -> dict[str, Any]:
    """CVE-2026-87886 as NVD serves it: Acronis Backup on a Linux platform CPE.

    Hand-built from the raw NVD 2.0 shape rather than a FakeItem, because the
    bug this guards lived in `_extract_products`, not in the ranker: a fixture
    that sets `affected_products` itself cannot see it.
    """
    return {"cve": {
        "id": "CVE-2026-87886",
        "published": "2026-09-20T00:00:00.000",
        "lastModified": "2026-09-20T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "A flaw in the Acronis backup agent."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseSeverity": "HIGH", "baseScore": 7.8, "version": "3.1",
            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True,
             "criteria": "cpe:2.3:a:acronis:backup:12.5:*:*:*:*:*:*:*"},
            {"vulnerable": False,
             "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
        ]}]}],
    }}


class TestPlatformCpeReachEndToEnd(unittest.TestCase):
    """The card's defect sentence, asserted through `parse_vulnerability`."""

    def parsed(self) -> Any:
        from src.sources.nvd import parse_vulnerability

        item = parse_vulnerability(acronis_entry())
        assert item is not None
        return item

    def test_a_platform_cpe_never_becomes_an_affected_product(self):
        """`affected_products` is a display field the ranker reads -- keep it clean."""
        self.assertEqual(self.parsed().affected_products, ("acronis backup",))

    def test_the_split_still_records_the_platform_cpe_as_context(self):
        item = self.parsed()
        self.assertEqual(item.vulnerable_cpes,
                         ("cpe:2.3:a:acronis:backup:12.5:*:*:*:*:*:*:*",))
        self.assertEqual(item.platform_cpes,
                         ("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",))

    def test_the_parsed_record_scores_no_reach_from_the_kernel(self):
        """Was reach 100, match "linux kernel", for a bug that is not in Linux."""
        ranked = rank_news([self.parsed()], None)[0]
        self.assertEqual(ranked.reach, 0)
        self.assertEqual(ranked.reach_match, "")

    def test_a_vulnerable_cpe_still_scores_reach_through_the_parser(self):
        """The fix removes a false positive; it must not remove the true ones."""
        from src.sources.nvd import parse_vulnerability

        entry = acronis_entry()
        entry["cve"]["id"] = "CVE-2026-87887"
        entry["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"] = (
            "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*"
        )
        item = parse_vulnerability(entry)
        assert item is not None
        ranked = rank_news([item], None)[0]
        self.assertGreater(ranked.reach, 0)
        self.assertEqual(ranked.reach_match, "linux kernel")

    def test_the_product_key_comes_from_the_vulnerable_cpe_only(self):
        ranked = rank_news([self.parsed()], None)[0]
        self.assertEqual(ranked.product_keys, (("acronis", "backup"),))


if __name__ == "__main__":
    unittest.main(verbosity=2)
