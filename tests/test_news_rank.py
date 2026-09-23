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
    ReachEntry,
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
    cna_products: tuple[tuple[str, str], ...] = ()
    cpe_criteria: tuple[str, ...] = ()
    published: datetime | None = NOW
    description: str = ""


@dataclass(frozen=True)
class FakeKevShapedItem:
    """An item that names its software only the way a KEV row does.

    KEV items reach the ranker fetched by id, and the fields the catalogue
    guarantees are `vendor` and `product` -- not a CPE and not a CNA row.
    """

    cve_id: str
    vendor: str = ""
    product: str = ""
    cvss_severity: str | None = "HIGH"
    cvss_score: float | None = 7.0
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


class TestProductKeysFromEveryStructuredSource(unittest.TestCase):
    """The cap must not go inert on a CVE NVD has not analysed into CPEs.

    On the AG-8 recorded window not one of 600 CVEs carried a vulnerable CPE,
    so a CPE-only cap dropped nothing and a quiet KEV day shipped four Adobe
    Connect advisories out of five items. The keys therefore also come from the
    CNA `affected` rows, which a CVE carries from the day it is filed.
    """

    def test_a_cna_row_alone_gives_the_item_a_product_key(self):
        item = FakeItem("CVE-2026-8801", "HIGH", 7.0,
                        cna_products=(("Adobe", "Adobe Connect"),))
        ranked = rank_news([item], None, reach=small_table())[0]
        self.assertEqual(ranked.product_keys, (("adobe", "adobe connect"),))

    def test_two_cna_rows_in_one_product_ship_one_item(self):
        """The defect sentence: four Adobe Connect advisories are one slot."""
        items = [
            FakeItem(f"CVE-2026-88{n:02d}", "CRITICAL", 9.3,
                     cna_products=(("Adobe", "Adobe Connect"),))
            for n in range(4)
        ]
        ranked = rank_news(items, None, reach=small_table())
        self.assertEqual(len(ranked), 1)

    def test_a_cna_key_collides_with_the_cpe_spelling_of_the_same_product(self):
        """`adobe:adobe_connect` and `Adobe` / `Adobe Connect` are one product."""
        ranked = rank_news(
            [
                FakeItem("CVE-2026-8811", "CRITICAL", 9.8,
                         vulnerable_cpes=(cpe("adobe", "adobe_connect"),)),
                FakeItem("CVE-2026-8812", "HIGH", 7.0,
                         cna_products=(("Adobe", "Adobe Connect"),)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual([r.cve_id for r in ranked], ["CVE-2026-8811"])

    def test_one_vendor_two_cna_products_both_survive(self):
        ranked = rank_news(
            [
                FakeItem("CVE-2026-8821", "HIGH", 7.0,
                         cna_products=(("Adobe", "Adobe Connect"),)),
                FakeItem("CVE-2026-8822", "HIGH", 7.0,
                         cna_products=(("Adobe", "Campaign Classic"),)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(len(ranked), 2)

    def test_an_item_with_no_product_from_any_source_is_still_exempt(self):
        """No CPE, no CNA row, no KEV fields: never capped, never guessed at."""
        items = [FakeItem(f"CVE-2026-88{n:02d}", "HIGH", 7.0) for n in range(30, 35)]
        ranked = rank_news(items, None, reach=small_table())
        self.assertEqual(len(ranked), 5)
        self.assertTrue(all(r.product_keys == () for r in ranked))

    def test_an_empty_cna_row_creates_no_key(self):
        """A row NVD filled with "n/a" must not become a key every CVE shares."""
        items = [
            FakeItem(f"CVE-2026-88{n:02d}", "HIGH", 7.0, cna_products=(("", ""),))
            for n in range(40, 45)
        ]
        ranked = rank_news(items, None, reach=small_table())
        self.assertEqual(len(ranked), 5)
        self.assertTrue(all(r.product_keys == () for r in ranked))

    def test_a_cna_row_never_reaches_the_reach_match_surface(self):
        """Structured keys for the cap, and nothing more: reach is untouched.

        `windows` is weight 100 in the test table. A CNA row naming it must
        score zero, because a CNA row is not evidence NVD has vouched for.
        """
        ranked = rank_news(
            [FakeItem("CVE-2026-8850", "HIGH", 7.0,
                      cna_products=(("Microsoft", "Windows"),))],
            None,
            reach=small_table(),
        )[0]
        self.assertEqual(ranked.reach, 0)
        self.assertEqual(ranked.reach_match, "")

    def test_a_kev_rows_own_vendor_and_product_are_a_key(self):
        """KEV items are fetched by id and may carry only these two fields."""
        ranked = rank_news(
            [
                FakeKevShapedItem("CVE-2026-8861", "Ivanti", "Connect Secure"),
                FakeKevShapedItem("CVE-2026-8862", "Ivanti", "Connect Secure"),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0].product_keys, (("ivanti", "connect secure"),))

    def test_the_cap_still_keeps_the_better_ranked_cna_item(self):
        ranked = rank_news(
            [
                FakeItem("CVE-2026-8871", "LOW", 2.0,
                         cna_products=(("Adobe", "Adobe Connect"),)),
                FakeItem("CVE-2026-8872", "CRITICAL", 9.8,
                         cna_products=(("Adobe", "Adobe Connect"),)),
            ],
            None,
            reach=small_table(),
        )
        self.assertEqual([r.cve_id for r in ranked], ["CVE-2026-8872"])


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


# --------------------------------------------------------------------------- #
# the quiet-KEV defect, end to end through the real NVD parser
# --------------------------------------------------------------------------- #

def adobe_entry(cve_id: str) -> dict[str, Any]:
    """An Adobe Connect advisory as NVD served it in the AG-8 recorded window.

    The shape that made the cap inert: a CNA `affected` row naming the product,
    and no `configurations` block at all, because NVD has not analysed it yet.
    Built from the raw NVD 2.0 shape, not a FakeItem, because the defect is in
    what the parser keeps.
    """
    return {"cve": {
        "id": cve_id,
        "published": "2026-09-20T00:00:00.000",
        "lastModified": "2026-09-20T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "A flaw in Adobe Connect."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseSeverity": "CRITICAL", "baseScore": 9.3, "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}}]},
        "affected": [{"source": "psirt@adobe.com", "affectedData": [
            {"vendor": "Adobe", "product": "Adobe Connect",
             "versions": [{"version": "12.9", "status": "affected"}]},
        ]}],
    }}


class TestQuietKevDayEndToEnd(unittest.TestCase):
    """Four advisories in one product must not fill four of five slots."""

    def parsed(self, cve_id: str) -> Any:
        from src.sources.nvd import parse_vulnerability

        item = parse_vulnerability(adobe_entry(cve_id))
        assert item is not None
        return item

    def test_the_parser_keeps_the_cna_row_as_a_structured_pair(self):
        self.assertEqual(self.parsed("CVE-2026-75682").cna_products,
                         (("Adobe", "Adobe Connect"),))

    def test_a_cve_with_no_cpe_data_still_carries_a_product_key(self):
        ranked = rank_news([self.parsed("CVE-2026-75682")], None)[0]
        self.assertEqual(ranked.vulnerable_cpes, ())
        self.assertEqual(ranked.product_keys, (("adobe", "adobe connect"),))

    def test_four_adobe_connect_advisories_ship_as_one_item(self):
        items = [self.parsed(f"CVE-2026-756{n:02d}") for n in (82, 89, 97, 98)]
        ranked = rank_news(items, None)
        self.assertEqual(len(ranked), 1)

    def test_the_parser_does_not_put_the_cna_row_on_the_reach_surface(self):
        """The reach score is whatever the display label already produced."""
        item = self.parsed("CVE-2026-75682")
        self.assertEqual(item.affected_products, ("Adobe Adobe Connect",))
        self.assertEqual(rank_news([item], None)[0].reach_match, "")


# --------------------------------------------------------------------------- #
# reach is matched at the HEAD of a product name, per vendor
# --------------------------------------------------------------------------- #

RULE_REACH_TEXT = """
# every mechanism of the reach file, one line each
100  windows
98   chrome, google chrome
95   iphone os, apple/ios
62   vendor:fortinet
60   ios xe, cisco/ios xe, cisco/ios
44   .net
26   brand:d-link
"""


def rule_table() -> ReachTable:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(RULE_REACH_TEXT)
        path = handle.name
    return load_reach_table(path)


@dataclass(frozen=True)
class NamedRow:
    """The shape a KEV row reaches the ranker in: a vendor and a product."""

    vendor: str = ""
    product: str = ""


class TestReachMatchesTheHeadOfAName(unittest.TestCase):
    """A reach token names software, and software is named head-first.

    The rule this replaces matched a token as a substring of one flat blob of
    every label on an item. Two live defects came out of that and both are
    asserted here, plus the four cases that must NOT regress while fixing them.
    """

    def setUp(self):
        self.table = rule_table()

    def score(self, vendor, product):
        return self.table.score(NamedRow(vendor, product))

    # --- the two defects ---------------------------------------------------- #

    def test_a_word_in_the_middle_of_a_name_is_not_reach(self):
        """CVE-2026-84388: "Fortinet FortiPAM Chrome Extension" scored 98."""
        self.assertEqual(self.score("Fortinet", "FortiPAM Chrome Extension"), (0, ""))

    def test_a_match_may_not_stop_inside_a_word(self):
        """CVE-2016-15059: the Perl module Net-IDN-Encode scored 44 as .NET."""
        self.assertEqual(self.score("", "Net-IDN-Encode"), (0, ""))

    def test_a_hyphen_binds_but_a_space_separates(self):
        """The one-character difference between the two: nginx-ignition."""
        self.assertEqual(self.score("Google", "Chrome-Cast-Thing"), (0, ""))
        self.assertEqual(self.score("Google", "Chrome for Android"), (98, "chrome"))

    # --- what must survive the fix ------------------------------------------ #

    def test_an_edition_after_the_head_still_scores(self):
        """CVE-2020-1472 ships on Windows Server 2019 and is still 100."""
        self.assertEqual(self.score("Microsoft", "Windows Server 2019"), (100, "windows"))

    def test_a_vendor_qualified_spelling_still_scores(self):
        self.assertEqual(self.score("Google", "Chrome"), (98, "chrome"))

    def test_a_trailing_version_is_not_part_of_the_name(self):
        self.assertEqual(self.score("Microsoft", "Windows 10"), (100, "windows"))

    def test_a_vulnerable_cpe_is_still_a_surface(self):
        item = FakeItem(
            "CVE-2026-9901", "HIGH", 7.0,
            vulnerable_cpes=("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",),
        )
        self.assertEqual(self.table.score(item), (100, "windows"))

    def test_a_platform_cpe_is_still_not_a_surface(self):
        item = FakeItem(
            "CVE-2026-9902", "HIGH", 7.0,
            platform_cpes=("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",),
        )
        self.assertEqual(self.table.score(item), (0, ""))


class TestAVendorIsNotSoftware(unittest.TestCase):
    """A company name may not lead a product name.

    Letting it is the same over-reach one level up: every niche product a big
    vendor ships would inherit the vendor's weight, so "Fortinet FortiPAM
    Chrome Extension" would simply keep a figure after losing "chrome".
    """

    def setUp(self):
        self.table = rule_table()

    def score(self, vendor, product):
        return self.table.score(NamedRow(vendor, product))

    def test_a_vendor_line_scores_a_row_that_names_no_product(self):
        self.assertEqual(self.score("Fortinet", "Multiple Products"), (62, "fortinet"))

    def test_a_vendor_line_never_scores_a_named_product(self):
        self.assertEqual(self.score("Fortinet", "FortiWeb Cloud Connector"), (0, ""))

    def test_a_brand_line_scores_the_whole_catalogue(self):
        """d-link is 26 because that is true of every D-Link box."""
        self.assertEqual(self.score("D-Link", "DIR-859 Router"), (26, "d-link"))
        self.assertEqual(self.score("D-Link", "Multiple Products"), (26, "d-link"))


class TestATokenMayBeScopedToItsVendor(unittest.TestCase):
    """Cisco IOS is a router OS and Apple iOS is a phone OS."""

    def setUp(self):
        self.table = rule_table()

    def score(self, vendor, product):
        return self.table.score(NamedRow(vendor, product))

    def test_ciscos_ios_does_not_score_an_apple_row(self):
        weight, token = self.score("Apple", "iOS and iPadOS")
        self.assertEqual(weight, 95)
        self.assertNotEqual(token, "ios xe")

    def test_apples_ios_does_not_score_a_cisco_row(self):
        weight, token = self.score("Cisco", "IOS XE Web UI")
        self.assertEqual(weight, 60)
        self.assertNotEqual(token, "iphone os")

    def test_an_unscoped_ios_token_would_take_the_apple_row(self):
        """Guard the premise: without the scope this is exactly the defect.

        Strip only the Cisco scope and Cisco's router-OS line starts taking
        rows it has no claim on -- an Apple phone row and a vendor the table
        has never heard of both score 60 off it.
        """
        cisco_only = ReachTable(entries=tuple(
            e for e in self.table.entries if e.scope == "cisco"))
        self.assertEqual(cisco_only.score(NamedRow("Apple", "iOS 17")), (0, ""))

        unscoped = ReachTable(entries=tuple(
            ReachEntry(token=e.token, weight=e.weight, note=e.note, kind=e.kind)
            for e in cisco_only.entries
        ))
        self.assertEqual(unscoped.score(NamedRow("Apple", "iOS 17"))[0], 60)
        self.assertEqual(unscoped.score(NamedRow("Netgear", "ios thing"))[0], 60)


class TestTheShippedReachFile(unittest.TestCase):
    """The four named acceptance cases, against data/software_reach.txt.

    Offline: the file is read from disk, the items are the shapes the live
    feeds produce for those four CVEs.
    """

    @classmethod
    def setUpClass(cls):
        cls.table = load_reach_table(DEFAULT_REACH_FILE)

    def test_fortipam_chrome_extension_is_unrated(self):
        self.assertEqual(
            self.table.score(NamedRow("Fortinet", "FortiPAM Chrome Extension")), (0, ""))

    def test_net_idn_encode_is_unrated(self):
        self.assertEqual(self.table.score(NamedRow("", "Net-IDN-Encode")), (0, ""))

    def test_windows_server_2019_keeps_its_full_weight(self):
        self.assertEqual(
            self.table.score(NamedRow("Microsoft", "Windows Server 2019")),
            (100, "windows"))

    def test_no_cisco_scoped_token_can_score_an_apple_row(self):
        cisco_only = ReachTable(entries=tuple(
            e for e in self.table.entries if e.scope == "cisco"))
        self.assertTrue(cisco_only.entries, "the file no longer scopes anything to cisco")
        for product in ("iOS", "iOS and iPadOS", "iOS, iPadOS, and macOS", "iPadOS"):
            with self.subTest(product=product):
                self.assertEqual(cisco_only.score(NamedRow("Apple", product)), (0, ""))

    def test_every_token_in_the_file_is_reachable(self):
        """A token nobody can match is a weight that silently does nothing.

        The row is built the way a feed writes one -- the token in the PRODUCT
        field, the vendor field carrying only a scope the file itself asked
        for. Putting the token in both fields would let the vendor-word rule
        satisfy this test for a token the product rule cannot reach, which is
        how a `41 wordpress` that scored nothing live passed here before.
        """
        for entry in self.table.entries:
            with self.subTest(token=entry.token, kind=entry.kind):
                if entry.kind == "product":
                    row = NamedRow(entry.scope, entry.token)
                else:
                    row = NamedRow(entry.token, "Multiple Products")
                self.assertGreater(self.table.score(row)[0], 0)


class TestSoftwareNamedInTheVendorField(unittest.TestCase):
    """A feed chooses which half of a name goes in which field.

    KEV files WordPress core as ("WordPress", "Core") and PHP's FPM as
    ("PHP", "FastCGI Process Manager (FPM)") -- the software this table prices
    by name is in the VENDOR field and the product field holds a component.
    Refusing the vendor word outright made `41 wordpress`, `84 php`,
    `52 gitlab`, `40 drupal`, `52 jenkins`, `80 openbsd` and `76 docker`
    unmatchable against the live catalogue while the file still priced them.

    Every row below is a real live CISA KEV row shape, quoted in the card.
    """

    @classmethod
    def setUpClass(cls):
        cls.table = load_reach_table(DEFAULT_REACH_FILE)

    def score(self, vendor, product):
        return self.table.score(NamedRow(vendor, product))

    # --- software the file names, filed under its own name ------------------ #

    def test_wordpress_core_scores_wordpress(self):
        """CVE-2026-60137, CVE-2026-63030, CVE-2018-7602-era rows."""
        self.assertEqual(self.score("WordPress", "Core"), (41, "wordpress"))

    def test_drupal_core_scores_drupal(self):
        """CVE-2019-6340."""
        self.assertEqual(self.score("Drupal", "Core"), (40, "drupal"))

    def test_gitlab_ce_and_ee_scores_gitlab(self):
        """CVE-2021-22205."""
        self.assertEqual(
            self.score("GitLab", "Community and Enterprise Editions"), (52, "gitlab"))

    def test_php_fpm_scores_php(self):
        """CVE-2019-11043."""
        self.assertEqual(
            self.score("PHP", "FastCGI Process Manager (FPM)"), (84, "php"))

    def test_openbsd_opensmtpd_scores_openbsd(self):
        """CVE-2020-7247."""
        self.assertEqual(self.score("OpenBSD", "OpenSMTPD"), (80, "openbsd"))

    def test_docker_desktop_scores_docker(self):
        """CVE-2019-15752."""
        self.assertEqual(
            self.score("Docker", "Desktop Community Edition"), (76, "docker"))

    def test_jenkins_plugin_scores_jenkins(self):
        """CVE-2019-1003029: a plugin runs inside the server it plugs into."""
        self.assertEqual(
            self.score("Jenkins", "Script Security Plugin"), (52, "jenkins"))

    # --- and the company names that must still NOT lead a product ----------- #

    def test_a_vendor_line_still_never_leads_a_named_product(self):
        for vendor, product in (
            ("Fortinet", "FortiWeb Cloud Connector"),
            ("Fortinet", "FortiPAM Chrome Extension"),
            ("Red Hat", "Build of Keycloak"),
            ("Apple", "Xcode Server"),
            ("Cisco", "Small Business RV Series Routers"),
            ("Apache", "MINA"),
            ("Oracle", "Agile PLM"),
        ):
            with self.subTest(vendor=vendor, product=product):
                self.assertEqual(self.score(vendor, product), (0, ""))

    def test_the_file_decides_which_names_are_companies(self):
        """The rule reads the file, it does not carry its own list."""
        self.assertIn("fortinet", self.table.company_names)
        self.assertIn("red hat", self.table.company_names)
        self.assertNotIn("wordpress", self.table.company_names)
        self.assertNotIn("php", self.table.company_names)

    def test_a_name_written_both_ways_is_still_a_company(self):
        """The guard, on a file that spells one name as product AND vendor.

        In the shipped file no name is written both ways except `android`,
        where both lines are 97 and the ambiguity costs nothing. This builds
        the case anyway, because the rule must be the file's to decide: a
        `vendor:` line on a name disqualifies that name from leading a product,
        even when the same name also appears as a plain product token.
        """
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("62   fortinet, vendor:fortinet\n41   wordpress\n")
            path = handle.name
        table = load_reach_table(path)
        self.assertEqual(table.score(NamedRow("Fortinet", "FortiWeb Cloud Connector")),
                         (0, ""))
        self.assertEqual(table.score(NamedRow("Fortinet", "Multiple Products")),
                         (62, "fortinet"))
        self.assertEqual(table.score(NamedRow("WordPress", "Core")), (41, "wordpress"))

    def test_making_a_named_product_a_vendor_line_would_stop_it(self):
        """Guard the premise: the vendor: line is what refuses the name.

        Rewrite `41 wordpress` as a vendor line and the WordPress core row
        loses it again -- so the rule is obeying the file, not a hard-coded
        allowance for these seven names.
        """
        rewritten = ReachTable(entries=tuple(
            ReachEntry(token=e.token, weight=e.weight, note=e.note,
                       kind="vendor" if e.token == "wordpress" else e.kind,
                       scope=e.scope)
            for e in self.table.entries
        ))
        self.assertEqual(rewritten.score(NamedRow("WordPress", "Core")), (0, ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
