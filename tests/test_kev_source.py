"""Tests for the CISA KEV source.

    python3 -m unittest tests.test_kev_source -v

Two halves, both of which have to pass for the module to be trustworthy:

  live      one fetch of the real catalogue (~2 MB, a few seconds). The point
            of a source module is that it survives the real feed's shape, and
            a fixture only proves the fixture was written to match the code.
            An unreachable feed is reported as a failure, not skipped -- a
            green run that never touched the network would be a lie.

  offline   the parser and the error contract, exercised directly on decoded
            documents. No fixture files and no network stubbing inside the
            source module: these call the public parse functions with literal
            dicts, which is the same thing the live path does after json.loads.
"""

from __future__ import annotations

import re
import sys
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.sources.kev import (  # noqa: E402
    FEED_URL,
    KevCatalog,
    KevEntry,
    KevError,
    fetch_kev_catalog,
    fetch_recent_kev,
    parse_catalog,
    parse_entry,
)

TIMEOUT = 60.0

# A row in the shape CISA actually publishes, copied from the live feed.
SAMPLE_ROW = {
    "cveID": "CVE-2025-39964",
    "vendorProject": "Linux",
    "product": "Kernel",
    "vulnerabilityName": "Linux Kernel Race Condition Vulnerability",
    "dateAdded": "2026-09-18",
    "shortDescription": "Linux Kernel contains a race condition vulnerability.",
    "requiredAction": "Apply mitigations in accordance with vendor instructions.",
    "dueDate": "2026-09-21",
    "knownRansomwareCampaignUse": "Known",
    "notes": "https://nvd.nist.gov/vuln/detail/CVE-2025-39964",
    "cwes": ["CWE-362"],
}


def _doc(*rows: dict) -> dict:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.09.18",
        "dateReleased": "2026-09-18T19:00:05.0974Z",
        "count": len(rows),
        "vulnerabilities": list(rows),
    }


class TestKevParsing(unittest.TestCase):
    """The offline half: shape, fields, and the error contract."""

    def test_entry_carries_every_field_the_newsletter_needs(self):
        entry = parse_entry(SAMPLE_ROW)
        self.assertIsInstance(entry, KevEntry)
        self.assertEqual(entry.cve_id, "CVE-2025-39964")
        self.assertEqual(entry.vendor, "Linux")
        self.assertEqual(entry.product, "Kernel")
        self.assertTrue(entry.description)
        self.assertEqual(entry.date_added, date(2026, 9, 18))
        self.assertEqual(entry.due_date, date(2026, 9, 21))
        self.assertTrue(entry.known_ransomware)
        self.assertEqual(entry.cwes, ("CWE-362",))
        self.assertEqual(entry.url, "https://nvd.nist.gov/vuln/detail/CVE-2025-39964")
        self.assertEqual(entry.label, "Linux Kernel")

    def test_entry_is_immutable(self):
        entry = parse_entry(SAMPLE_ROW)
        with self.assertRaises(Exception):
            entry.cve_id = "CVE-0000-0000"  # type: ignore[misc]

    def test_ransomware_flag_is_only_true_for_known(self):
        unknown = parse_entry({**SAMPLE_ROW, "knownRansomwareCampaignUse": "Unknown"})
        self.assertFalse(unknown.known_ransomware)

    def test_missing_optional_dates_are_none_not_a_crash(self):
        entry = parse_entry({"cveID": "CVE-1999-0001", "dueDate": "", "dateAdded": "n/a"})
        self.assertIsNone(entry.date_added)
        self.assertIsNone(entry.due_date)

    def test_row_without_a_cve_id_is_dropped_not_fatal(self):
        self.assertIsNone(parse_entry({"vendorProject": "Nobody"}))
        catalog = parse_catalog(_doc(SAMPLE_ROW, {"vendorProject": "Nobody"}))
        self.assertEqual(len(catalog), 1)

    def test_lookup_by_cve_id(self):
        catalog = parse_catalog(_doc(SAMPLE_ROW))
        found = catalog.by_cve_id("CVE-2025-39964")
        self.assertIsNotNone(found)
        self.assertEqual(found.vendor, "Linux")
        # The ranker will hand us whatever case NVD used.
        self.assertIsNotNone(catalog.by_cve_id("cve-2025-39964"))
        self.assertIsNotNone(catalog.by_cve_id(" CVE-2025-39964 "))
        self.assertIsNone(catalog.by_cve_id("CVE-2000-1234"))
        self.assertIsNone(catalog.by_cve_id(""))
        self.assertTrue(catalog.contains("CVE-2025-39964"))
        self.assertIn("CVE-2025-39964", catalog)
        self.assertNotIn("CVE-2000-1234", catalog)

    def test_added_since_uses_the_catalogue_date_and_sorts_newest_first(self):
        old = {**SAMPLE_ROW, "cveID": "CVE-2019-0001", "dateAdded": "2019-01-01"}
        undated = {**SAMPLE_ROW, "cveID": "CVE-2020-0002", "dateAdded": ""}
        catalog = parse_catalog(_doc(old, SAMPLE_ROW, undated))

        recent = catalog.added_since(date(2026, 1, 1))
        self.assertEqual([e.cve_id for e in recent], ["CVE-2025-39964"])

        everything = catalog.added_since(date(2000, 1, 1))
        self.assertEqual(
            [e.cve_id for e in everything], ["CVE-2025-39964", "CVE-2019-0001"]
        )
        # An undated row is never claimed as news.
        self.assertNotIn("CVE-2020-0002", [e.cve_id for e in everything])

    def test_added_since_accepts_a_day_count(self):
        today = datetime.now(timezone.utc).date()
        fresh = {**SAMPLE_ROW, "cveID": "CVE-2030-0001", "dateAdded": today.isoformat()}
        stale = {
            **SAMPLE_ROW,
            "cveID": "CVE-2030-0002",
            "dateAdded": (today - timedelta(days=90)).isoformat(),
        }
        catalog = parse_catalog(_doc(fresh, stale))
        self.assertEqual([e.cve_id for e in catalog.added_since(7)], ["CVE-2030-0001"])
        self.assertEqual(len(catalog.added_since(365)), 2)

    def test_empty_catalogue_is_not_an_error(self):
        catalog = parse_catalog(_doc())
        self.assertEqual(len(catalog), 0)
        self.assertEqual(catalog.added_since(7), [])
        self.assertIsNone(catalog.by_cve_id("CVE-2025-39964"))

    def test_malformed_documents_raise_the_named_error(self):
        with self.assertRaises(KevError):
            parse_catalog(["not", "a", "catalogue"])
        with self.assertRaises(KevError):
            parse_catalog({"title": "something else"})
        with self.assertRaises(KevError):
            parse_catalog({"vulnerabilities": "not a list"})
        with self.assertRaises(KevError):
            parse_catalog(_doc({"vendorProject": "Nobody"}, {"product": "Nothing"}))

    def test_unreachable_catalogue_raises_the_named_error(self):
        # Port 9 (discard) on localhost: refused immediately, no live traffic.
        with self.assertRaises(KevError):
            fetch_kev_catalog(url="http://127.0.0.1:9/kev.json", timeout=2.0)

    def test_no_cache_or_fixture_mode_in_the_source_module(self):
        source = (
            Path(__file__).resolve().parents[1] / "src" / "sources" / "kev.py"
        ).read_text()
        for forbidden in ("pathlib", "pickle", "shelve", "sqlite3", "tempfile", "shutil"):
            self.assertNotIn(
                forbidden, source, f"kev.py must not touch disk (found {forbidden!r})"
            )
        # `urlopen` is the whole point; a bare builtin `open(` is a cache.
        self.assertIsNone(
            re.search(r"\bopen\(", source.replace("urlopen(", "")),
            "kev.py must not open files",
        )


class TestKevLiveFeed(unittest.TestCase):
    """The live half: one fetch of the real CISA catalogue."""

    catalog: KevCatalog

    @classmethod
    def setUpClass(cls):
        try:
            cls.catalog = fetch_kev_catalog(timeout=TIMEOUT)
        except KevError as exc:  # reported, never skipped
            raise AssertionError(f"live KEV catalogue unreachable: {exc}") from exc

    def test_feed_url_is_the_public_cisa_one(self):
        self.assertTrue(FEED_URL.startswith("https://www.cisa.gov/"))
        self.assertTrue(FEED_URL.endswith("known_exploited_vulnerabilities.json"))

    def test_live_catalogue_is_populated_and_labelled(self):
        self.assertGreater(len(self.catalog), 1000, "KEV has had 1000+ entries for years")
        self.assertIn("Known Exploited", self.catalog.title)
        self.assertTrue(self.catalog.version)
        self.assertIsNotNone(self.catalog.date_released)

    def test_live_entries_carry_the_required_fields(self):
        for entry in self.catalog.entries[:50]:
            self.assertRegex(entry.cve_id, r"^CVE-\d{4}-\d{4,}$")
            self.assertTrue(entry.vendor, f"{entry.cve_id} has no vendor")
            self.assertTrue(entry.product, f"{entry.cve_id} has no product")
            self.assertTrue(entry.description, f"{entry.cve_id} has no description")
            self.assertIsInstance(entry.date_added, date)
            self.assertIsInstance(entry.due_date, date)
            self.assertGreaterEqual(entry.due_date, entry.date_added)

    def test_live_lookup_round_trips(self):
        sample = self.catalog.entries[0]
        self.assertIs(self.catalog.by_cve_id(sample.cve_id), sample)
        self.assertIs(self.catalog.by_cve_id(sample.cve_id.lower()), sample)
        self.assertIsNone(self.catalog.by_cve_id("CVE-1970-0001"))

    def test_live_catalogue_dates_are_sane(self):
        today = datetime.now(timezone.utc).date()
        dated = [e for e in self.catalog.entries if e.date_added]
        self.assertEqual(len(dated), len(self.catalog))
        self.assertLessEqual(max(e.date_added for e in dated), today + timedelta(days=1))
        # KEV started in November 2021.
        self.assertGreaterEqual(min(e.date_added for e in dated), date(2021, 11, 1))

    def test_live_recent_window_is_a_subset_of_the_catalogue(self):
        recent = fetch_recent_kev(90, timeout=TIMEOUT)
        self.assertLessEqual(len(recent), len(self.catalog))
        cutoff = datetime.now(timezone.utc).date() - timedelta(days=90)
        for entry in recent:
            self.assertGreaterEqual(entry.date_added, cutoff)
        # Newest first, so the renderer can take the head of the list.
        self.assertEqual(
            [e.date_added for e in recent],
            sorted((e.date_added for e in recent), reverse=True),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
