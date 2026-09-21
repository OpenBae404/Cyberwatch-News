"""The entrypoint: one command, a dated file, and a loud KEV outage.

Four things are asserted here, because nothing else in the repo can assert
them -- every other module is a well-behaved component that would happily
take part in a degraded run:

  1. `run.py` with no arguments fetches KEV, fetches the *published* NVD
     window, ranks and renders, and writes ONE dated markdown file under
     issues/.
  2. A KEV outage -- unreachable, malformed, or a catalogue that parses but
     has lost its contents -- aborts with a non-zero exit and writes NOTHING.
     The failure mode this guards against is not a crash; it is a perfectly
     valid-looking severity-only issue that silently claims nothing is
     known-exploited.
  3. The NVD fetch is never asked for a lastMod window.
  4. A quiet KEV day (full catalogue, nothing new in it) is NOT an outage:
     the issue still ships, all tier 2.

Every test stubs both feeds. No network, milliseconds.
"""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import run as entrypoint  # noqa: E402
from run import (  # noqa: E402
    EmptyIssue,
    FeedFailure,
    KevOutage,
    build_issue,
    collect_candidates,
    load_kev,
    write_issue,
)
from src.sources.kev import KevCatalog, KevEntry, KevError  # noqa: E402
from src.sources.nvd import NvdError  # noqa: E402


# --------------------------------------------------------------------------- #
# stubs
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class FakeCve:
    """NvdItem-shaped, enough for dedupe, the ranker and the renderer."""

    cve_id: str
    description: str = "A remote attacker can do something bad."
    published: datetime = datetime(2026, 9, 21, 8, 0, tzinfo=timezone.utc)
    last_modified: datetime = datetime(2026, 9, 21, 8, 0, tzinfo=timezone.utc)
    cvss_score: float | None = 9.8
    cvss_severity: str | None = "CRITICAL"
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cvss_version: str = "3.1"
    affected_products: tuple[str, ...] = ("nginx nginx",)
    cpe_criteria: tuple[str, ...] = ("cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*",)
    references: tuple[str, ...] = ()

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


def feed(count: int = 12) -> list[FakeCve]:
    base = datetime(2026, 9, 21, 8, 0, tzinfo=timezone.utc)
    return [
        FakeCve(
            cve_id=f"CVE-2026-{1000 + n}",
            published=base - timedelta(hours=n),
            last_modified=base - timedelta(hours=n),
            cvss_score=9.8 - (n * 0.1),
        )
        for n in range(count)
    ]


def catalog(
    size: int = 400,
    cve_ids: tuple[str, ...] = (),
    *,
    added: date | None = None,
) -> KevCatalog:
    """A plausible catalogue: `size` entries, `cve_ids` guaranteed present.

    `added` defaults to *today*, so the named ids are inside any lookback
    window. Anchoring them to a literal date would make the by-id tests pass
    this week and silently stop exercising anything next week.
    """
    listed_on = added or datetime.now(timezone.utc).date()
    entries: list[KevEntry] = []
    for cve_id in cve_ids:
        entries.append(
            KevEntry(
                cve_id=cve_id,
                vendor="nginx",
                product="nginx",
                vulnerability_name="Test",
                description="Exploited in the wild.",
                date_added=listed_on,
                due_date=listed_on + timedelta(days=21),
            )
        )
    for n in range(size - len(entries)):
        entries.append(
            KevEntry(
                cve_id=f"CVE-2015-{9000 + n}",
                vendor="old",
                product="thing",
                vulnerability_name="Old",
                description="Exploited years ago.",
                date_added=date(2015, 1, 1),
                due_date=date(2015, 2, 1),
            )
        )
    return KevCatalog(
        title="Known Exploited Vulnerabilities Catalog",
        version="2026.09.21",
        date_released=datetime(2026, 9, 21, tzinfo=timezone.utc),
        entries=tuple(entries),
        _index={e.cve_id: e for e in entries},
    )


@dataclass
class RecordingNvd:
    """Stands in for fetch_recent_cves, remembering how it was called."""

    items: list[FakeCve] = field(default_factory=lambda: feed(12))
    calls: list[dict] = field(default_factory=list)
    error: Exception | None = None

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return list(self.items)


@dataclass
class RecordingKevItems:
    """Stands in for fetch_cves_by_id: records the ids it was asked for."""

    items: list[FakeCve] = field(default_factory=list)
    calls: list[tuple] = field(default_factory=list)
    error: Exception | None = None

    def __call__(self, cve_ids, **kwargs):
        ids = list(cve_ids)
        self.calls.append((ids, kwargs))
        if self.error is not None:
            raise self.error
        return list(self.items)


def kev_ok(size: int = 400, cve_ids: tuple[str, ...] = (), *, added: date | None = None):
    def _fetch(**_kwargs):
        return catalog(size, cve_ids, added=added)
    return _fetch


def kev_raising(exc: Exception):
    def _fetch(**_kwargs):
        raise exc
    return _fetch


_real_build_issue = build_issue


def build_issue(**kwargs):  # noqa: F811  -- test shim, keeps the suite offline
    """`run.build_issue` with a stubbed by-id fetch unless a test supplies one.

    Every test in this file must be hermetic; the real default for
    `kev_item_fetch` is the live NVD by-id fetch.
    """
    kwargs.setdefault("kev_item_fetch", RecordingKevItems())
    return _real_build_issue(**kwargs)


def main(argv, **overrides):
    """`run.main` with the same hermetic default."""
    overrides.setdefault("kev_item_fetch", RecordingKevItems())
    return entrypoint.main(argv, **overrides)


# --------------------------------------------------------------------------- #
# 1. the wiring
# --------------------------------------------------------------------------- #

class TestOneCommandWiring(unittest.TestCase):

    def test_build_issue_runs_all_four_stages_with_no_arguments(self):
        nvd = RecordingNvd()
        run = build_issue(kev_fetch=kev_ok(), nvd_fetch=nvd, use_llm=False)

        self.assertTrue(nvd.calls, "NVD was never fetched")
        self.assertEqual(len(run.items), 5, "the issue is not five items")
        self.assertTrue(run.markdown.startswith("# CyberWatch Newsletter"))
        self.assertEqual(run.kev_entries, 400)

    def test_the_issue_is_one_document_with_five_items(self):
        run = build_issue(kev_fetch=kev_ok(), nvd_fetch=RecordingNvd(), use_llm=False)
        self.assertEqual(run.markdown.count("\n## "), 5)
        self.assertEqual(run.markdown.count("\n# "), 0, "more than one document")
        for label in ("What happened", "Who is affected", "How serious", "What to do"):
            self.assertEqual(
                run.markdown.count(f"**{label}:**"), 5,
                f"{label} is not on every item",
            )
        self.assertEqual(run.markdown.count("**Why this is here:**"), 5)

    def test_a_dated_markdown_file_is_written_under_issues(self):
        run = build_issue(
            kev_fetch=kev_ok(), nvd_fetch=RecordingNvd(), use_llm=False,
            issue_date=date(2026, 9, 21),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = write_issue(run, Path(tmp) / "issues")
            self.assertEqual(path.name, "2026-09-21.md")
            self.assertEqual(path.parent.name, "issues")
            self.assertEqual(path.read_text(encoding="utf-8"), run.markdown)

    def test_main_with_no_arguments_writes_a_file_and_exits_zero(self):
        nvd = RecordingNvd()
        with tempfile.TemporaryDirectory() as tmp:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = entrypoint.main(
                    ["--issues-dir", tmp, "--no-llm"],
                    kev_fetch=kev_ok(),
                    nvd_fetch=nvd,
                )
            self.assertEqual(code, 0, err.getvalue())
            written = list(Path(tmp).glob("*.md"))
            self.assertEqual(len(written), 1, f"expected one issue, got {written}")
            self.assertRegex(written[0].name, r"^\d{4}-\d{2}-\d{2}\.md$")
            self.assertIn("wrote", out.getvalue())

    def test_the_kev_item_is_tier_one_and_marked(self):
        items = feed(12)
        nvd = RecordingNvd(items=items)
        # A moderate KEV CVE, so tier can't be confused with severity order.
        exploited = FakeCve(
            cve_id="CVE-2026-7777", cvss_score=5.5, cvss_severity="MEDIUM",
            published=datetime(2026, 9, 20, tzinfo=timezone.utc),
            last_modified=datetime(2026, 9, 20, tzinfo=timezone.utc),
        )
        nvd.items = [exploited, *items]
        run = build_issue(
            kev_fetch=kev_ok(cve_ids=("CVE-2026-7777",)), nvd_fetch=nvd, use_llm=False,
        )
        self.assertEqual(run.items[0].cve_id, "CVE-2026-7777",
                         "a MEDIUM KEV CVE did not outrank CRITICAL non-KEV ones")
        self.assertEqual(run.known_exploited, 1)
        self.assertIn("KNOWN EXPLOITED", run.markdown)


# --------------------------------------------------------------------------- #
# 2. a KEV outage fails loudly
# --------------------------------------------------------------------------- #

class TestKevOutageFailsLoudly(unittest.TestCase):
    """The core guard. A run without tier 1 must not produce an issue."""

    def test_unreachable_kev_raises_rather_than_returning_none(self):
        with self.assertRaises(KevOutage):
            load_kev(kev_raising(KevError("CISA unreachable: URLError")))

    def test_malformed_kev_raises(self):
        with self.assertRaises(KevOutage):
            load_kev(kev_raising(KevError("KEV catalogue has no 'vulnerabilities' list")))

    def test_an_os_error_from_the_fetch_is_also_an_outage(self):
        with self.assertRaises(KevOutage):
            load_kev(kev_raising(OSError("connection reset")))

    def test_a_catalogue_that_lost_its_contents_is_an_outage(self):
        """Parses fine, 3 rows. That is a truncated feed, not a quiet day."""
        with self.assertRaises(KevOutage):
            load_kev(kev_ok(size=3))

    def test_build_issue_aborts_on_a_kev_outage(self):
        nvd = RecordingNvd()
        with self.assertRaises(KevOutage):
            build_issue(
                kev_fetch=kev_raising(KevError("down")), nvd_fetch=nvd, use_llm=False,
            )

    def test_no_nvd_fetch_happens_once_kev_is_down(self):
        """KEV first: a dead tier 1 should not cost a minute of NVD paging."""
        nvd = RecordingNvd()
        with self.assertRaises(KevOutage):
            build_issue(
                kev_fetch=kev_raising(KevError("down")), nvd_fetch=nvd, use_llm=False,
            )
        self.assertEqual(nvd.calls, [], "NVD was fetched during a KEV outage")

    def test_main_exits_non_zero_and_writes_nothing_on_a_kev_outage(self):
        with tempfile.TemporaryDirectory() as tmp:
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = entrypoint.main(
                    ["--issues-dir", tmp, "--no-llm"],
                    kev_fetch=kev_raising(KevError("CISA unreachable")),
                    nvd_fetch=RecordingNvd(),
                )
            self.assertNotEqual(code, 0, "a KEV outage exited zero")
            self.assertEqual(code, KevOutage.exit_code)
            self.assertEqual(list(Path(tmp).glob("*.md")), [],
                             "a severity-only issue was written during a KEV outage")
            self.assertIn("KEV", err.getvalue())
            self.assertIn("no issue written", err.getvalue())

    def test_the_degraded_issue_is_what_we_are_preventing(self):
        """Proof the guard is load-bearing: the ranker WILL ship without KEV.

        `rank_news(items, None)` returns a full five items, every one of them
        tier 2, and the rendered document then states in words that nothing is
        known-exploited -- which is a claim, not an absence. That document is
        exactly what `build_issue` must refuse to write.
        """
        from src.news_rank import rank_news
        from src.render import render_issue

        degraded = rank_news(feed(12), None)
        self.assertEqual(len(degraded), 5)
        self.assertTrue(all(item.tier == 2 for item in degraded))
        document = render_issue(degraded, use_llm=False)
        self.assertIn("Nothing in today's issue is known-exploited", document)


# --------------------------------------------------------------------------- #
# 2b. tier 1 is actually reachable
# --------------------------------------------------------------------------- #

class TestTierOneIsReachable(unittest.TestCase):
    """Without the by-id fetch, tier 1 never fires and the rule is decorative.

    A KEV listing almost never falls inside the published window: CISA lists a
    CVE when exploitation is observed, typically weeks or months after it was
    published. Measured against the live feeds on 2026-09-21, 0 of 181 CVEs in
    a two-day published window were in KEV. A run that only reads the window
    therefore leads with severity every single day while claiming to lead with
    exploitation -- the same dishonest document `load_kev` refuses to write,
    arrived at from the other direction.
    """

    def test_recently_listed_kev_cves_are_fetched_by_id(self):
        by_id = RecordingKevItems()
        _real_build_issue(
            kev_fetch=kev_ok(cve_ids=("CVE-2026-7777",)),
            nvd_fetch=RecordingNvd(),
            kev_item_fetch=by_id,
            use_llm=False,
        )
        self.assertTrue(by_id.calls, "no KEV-listed CVE was ever fetched by id")
        asked = by_id.calls[0][0]
        self.assertIn("CVE-2026-7777", asked)

    def test_a_kev_cve_outside_the_published_window_still_reaches_the_issue(self):
        """The whole point: an old publication, listed by CISA this week."""
        exploited = FakeCve(
            cve_id="CVE-2023-1111", cvss_score=5.5, cvss_severity="MEDIUM",
            published=datetime(2023, 4, 1, tzinfo=timezone.utc),
            last_modified=datetime(2023, 4, 1, tzinfo=timezone.utc),
        )
        window = RecordingNvd(items=feed(12))      # does NOT contain CVE-2023-1111
        run = _real_build_issue(
            kev_fetch=kev_ok(cve_ids=("CVE-2023-1111",)),
            nvd_fetch=window,
            kev_item_fetch=RecordingKevItems(items=[exploited]),
            use_llm=False,
        )
        self.assertEqual(run.items[0].cve_id, "CVE-2023-1111",
                         "the KEV-listed CVE did not lead the issue")
        self.assertEqual(run.known_exploited, 1)
        self.assertEqual(run.kev_fetched, 1)

    def test_a_window_only_run_would_ship_a_severity_only_issue(self):
        """Proof this check is load-bearing, not decoration.

        Same catalogue, same window, but no by-id fetch: five items, none of
        them known-exploited, and the document says so in words.
        """
        run = _real_build_issue(
            kev_fetch=kev_ok(cve_ids=("CVE-2023-1111",)),
            nvd_fetch=RecordingNvd(items=feed(12)),
            kev_item_fetch=RecordingKevItems(items=[]),   # the bug
            use_llm=False,
        )
        self.assertEqual(run.known_exploited, 0)
        self.assertIn("Nothing in today's issue is known-exploited", run.markdown)

    def test_a_cve_in_both_the_window_and_kev_appears_once(self):
        items = feed(12)
        both = items[0]
        run = _real_build_issue(
            kev_fetch=kev_ok(cve_ids=(both.cve_id,)),
            nvd_fetch=RecordingNvd(items=items),
            kev_item_fetch=RecordingKevItems(items=[both]),
            use_llm=False,
        )
        ids = [item.cve_id for item in run.items]
        self.assertEqual(len(ids), len(set(ids)), f"a CVE was listed twice: {ids}")
        self.assertEqual(ids.count(both.cve_id), 1)

    def test_a_by_id_failure_is_a_thinner_issue_not_a_dead_run(self):
        """The catalogue is in hand, so KEV labelling still works. Ship."""
        run = _real_build_issue(
            kev_fetch=kev_ok(cve_ids=("CVE-2023-1111",)),
            nvd_fetch=RecordingNvd(),
            kev_item_fetch=RecordingKevItems(error=NvdError("HTTP 503")),
            use_llm=False,
        )
        self.assertEqual(len(run.items), 5)
        self.assertEqual(run.kev_fetched, 0)

    def test_nothing_listed_recently_costs_no_nvd_requests(self):
        """A quiet KEV day must not spend requests on decade-old listings."""
        by_id = RecordingKevItems()
        _real_build_issue(
            kev_fetch=kev_ok(size=1700),           # all dated 2015
            nvd_fetch=RecordingNvd(),
            kev_item_fetch=by_id,
            use_llm=False,
        )
        self.assertEqual(by_id.calls, [], "by-id requests spent on a quiet day")

    def test_the_by_id_fetch_is_capped(self):
        many = tuple(f"CVE-2026-{5000 + n}" for n in range(40))
        by_id = RecordingKevItems()
        _real_build_issue(
            kev_fetch=kev_ok(size=400, cve_ids=many),
            nvd_fetch=RecordingNvd(),
            kev_item_fetch=by_id,
            use_llm=False,
        )
        self.assertTrue(by_id.calls)
        cap = by_id.calls[0][1].get("max_ids")
        self.assertIsNotNone(cap, "no cap was passed to the by-id fetch")
        self.assertLessEqual(cap, entrypoint.MAX_KEV_LOOKUPS)


# --------------------------------------------------------------------------- #
# 3. published window only
# --------------------------------------------------------------------------- #

class TestPublishedWindowOnly(unittest.TestCase):

    def test_the_nvd_fetch_is_always_asked_for_the_published_window(self):
        nvd = RecordingNvd()
        build_issue(kev_fetch=kev_ok(), nvd_fetch=nvd, use_llm=False)
        self.assertTrue(nvd.calls)
        for call in nvd.calls:
            self.assertEqual(call.get("by"), "published",
                             f"a non-published window was requested: {call}")

    def test_no_call_ever_asks_for_modified(self):
        nvd = RecordingNvd(items=[])          # forces every widening step
        collect_candidates(nvd, windows=(2, 4, 7))
        self.assertEqual(len(nvd.calls), 3)
        self.assertNotIn("modified", [c.get("by") for c in nvd.calls])

    def test_the_window_widens_only_while_there_is_not_enough(self):
        nvd = RecordingNvd(items=feed(12))
        items, days, considered = collect_candidates(nvd, windows=(2, 4, 7), want=5)
        self.assertEqual(len(nvd.calls), 1, "widened past a sufficient window")
        self.assertEqual(days, 2)
        self.assertEqual(considered, 12)
        self.assertEqual(len(items), 12)

    def test_dedupe_runs_before_the_ranker(self):
        duplicated = feed(6) + feed(6)
        nvd = RecordingNvd(items=duplicated)
        items, _days, considered = collect_candidates(nvd, windows=(2,), want=5)
        self.assertEqual(considered, 12)
        self.assertEqual(len(items), 6, "duplicate CVE ids reached the ranker")


# --------------------------------------------------------------------------- #
# 4. a quiet KEV day still ships; other failures are distinguishable
# --------------------------------------------------------------------------- #

class TestQuietDayAndOtherFailures(unittest.TestCase):

    def test_a_quiet_kev_day_still_produces_a_five_item_issue(self):
        """Full catalogue, nothing in it matches today's CVEs. Tier 2 ships."""
        run = build_issue(kev_fetch=kev_ok(size=1700), nvd_fetch=RecordingNvd(),
                          use_llm=False)
        self.assertEqual(len(run.items), 5)
        self.assertEqual(run.known_exploited, 0)
        self.assertTrue(all(item.tier == 2 for item in run.items))
        self.assertNotIn("KNOWN EXPLOITED", run.markdown)
        self.assertIn("Nothing in today's issue is known-exploited", run.markdown)

    def test_an_nvd_failure_is_its_own_exit_code(self):
        nvd = RecordingNvd(error=NvdError("HTTP 503"))
        with self.assertRaises(FeedFailure):
            build_issue(kev_fetch=kev_ok(), nvd_fetch=nvd, use_llm=False)
        with tempfile.TemporaryDirectory() as tmp:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = entrypoint.main(
                    ["--issues-dir", tmp, "--no-llm"],
                    kev_fetch=kev_ok(), nvd_fetch=RecordingNvd(error=NvdError("503")),
                )
            self.assertEqual(code, FeedFailure.exit_code)
            self.assertEqual(list(Path(tmp).glob("*.md")), [])

    def test_an_empty_feed_writes_nothing_rather_than_an_empty_issue(self):
        """The renderer has a zero-match document. It is not a newsletter."""
        with self.assertRaises(EmptyIssue):
            build_issue(kev_fetch=kev_ok(), nvd_fetch=RecordingNvd(items=[]),
                        use_llm=False)
        with tempfile.TemporaryDirectory() as tmp:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = entrypoint.main(
                    ["--issues-dir", tmp, "--no-llm"],
                    kev_fetch=kev_ok(), nvd_fetch=RecordingNvd(items=[]),
                )
            self.assertEqual(code, EmptyIssue.exit_code)
            self.assertEqual(list(Path(tmp).glob("*.md")), [])

    def test_fewer_candidates_than_the_cap_is_not_padded(self):
        run = build_issue(kev_fetch=kev_ok(), nvd_fetch=RecordingNvd(items=feed(3)),
                          use_llm=False)
        self.assertEqual(len(run.items), 3)
        self.assertEqual(run.markdown.count("\n## "), 3)

    def test_the_issue_never_mentions_a_profile_or_a_homelab(self):
        """This is Project 2. Project 1's vocabulary must not leak into it."""
        run = build_issue(kev_fetch=kev_ok(), nvd_fetch=RecordingNvd(), use_llm=False)
        lowered = run.markdown.lower()
        for banned in ("homelab", "profile", "your stack", "this machine"):
            self.assertNotIn(banned, lowered, f"issue text mentions {banned!r}")

    def test_a_dry_run_writes_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = entrypoint.main(
                    ["--issues-dir", tmp, "--no-llm", "--dry-run"],
                    kev_fetch=kev_ok(), nvd_fetch=RecordingNvd(),
                )
            self.assertEqual(code, 0)
            self.assertEqual(list(Path(tmp).glob("*.md")), [])
            self.assertIn("# CyberWatch Newsletter", out.getvalue())


# --------------------------------------------------------------------------- #
# the checks can fail
# --------------------------------------------------------------------------- #

class TestTheseChecksCanFail(unittest.TestCase):
    """A guard nobody has watched go red is not a guard."""

    def test_a_tolerant_load_kev_would_break_the_outage_tests(self):
        def tolerant(fetch):
            try:
                return fetch()
            except Exception:
                return None      # the exact bug this file exists to prevent

        self.assertIsNone(tolerant(kev_raising(KevError("down"))))
        with self.assertRaises(KevOutage):
            load_kev(kev_raising(KevError("down")))

    def test_a_lastmod_fetch_would_break_the_window_test(self):
        """If collect_candidates asked for lastMod, the window assertion flips."""
        nvd = RecordingNvd()
        nvd(by="modified", days=2)                     # what the bug would look like
        self.assertNotEqual(
            {c.get("by") for c in nvd.calls}, {"published"},
            "the window assertion cannot distinguish a lastMod call",
        )
        real = RecordingNvd()
        build_issue(kev_fetch=kev_ok(), nvd_fetch=real, use_llm=False)
        self.assertEqual({c.get("by") for c in real.calls}, {"published"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
