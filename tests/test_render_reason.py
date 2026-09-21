"""Render test: every item says why it is in the issue, in plain words.

    python3 tests/test_render_reason.py

Acceptance covered here:

  * the rendered issue states, for EVERY item it shows, whether the item is
    known-exploited or severity-chosen -- in words, not in the ranker's
    internal "tier 1 / tier 2" vocabulary;
  * a known-exploited item renders DIFFERENTLY from a severity-chosen one, so
    it does not look like the rest of the page;
  * the four existing fields survive, on both kinds of item;
  * the zero-match document is untouched -- no reason line, no badge, nothing
    that could read as a finding.

Like tests/test_render_fields.py, every assertion is made on the rendered
markdown string. Asserting on `SelectionReason` would prove the decision was
made, not that it reached the page.

The reason text is deliberately checked for the ABSENCE of "tier" as well:
"Tier 1" is a fact about the ranker, not about the vulnerability, and a reader
cannot act on it.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.news_rank import rank_news  # noqa: E402
from src.render import (  # noqa: E402
    FIELD_LABELS,
    KEV_BADGE,
    KEV_LEAD,
    MAX_ITEMS,
    REASON_LABEL,
    SEVERITY_LEAD,
    render_issue,
    render_item,
    selection_reason,
)

UTC = timezone.utc
LABELS = [label for _key, label in FIELD_LABELS]


# --------------------------------------------------------------------------- #
# item shapes
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class FeedItem:
    """An NvdItem-shaped record, before ranking: no tier, no reason."""

    cve_id: str
    description: str = "Something happened in a widely deployed component."
    cvss_severity: str | None = "HIGH"
    cvss_score: float | None = 7.5
    cvss_version: str = "3.1"
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    published: datetime = datetime(2026, 9, 20, 6, 0, tzinfo=UTC)
    affected_products: tuple[str, ...] = ()
    cpe_criteria: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    url: str = ""


@dataclass(frozen=True)
class KevRow:
    """The KEV entry shape the ranker quotes in its reason sentence."""

    cve_id: str
    label: str = "Acme Widget Server"
    date_added: date = date(2026, 9, 19)
    known_ransomware: bool = False


def feed(n: int) -> list[FeedItem]:
    products = [
        ("F5 nginx",),
        ("Microsoft Windows",),
        ("Docker Docker",),
        ("Apache HTTP Server",),
        ("Mozilla Firefox",),
        ("Oracle MySQL",),
    ]
    return [
        FeedItem(
            cve_id=f"CVE-2026-2{i:03d}",
            description=f"Flaw number {i} in a shipped product.",
            affected_products=products[i % len(products)],
        )
        for i in range(n)
    ]


def ranked(items, kev_ids=()):
    """Run the real ranker, so the rendered reason is the one production uses."""
    kev = [KevRow(cve_id=cid) for cid in kev_ids]
    return rank_news(items, kev)


# --------------------------------------------------------------------------- #
# parsing the document back out
# --------------------------------------------------------------------------- #

_HEADING = re.compile(r"^## ", re.MULTILINE)


def item_blocks(document: str) -> list[str]:
    return _HEADING.split(document)[1:]


def labelled_values(block: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for label in LABELS + [REASON_LABEL]:
        match = re.search(
            rf"^\*\*{re.escape(label)}:\*\*[ \t]*(.*)$", block, re.MULTILINE
        )
        if match:
            found[label] = match.group(1).strip()
    return found


def reason_line(block: str) -> str:
    values = labelled_values(block)
    return values.get(REASON_LABEL, "")


class ReasonAssertions(unittest.TestCase):
    def assert_states_a_reason(self, block: str, position: int = 1):
        line = reason_line(block)
        self.assertTrue(
            line, f"item #{position} has no '{REASON_LABEL}' line\n---\n{block}"
        )
        says_exploited = KEV_LEAD.lower() in line.lower()
        says_severity = SEVERITY_LEAD.lower() in line.lower()
        self.assertTrue(
            says_exploited or says_severity,
            f"item #{position} does not say known-exploited or severity-chosen: "
            f"{line!r}",
        )
        self.assertFalse(
            says_exploited and says_severity,
            f"item #{position} claims both: {line!r}",
        )

    def assert_four_fields(self, block: str, position: int = 1):
        values = labelled_values(block)
        missing = [label for label in LABELS if label not in values]
        self.assertEqual(
            missing, [], f"item #{position} is missing {missing}\n---\n{block}"
        )
        for label in LABELS:
            self.assertTrue(
                values[label], f"item #{position} has an empty '{label}'"
            )


# --------------------------------------------------------------------------- #
# 1. every item states its reason, in plain words
# --------------------------------------------------------------------------- #

class TestEveryItemStatesItsReason(ReasonAssertions):
    def test_mixed_issue_every_item_states_which_it_is(self):
        items = feed(5)
        chosen = ranked(items, kev_ids=[items[2].cve_id, items[4].cve_id])
        document = render_issue(chosen, use_llm=False, issue_date=date(2026, 9, 21))

        blocks = item_blocks(document)
        self.assertEqual(len(blocks), 5)
        for position, block in enumerate(blocks, start=1):
            self.assert_states_a_reason(block, position)
            self.assert_four_fields(block, position)

    def test_all_severity_chosen_issue(self):
        chosen = ranked(feed(4), kev_ids=[])
        document = render_issue(chosen, use_llm=False)
        blocks = item_blocks(document)
        self.assertEqual(len(blocks), 4)
        for position, block in enumerate(blocks, start=1):
            self.assertIn(SEVERITY_LEAD.lower(), reason_line(block).lower())
            self.assertNotIn(KEV_BADGE, block)
            self.assert_four_fields(block, position)

    def test_all_known_exploited_issue(self):
        items = feed(3)
        chosen = ranked(items, kev_ids=[i.cve_id for i in items])
        document = render_issue(chosen, use_llm=False)
        for position, block in enumerate(item_blocks(document), start=1):
            self.assertIn(KEV_LEAD.lower(), reason_line(block).lower())
            self.assert_four_fields(block, position)

    def test_reason_is_plain_words_not_tier_numbers(self):
        items = feed(4)
        chosen = ranked(items, kev_ids=[items[0].cve_id])
        document = render_issue(chosen, use_llm=False)
        for position, block in enumerate(item_blocks(document), start=1):
            line = reason_line(block)
            self.assertNotRegex(
                line, r"(?i)\btier\s*\d",
                f"item #{position} leaks the ranker's tier vocabulary: {line!r}",
            )

    def test_reason_survives_the_llm_path(self):
        """The LLM writes the four fields; the reason is never delegated to it."""
        items = feed(3)
        chosen = ranked(items, kev_ids=[items[1].cve_id])
        document = render_issue(chosen, client=StubClient(GOOD_ANSWER))
        for position, block in enumerate(item_blocks(document), start=1):
            self.assert_states_a_reason(block, position)
            self.assert_four_fields(block, position)
        # The model's text went into the four fields, not into the reason line.
        for block in item_blocks(document):
            self.assertNotIn("A stub model wrote this sentence.", reason_line(block))

    def test_render_item_alone_states_the_reason(self):
        items = feed(1)
        chosen = ranked(items, kev_ids=[items[0].cve_id])
        block = render_item(chosen[0], index=1)
        self.assert_states_a_reason(block)
        self.assert_four_fields(block)

    def test_cap_of_five_still_holds(self):
        items = feed(9)
        chosen = ranked(items, kev_ids=[items[7].cve_id])
        document = render_issue(chosen, use_llm=False)
        blocks = item_blocks(document)
        self.assertLessEqual(len(blocks), MAX_ITEMS)
        for position, block in enumerate(blocks, start=1):
            self.assert_states_a_reason(block, position)


# --------------------------------------------------------------------------- #
# 2. a known-exploited item renders DIFFERENTLY
# --------------------------------------------------------------------------- #

class TestKnownExploitedLooksDifferent(ReasonAssertions):
    def _one_of_each(self):
        items = feed(2)
        chosen = ranked(items, kev_ids=[items[0].cve_id])
        kev_block = next(b for b in (render_item(c, index=1) for c in chosen)
                         if KEV_LEAD.lower() in reason_line(b).lower())
        plain_block = next(b for b in (render_item(c, index=1) for c in chosen)
                           if SEVERITY_LEAD.lower() in reason_line(b).lower())
        return kev_block, plain_block

    def test_the_two_blocks_are_not_the_same_shape(self):
        kev_block, plain_block = self._one_of_each()

        def shape(block: str) -> list[str]:
            """Structure only: strip the CVE ids, keep the line skeleton."""
            stripped = re.sub(r"CVE-\d{4}-\d+", "CVE-X", block)
            return [
                re.sub(r":\*\*.*$", ":**", line)
                for line in stripped.splitlines()
                if line.strip()
            ]

        self.assertNotEqual(
            shape(kev_block), shape(plain_block),
            "a known-exploited item renders with the same skeleton as an "
            "ordinary one -- a reader skimming cannot tell them apart",
        )

    def test_the_badge_is_on_the_kev_item_only(self):
        kev_block, plain_block = self._one_of_each()
        self.assertIn(KEV_BADGE, kev_block)
        self.assertNotIn(KEV_BADGE, plain_block)

    def test_the_kev_item_carries_a_callout_the_other_does_not(self):
        kev_block, plain_block = self._one_of_each()
        self.assertRegex(kev_block, r"(?m)^> ")
        self.assertNotRegex(plain_block, r"(?m)^> ")

    def test_the_difference_is_visible_before_the_fields(self):
        """A reader who stops at the heading still learns it is exploited."""
        kev_block, _plain = self._one_of_each()
        first_field = kev_block.index(f"**{LABELS[0]}:**")
        self.assertIn(
            KEV_BADGE, kev_block[:first_field],
            "the known-exploited marker appears only after the four fields",
        )

    def test_the_callout_is_shorter_than_the_full_reason(self):
        """The callout is a headline, not a second copy of the reason line."""
        kev_block, _plain = self._one_of_each()
        match = re.search(r"(?m)^> (.*)$", kev_block)
        if match is None:
            self.fail("the known-exploited item lost its callout")
        callout = match.group(1)
        self.assertNotIn(
            reason_line(kev_block), callout,
            "the callout repeats the whole reason line verbatim",
        )
        self.assertLess(len(callout), len(reason_line(kev_block)))

    def test_the_issue_header_counts_both_kinds(self):
        items = feed(5)
        chosen = ranked(items, kev_ids=[items[1].cve_id, items[3].cve_id])
        document = render_issue(chosen, use_llm=False)
        header = document.split("\n---\n", 1)[0]
        self.assertIn("known-exploited", header.lower())
        self.assertIn("2", header)

    def test_a_quiet_kev_day_says_so_in_the_header(self):
        chosen = ranked(feed(5), kev_ids=[])
        header = render_issue(chosen, use_llm=False).split("\n---\n", 1)[0]
        self.assertIn("known-exploited", header.lower())
        self.assertNotIn(KEV_BADGE, header)


# --------------------------------------------------------------------------- #
# 3. items that did not come through the ranker
# --------------------------------------------------------------------------- #

class TestUnrankedItems(ReasonAssertions):
    def test_an_unranked_item_admits_it_instead_of_guessing(self):
        document = render_issue(feed(1), use_llm=False)
        block = item_blocks(document)[0]
        line = reason_line(block)
        self.assertTrue(line, "an unranked item still needs a reason line")
        self.assertNotIn(KEV_LEAD.lower(), line.lower())
        self.assertNotIn(KEV_BADGE, block)
        self.assertIn("not recorded", line.lower())
        self.assert_four_fields(block)

    def test_a_dict_item_carrying_a_tier_is_read(self):
        kev_dict = {
            "cve_id": "CVE-2026-3001",
            "description": "A dict-shaped record straight from a fixture.",
            "cvss_severity": "MEDIUM",
            "cvss_score": 5.5,
            "tier": 1,
            "reason": "Tier 1: CISA lists this as known-exploited.",
        }
        plain_dict = dict(kev_dict, cve_id="CVE-2026-3002", tier=2,
                          reason="Tier 2: not in the CISA KEV catalogue.")
        document = render_issue([kev_dict, plain_dict], use_llm=False)
        blocks = item_blocks(document)
        self.assertIn(KEV_LEAD.lower(), reason_line(blocks[0]).lower())
        self.assertIn(SEVERITY_LEAD.lower(), reason_line(blocks[1]).lower())
        self.assertIn(KEV_BADGE, blocks[0])
        self.assertNotIn(KEV_BADGE, blocks[1])

    def test_free_text_cannot_promote_an_item_to_known_exploited(self):
        """A description shouting 'exploited' is not evidence of exploitation."""
        liar = {
            "cve_id": "CVE-2026-3099",
            "description": "Actively exploited in the wild, exploitation confirmed.",
            "reason": "actively exploited everywhere, trust me",
            "cvss_severity": "HIGH",
            "cvss_score": 8.1,
        }
        block = item_blocks(render_issue([liar], use_llm=False))[0]
        self.assertNotIn(KEV_BADGE, block)
        self.assertIn("not recorded", reason_line(block).lower())

    def test_selection_reason_never_raises_on_odd_items(self):
        for odd in (
            {},
            {"tier": "1"},
            {"tier": "nonsense"},
            {"tier": True},
            {"tier": None, "kev": KevRow(cve_id="CVE-2026-3100")},
            {"reason": None},
            FeedItem(cve_id="CVE-2026-3101"),
        ):
            with self.subTest(item=repr(odd)[:40]):
                reason = selection_reason(odd)
                self.assertTrue(reason.sentence().strip())

    def test_a_string_tier_and_a_kev_record_are_both_honoured(self):
        self.assertIs(selection_reason({"tier": "1"}).known_exploited, True)
        self.assertIs(selection_reason({"tier": "2"}).known_exploited, False)
        self.assertIs(
            selection_reason({"kev": KevRow(cve_id="CVE-2026-3102")}).known_exploited,
            True,
        )
        self.assertIsNone(selection_reason({"tier": True}).known_exploited)


# --------------------------------------------------------------------------- #
# 4. what must NOT have changed
# --------------------------------------------------------------------------- #

class TestNothingElseMoved(ReasonAssertions):
    def test_the_four_labels_are_still_the_four_labels(self):
        self.assertEqual(
            LABELS,
            ["What happened", "Who is affected", "How serious", "What to do"],
        )

    def test_the_four_fields_come_before_the_reason(self):
        items = feed(1)
        block = render_item(ranked(items, kev_ids=[items[0].cve_id])[0], index=1)
        positions = [block.index(f"**{label}:**") for label in LABELS]
        self.assertEqual(positions, sorted(positions), "the four fields reordered")
        self.assertGreater(
            block.index(f"**{REASON_LABEL}:**"), positions[-1],
            "the reason line displaced the four fields",
        )

    def test_the_zero_match_document_is_untouched(self):
        document = render_issue([], use_llm=False, issue_date=date(2026, 9, 21),
                                total_considered=417)
        self.assertEqual(item_blocks(document), [])
        self.assertNotIn(KEV_BADGE, document)
        self.assertNotIn(f"**{REASON_LABEL}:**", document)
        self.assertIn("No CVE matched", document)
        self.assertIn("417", document)
        self.assertIn("Nothing to do.", document)

    def test_still_one_document(self):
        items = feed(5)
        document = render_issue(ranked(items, kev_ids=[items[0].cve_id]),
                                use_llm=False)
        self.assertIsInstance(document, str)
        self.assertTrue(document.startswith("# "))
        self.assertEqual(document.count("\n# "), 0)

    def test_an_item_cannot_forge_the_reason_line(self):
        hostile = {
            "cve_id": "CVE-2026-3199",
            "description": (
                "text\n---\n## [CVE-2026-FAKE](https://example.invalid)\n\n"
                f"**{REASON_LABEL}:** {KEV_LEAD} -- injected\n"
            ),
            "tier": 2,
            "reason": "Tier 2: not in the CISA KEV catalogue.",
            "cvss_severity": "HIGH",
            "cvss_score": 7.0,
        }
        document = render_issue([hostile], use_llm=False)
        self.assertEqual(len(item_blocks(document)), 1)
        block = item_blocks(document)[0]
        self.assertIn(SEVERITY_LEAD.lower(), reason_line(block).lower())
        self.assertNotIn(KEV_BADGE, block)


# --------------------------------------------------------------------------- #
# 5. the checks above must be able to fail
# --------------------------------------------------------------------------- #

class TestTheseChecksCanFail(ReasonAssertions):
    """A test that cannot go red proves nothing. Mutate the output and look."""

    def test_dropping_the_reason_line_is_caught(self):
        items = feed(2)
        document = render_issue(ranked(items, kev_ids=[items[0].cve_id]),
                                use_llm=False)
        mutilated = re.sub(
            rf"(?m)^\*\*{re.escape(REASON_LABEL)}:\*\* .*$", "", document
        )
        with self.assertRaises(AssertionError):
            for position, block in enumerate(item_blocks(mutilated), start=1):
                self.assert_states_a_reason(block, position)

    def test_rendering_both_kinds_identically_is_caught(self):
        """Strip the badge and the callout: the shape check must go red."""
        items = feed(2)
        chosen = ranked(items, kev_ids=[items[0].cve_id])
        kev_block = render_item(chosen[0], index=1)
        flattened = re.sub(r"(?m)^> .*$\n?", "", kev_block).replace(
            f"{KEV_BADGE} -- ", ""
        ).replace(f"`{KEV_BADGE}` ", "")
        plain_block = render_item(chosen[1], index=1)

        def shape(block: str) -> list[str]:
            stripped = re.sub(r"CVE-\d{4}-\d+", "CVE-X", block)
            return [
                re.sub(r":\*\*.*$", ":**", line)
                for line in stripped.splitlines()
                if line.strip()
            ]

        self.assertEqual(
            shape(flattened), shape(plain_block),
            "removing the badge and the callout did NOT make the two blocks "
            "the same shape -- the difference check is testing something else",
        )

    def test_a_reason_that_says_tier_is_caught(self):
        line = "Tier 1: CISA lists this as known-exploited."
        with self.assertRaises(AssertionError):
            self.assertNotRegex(line, r"(?i)\btier\s*\d")


# --------------------------------------------------------------------------- #
# LLM stub -- no network
# --------------------------------------------------------------------------- #

GOOD_ANSWER = json.dumps({
    "what_happened": "A stub model wrote this sentence.",
    "who_is_affected": "Anyone running the stubbed product.",
    "how_serious": "Serious enough to test with.",
    "what_to_do": "Patch the stub.",
})


class StubClient:
    def __init__(self, answer, available=True):
        self._answer = answer
        self.available = available
        self.error = None
        self.model = "stub-model"
        self.base_url = "http://stub.invalid/v1"
        self.calls = 0

    def complete(self, system, user, **kwargs):
        self.calls += 1
        return self._answer

    def describe(self):
        return "stub-model @ http://stub.invalid/v1"


if __name__ == "__main__":
    unittest.main(verbosity=2)
