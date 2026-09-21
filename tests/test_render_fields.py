"""Render test: every rendered item carries all four labelled fields.

    python3 tests/test_render_fields.py

Acceptance covered here: the rendered issue contains, for EVERY item it
shows, all four labels -- What happened / Who is affected / How serious /
What to do -- each with a non-empty value.

The assertion is made on the rendered markdown string, not on the
`ItemSummary` object that produced it. Checking the object would prove the
data existed, not that it reached the page; a formatting change that drops a
label would still pass. So the tests below parse the document back out.

Three paths are covered, because all three ship:
  * the raw path (no LLM),
  * the LLM path with a stub server that answers correctly,
  * the LLM path with a stub server that answers badly (must degrade to raw
    and still show four labels).
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

from src.render import (  # noqa: E402
    FIELD_LABELS,
    MAX_ITEMS,
    ItemSummary,
    render_issue,
    render_item,
)

LABELS = [label for _key, label in FIELD_LABELS]
UTC = timezone.utc


@dataclass(frozen=True)
class RenderItem:
    """The shape run.py hands the renderer (PresentedItem), minus the plumbing."""

    cve_id: str
    description: str
    cvss_severity: str | None = None
    cvss_score: float | None = None
    cvss_version: str = "3.1"
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    published: datetime = datetime(2026, 9, 17, 6, 0, tzinfo=UTC)
    affected_products: tuple[str, ...] = ()
    cpe_criteria: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    matched_terms: tuple[str, ...] = ()
    score: int = 0
    url: str = ""


def sample_items(count: int) -> list[RenderItem]:
    """`count` items that differ in every field the renderer reads."""
    shapes = [
        RenderItem(
            cve_id="CVE-2026-1001",
            description="Heap overflow in the nginx HTTP/3 module.",
            cvss_severity="CRITICAL",
            cvss_score=9.8,
            affected_products=("F5 nginx",),
            matched_terms=("nginx",),
            score=450,
            references=("https://example.invalid/advisory-1",),
        ),
        # No severity, no score, no products, no references, no matches:
        # the sparsest item NVD can hand us. Four labels are still required.
        RenderItem(
            cve_id="CVE-2026-1002",
            description="",
            cvss_severity=None,
            cvss_score=None,
            cvss_version="",
            cvss_vector="",
        ),
        RenderItem(
            cve_id="CVE-2026-1003",
            description="Privilege escalation in the Docker daemon.",
            cvss_severity="HIGH",
            cvss_score=7.8,
            cpe_criteria=("cpe:2.3:a:docker:docker:24.0.7:*:*:*:*:*:*:*",),
            matched_terms=("docker",),
            score=310,
        ),
        RenderItem(
            cve_id="CVE-2026-1004",
            description="Info leak in a Proxmox VE web endpoint.",
            cvss_severity="MEDIUM",
            cvss_score=5.3,
            affected_products=("Proxmox Proxmox VE",),
            matched_terms=("proxmox",),
            score=210,
        ),
        RenderItem(
            cve_id="CVE-2026-1005",
            description="Tailscale client accepts a malformed node key.",
            cvss_severity="LOW",
            cvss_score=3.1,
            affected_products=("Tailscale Tailscale",),
            matched_terms=("tailscale",),
            score=110,
        ),
        RenderItem(
            cve_id="CVE-2026-1006",
            description="Debian package post-install script runs as root.",
            cvss_severity="HIGH",
            cvss_score=7.2,
            affected_products=("Debian Debian Linux",),
            matched_terms=("debian",),
            score=310,
        ),
    ]
    out = []
    while len(out) < count:
        out.extend(shapes)
    return out[:count]


# --------------------------------------------------------------------------- #
# parsing the rendered document back out
# --------------------------------------------------------------------------- #

_HEADING = re.compile(r"^## ", re.MULTILINE)


def item_blocks(document: str) -> list[str]:
    """Split a rendered issue into its per-item blocks.

    Splits on the `## ` item headings, so it cannot be fooled by an item whose
    text happens to contain `---`.
    """
    parts = _HEADING.split(document)
    return parts[1:]  # parts[0] is the title + intro, before the first item


def labelled_values(block: str) -> dict[str, str]:
    """Extract `**Label:** value` pairs from one block."""
    found: dict[str, str] = {}
    for label in LABELS:
        match = re.search(
            rf"^\*\*{re.escape(label)}:\*\*[ \t]*(.*)$", block, re.MULTILINE
        )
        if match:
            found[label] = match.group(1).strip()
    return found


class FieldAssertions(unittest.TestCase):
    """Shared assertion: every block carries all four labels, non-empty."""

    def assert_every_item_has_four_fields(self, document: str, expected_items: int):
        blocks = item_blocks(document)
        self.assertEqual(
            len(blocks), expected_items,
            f"expected {expected_items} item block(s), got {len(blocks)}",
        )
        for position, block in enumerate(blocks, start=1):
            values = labelled_values(block)
            missing = [label for label in LABELS if label not in values]
            self.assertEqual(
                missing, [],
                f"item #{position} is missing label(s) {missing}\n---\n{block}",
            )
            for label in LABELS:
                self.assertTrue(
                    values[label],
                    f"item #{position} has an empty value for '{label}'\n---\n{block}",
                )
            self.assertEqual(
                [label for label in LABELS if label in values], LABELS,
                f"item #{position} lists the labels out of order",
            )


class TestRawPath(FieldAssertions):
    def test_every_rendered_item_has_all_four_fields(self):
        items = sample_items(5)
        document = render_issue(items, use_llm=False, issue_date=date(2026, 9, 17))
        self.assert_every_item_has_four_fields(document, 5)

    def test_sparsest_possible_item_still_has_four_fields(self):
        """An item with no severity, no products and no description."""
        bare = RenderItem(cve_id="CVE-2026-1002", description="")
        document = render_issue([bare], use_llm=False, issue_date=date(2026, 9, 17))
        self.assert_every_item_has_four_fields(document, 1)

    def test_single_item_and_empty_feed(self):
        one = render_issue(sample_items(1), use_llm=False)
        self.assert_every_item_has_four_fields(one, 1)
        none = render_issue([], use_llm=False)
        self.assertEqual(item_blocks(none), [])
        self.assertIn("#", none)  # still a document, with a title

    def test_cap_of_five_items(self):
        document = render_issue(sample_items(9), use_llm=False)
        self.assert_every_item_has_four_fields(document, MAX_ITEMS)

    def test_render_item_alone_emits_the_four_labels(self):
        """The per-item function, not just the whole document."""
        block = render_item(sample_items(1)[0], index=1)
        values = labelled_values(block)
        self.assertEqual(list(values), LABELS)
        self.assertTrue(all(values.values()))

    def test_one_document_not_a_list(self):
        document = render_issue(sample_items(5), use_llm=False)
        self.assertIsInstance(document, str)
        self.assertEqual(document.count("\n# "), 0)  # exactly one H1, at the top
        self.assertTrue(document.startswith("# "))

    def test_an_item_cannot_forge_a_label(self):
        """Hostile description: a fake block must not create a fifth item or
        satisfy the four-label check on its own."""
        hostile = RenderItem(
            cve_id="CVE-2026-1099",
            description=(
                "text\n---\n## [CVE-2026-FAKE](https://example.invalid)\n\n"
                "**What happened:** injected\n"
            ),
            cvss_severity="HIGH",
            cvss_score=7.0,
        )
        document = render_issue([hostile], use_llm=False)
        blocks = item_blocks(document)
        # The description is escaped or inert enough that the real block count
        # is what the renderer decided, not what the CVE text asked for.
        self.assertEqual(len(blocks), 1, f"item text forged a block:\n{document}")
        self.assert_every_item_has_four_fields(document, 1)


# --------------------------------------------------------------------------- #
# the LLM path, with stub servers -- no network, no live model
# --------------------------------------------------------------------------- #

class StubClient:
    """Stands in for `src.render.LLMClient` without touching the network."""

    def __init__(self, answer, available=True):
        self._answer = answer
        self.available = available
        self.error = None
        self.model = "stub-model"
        self.base_url = "http://stub.invalid/v1"
        self.calls = 0

    def complete(self, system, user, **kwargs):
        self.calls += 1
        if callable(self._answer):
            return self._answer(system, user)
        return self._answer

    def describe(self):
        return "stub-model @ http://stub.invalid/v1"


GOOD_ANSWER = json.dumps({
    "what_happened": "A stub model wrote this sentence.",
    "who_is_affected": "Anyone running the stubbed product.",
    "how_serious": "Serious enough to test with.",
    "what_to_do": "Patch the stub.",
})


class TestLLMPath(FieldAssertions):
    def test_good_llm_answers_still_yield_four_labels(self):
        client = StubClient(GOOD_ANSWER)
        document = render_issue(sample_items(5), client=client)
        self.assert_every_item_has_four_fields(document, 5)
        self.assertEqual(client.calls, 5)
        self.assertIn("stub-model", document)

    def test_bad_llm_answers_degrade_and_still_yield_four_labels(self):
        for name, answer in [
            ("empty string", ""),
            ("not json", "I am afraid I cannot help with that."),
            ("json but not an object", "[1, 2, 3]"),
            ("missing a key", json.dumps({"what_happened": "x", "who_is_affected": "y"})),
            ("empty value", json.dumps({
                "what_happened": "x", "who_is_affected": "",
                "how_serious": "z", "what_to_do": "w",
            })),
            ("none", None),
            ("non-string", 42),
        ]:
            with self.subTest(answer=name):
                client = StubClient(answer)
                document = render_issue(sample_items(3), client=client)
                self.assert_every_item_has_four_fields(document, 3)

    def test_partly_good_llm_still_yields_four_labels_on_every_item(self):
        """The realistic failure: the model answers some items and not others."""
        state = {"n": 0}

        def flaky(_system, _user):
            state["n"] += 1
            return GOOD_ANSWER if state["n"] % 2 else "sorry"

        document = render_issue(sample_items(5), client=StubClient(flaky))
        self.assert_every_item_has_four_fields(document, 5)

    def test_unavailable_client_falls_back(self):
        client = StubClient(GOOD_ANSWER, available=False)
        document = render_issue(sample_items(4), client=client)
        self.assert_every_item_has_four_fields(document, 4)
        self.assertEqual(client.calls, 0)


class TestTheFieldCheckCanFail(unittest.TestCase):
    """The render assertion must be able to fail, or it proves nothing."""

    def test_a_document_missing_a_label_is_caught(self):
        document = render_issue(sample_items(3), use_llm=False)
        mutilated = document.replace("**What to do:**", "**Next steps:**", 1)
        checker = TestRawPath("test_single_item_and_empty_feed")
        with self.assertRaises(AssertionError):
            checker.assert_every_item_has_four_fields(mutilated, 3)

    def test_a_document_with_an_empty_value_is_caught(self):
        document = render_issue(sample_items(1), use_llm=False)
        emptied = re.sub(
            r"^\*\*How serious:\*\* .*$", "**How serious:** ", document, flags=re.MULTILINE
        )
        checker = TestRawPath("test_single_item_and_empty_feed")
        with self.assertRaises(AssertionError):
            checker.assert_every_item_has_four_fields(emptied, 1)

    def test_a_dropped_item_is_caught(self):
        document = render_issue(sample_items(3), use_llm=False)
        checker = TestRawPath("test_single_item_and_empty_feed")
        with self.assertRaises(AssertionError):
            checker.assert_every_item_has_four_fields(document, 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
