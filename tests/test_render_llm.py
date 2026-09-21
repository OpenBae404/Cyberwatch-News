"""Render test: the LLM is actually asked to write, and silence is loud.

    python3 tests/test_render_llm.py

Two defects are covered here, and they are the same defect seen from two ends.

**The model was never given a chance to answer.** The newsletter's server runs
a reasoning model. Asked with default settings and a modest ``max_tokens`` it
spends the whole budget on hidden chain-of-thought and returns
``content: null`` with ``finish_reason: "length"``. Reproduced against the live
server on 2026-09-21:

    thinking on (default): finish='length' tokens=200 content=None
    thinking off:          finish='stop'   tokens=17  content='Cisco ISE allows...'

So every summarisation call must carry
``chat_template_kwargs: {"enable_thinking": false}``. The assertions below are
made on the **bytes handed to urlopen**, not on the payload dict the code
built, because the card's warning is precisely that a flag can be set in code
and still not arrive: a wrapper could drop an unknown key, or nest it where the
server does not look. Decoding the request body is the only check that cannot
be satisfied by intent.

**The failure was silent.** issues/2026-09-21.md shipped with a kernel commit
message in "What happened" and raw CPE strings in "Who is affected", under one
apologetic line in the footer. A reader skimming it saw a normal newsletter.
So: when the model is asked and writes nothing usable, the document must say
so where it cannot be missed, and ``strict=True`` must refuse to produce a
document at all.

The last class is the control. Every assertion here is re-run against a
deliberately silent renderer -- one that swallows the failure the way the
shipped code did -- and must FAIL against it. A loudness test that passes on a
silent renderer proves nothing.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import src.render as render  # noqa: E402
from src.render import (  # noqa: E402
    FAILURE_BADGE,
    FIELD_LABELS,
    ItemSummary,
    LLMClient,
    SummaryFailure,
    render_issue,
    render_item,
    summarise_item,
)

UTC = timezone.utc
LABELS = [label for _key, label in FIELD_LABELS]

GOOD_ANSWER = json.dumps({
    "what_happened": "A model wrote this sentence about the flaw.",
    "who_is_affected": "Anyone running the affected release.",
    "how_serious": "Serious; remotely reachable.",
    "what_to_do": "Apply the vendor update.",
})


@dataclass(frozen=True)
class Item:
    """An NVD-shaped record whose raw text is recognisably raw.

    The description is a real kernel commit message and the products are real
    CPE strings, so a test can tell "the model wrote this" from "the renderer
    printed the record" by looking at the page.
    """

    cve_id: str = "CVE-2025-39682"
    description: str = (
        "tls: fix handling of zero-length records on the rx_list Each "
        "recvmsg() call must process either -- all the records in rx_list or "
        "the full requested length."
    )
    cvss_severity: str | None = "HIGH"
    cvss_score: float | None = 7.1
    cvss_version: str = "3.1"
    cvss_vector: str = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
    published: datetime = datetime(2026, 9, 20, 6, 0, tzinfo=UTC)
    affected_products: tuple[str, ...] = (
        "linux linux kernel", "debian debian linux",
        "siemens simatic cn 4100 firmware",
    )
    cpe_criteria: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    matched_terms: tuple[str, ...] = ("linux",)
    score: int = 300
    url: str = ""
    tier: int = 2
    reason: str = "Tier 2: high severity in widely deployed software."


def items(n: int) -> list[Item]:
    return [Item(cve_id=f"CVE-2026-3{i:03d}") for i in range(n)]


# --------------------------------------------------------------------------- #
# a fake socket: every request body is captured verbatim
# --------------------------------------------------------------------------- #

class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class FakeServer:
    """Stands in for ``urllib.request.urlopen`` inside src.render.

    Records the raw bytes of every request so a test can assert on what was
    transmitted. ``chat_body`` is what the server would actually parse.
    """

    def __init__(self, chat_response, *, models=("a local model",)):
        self._chat_response = chat_response
        self._models = models
        self.requests: list[tuple[str, bytes | None]] = []

    def __call__(self, req, timeout=None):
        url = req.full_url
        body = req.data
        self.requests.append((url, body))
        if url.endswith("/models"):
            payload = {"data": [{"id": name} for name in self._models]}
        else:
            response = self._chat_response
            if callable(response):
                response = response(json.loads(body.decode()))
            payload = response
        return FakeResponse(json.dumps(payload).encode())

    # -- what the wire actually carried ---------------------------------- #

    def chat_bodies(self) -> list[dict]:
        return [
            json.loads(body.decode())
            for url, body in self.requests
            if body and url.endswith("/chat/completions")
        ]


def chat_ok(content: str) -> dict:
    return {
        "choices": [{"message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
        "usage": {"completion_tokens": 20},
    }


# The exact shape the live server returns when it is left thinking: the
# failure this card exists to stop.
THINKING_RESPONSE = {
    "choices": [{"message": {"role": "assistant", "content": None},
                 "finish_reason": "length"}],
    "usage": {"completion_tokens": 200, "total_tokens": 812},
}


def client_against(server: FakeServer) -> LLMClient:
    original = render.urllib.request.urlopen
    render.urllib.request.urlopen = server
    try:
        return LLMClient("http://fake.invalid/v1", timeout=1)
    finally:
        render.urllib.request.urlopen = original


def talk(server: FakeServer, fn):
    """Run `fn(client)` with urlopen pointed at `server`."""
    client = client_against(server)
    original = render.urllib.request.urlopen
    render.urllib.request.urlopen = server
    try:
        return fn(client)
    finally:
        render.urllib.request.urlopen = original


# --------------------------------------------------------------------------- #
# 1. the flag is on the wire, not just in the code
# --------------------------------------------------------------------------- #

class TestThinkingIsDisabledOnTheWire(unittest.TestCase):
    def test_every_summarisation_call_transmits_enable_thinking_false(self):
        server = FakeServer(chat_ok(GOOD_ANSWER))
        document = talk(server, lambda c: render_issue(items(5), client=c))

        bodies = server.chat_bodies()
        self.assertEqual(len(bodies), 5, "expected one chat call per item")
        for position, body in enumerate(bodies, start=1):
            kwargs = body.get("chat_template_kwargs")
            self.assertIsInstance(
                kwargs, dict,
                f"call #{position} sent no chat_template_kwargs: {body!r}",
            )
            self.assertIs(
                kwargs.get("enable_thinking"), False,
                f"call #{position} did not disable thinking: {kwargs!r}",
            )
        self.assertIn("A model wrote this sentence", document)

    def test_the_flag_survives_json_serialisation_verbatim(self):
        """Assert on the bytes, not on a dict this process built.

        A key can be present in the payload object and still not reach the
        server -- dropped by a wrapper, or nested where nothing reads it. The
        decoded request body is the only evidence that settles it.
        """
        server = FakeServer(chat_ok(GOOD_ANSWER))
        talk(server, lambda c: summarise_item(items(1)[0], c))

        raw = [body for url, body in server.requests
               if body and url.endswith("/chat/completions")]
        self.assertEqual(len(raw), 1)
        text = raw[0].decode()
        self.assertIn('"chat_template_kwargs"', text)
        self.assertIn('"enable_thinking": false', text)
        # And it is where the server reads it: top level of the body, not
        # buried under an extra_body envelope that only a python client
        # understands.
        body = json.loads(text)
        self.assertIn("chat_template_kwargs", body)
        self.assertNotIn("extra_body", body)

    def test_client_records_what_it_transmitted(self):
        server = FakeServer(chat_ok(GOOD_ANSWER))
        client = talk(server, lambda c: (c.complete("sys", "user"), c)[1])
        self.assertIsNotNone(client.last_request_bytes)
        sent = json.loads(client.last_request_bytes.decode())
        self.assertEqual(sent["chat_template_kwargs"], {"enable_thinking": False})
        self.assertEqual(sent, client.last_request)


# --------------------------------------------------------------------------- #
# 2. a thinking model that answers nothing is detected and named
# --------------------------------------------------------------------------- #

class TestNoUsableOutputIsDetected(unittest.TestCase):
    def test_null_content_with_length_finish_is_not_mistaken_for_an_answer(self):
        server = FakeServer(THINKING_RESPONSE)

        def ask(client):
            return client.complete("sys", "user"), client.error

        answer, error = talk(server, ask)
        self.assertIsNone(answer, "chain-of-thought silence read as an answer")
        self.assertIn("enable_thinking", error or "")

    def test_the_diagnosis_names_the_reasoning_model_case(self):
        server = FakeServer(THINKING_RESPONSE)

        def check(c):
            c.complete("sys", "user")
            return c.error or ""

        error = talk(server, check)
        self.assertIn("no content", error)
        self.assertIn("200 tokens", error)

    def test_summarise_item_marks_the_item_failed_not_raw(self):
        server = FakeServer(THINKING_RESPONSE)
        summary = talk(server, lambda c: summarise_item(items(1)[0], c))
        self.assertTrue(summary.failed, "a model that wrote nothing counted as fine")
        self.assertEqual(summary.source, "failed")
        self.assertTrue(summary.error, "the failure carries no reason")

    def test_not_asking_the_model_is_not_a_failure(self):
        """--no-llm is an expected path and must stay quiet."""
        summary = summarise_item(items(1)[0], None)
        self.assertEqual(summary.source, "raw")
        self.assertFalse(summary.failed)
        document = render_issue(items(3), use_llm=False)
        self.assertNotIn(FAILURE_BADGE, document)

    def test_every_unusable_answer_shape_is_a_failure_not_a_quiet_fallback(self):
        shapes = {
            "thinking, no content": THINKING_RESPONSE,
            "empty string": chat_ok(""),
            "prose, not json": chat_ok("I am afraid I cannot help with that."),
            "json array": chat_ok("[1, 2, 3]"),
            "missing a key": chat_ok(json.dumps({"what_happened": "x"})),
            "empty value": chat_ok(json.dumps({
                "what_happened": "x", "who_is_affected": "",
                "how_serious": "z", "what_to_do": "w",
            })),
        }
        for name, response in shapes.items():
            with self.subTest(answer=name):
                server = FakeServer(response)
                summary = talk(server, lambda c: summarise_item(items(1)[0], c))
                self.assertTrue(
                    summary.failed,
                    f"{name!r} was treated as an acceptable fallback",
                )


# --------------------------------------------------------------------------- #
# 3. the failure is loud on the page
# --------------------------------------------------------------------------- #

class LoudnessAssertions(unittest.TestCase):
    """The assertions a document must satisfy when summaries failed.

    Kept in one place so the control class below can run the same ones
    against a silent renderer and watch them fail.
    """

    def assert_document_is_loud(self, document: str, warned: str):
        head = document.split("\n---\n", 1)[0]
        self.assertIn(
            FAILURE_BADGE, head,
            "the failure is not announced before the first item:\n" + head,
        )
        self.assertIn(
            FAILURE_BADGE, document.rsplit("\n---\n", 1)[-1],
            "the footer does not record the failure",
        )
        for block in document.split("\n## ")[1:]:
            self.assertIn(
                FAILURE_BADGE, block,
                "an item shows raw NVD text without saying so:\n" + block,
            )
        self.assertIn(
            "raw", document.lower(),
            "the document never tells the reader the fields are raw data",
        )
        self.assertTrue(warned.strip(), "nothing was written to the warning stream")
        self.assertIn(
            "raw NVD text", warned,
            "the warning does not say the fields are raw data: " + warned,
        )

    def render_failing(self, count=3, strict=False, warn=None):
        server = FakeServer(THINKING_RESPONSE)
        return talk(server, lambda c: render_issue(
            items(count), client=c, strict=strict, warn=warn,
            issue_date=date(2026, 9, 21),
        ))


class TestTheFailureIsLoud(LoudnessAssertions):
    def test_a_failed_run_announces_itself_everywhere(self):
        warn = io.StringIO()
        document = self.render_failing(3, warn=warn)
        self.assert_document_is_loud(document, warn.getvalue())

    def test_the_raw_text_is_still_there_but_is_labelled(self):
        """Falling back is allowed. Falling back quietly is not."""
        warn = io.StringIO()
        document = self.render_failing(1, warn=warn)
        self.assertIn("tls: fix handling of zero-length records", document)
        self.assertIn("linux linux kernel", document)
        self.assert_document_is_loud(document, warn.getvalue())

    def test_strict_refuses_to_produce_a_document(self):
        with self.assertRaises(SummaryFailure) as caught:
            self.render_failing(2, strict=True)
        self.assertIn("raw NVD text", str(caught.exception))

    def test_a_mixed_run_is_still_loud(self):
        """One good answer must not launder four failures."""
        state = {"n": 0}

        def flaky(_payload):
            state["n"] += 1
            return chat_ok(GOOD_ANSWER) if state["n"] == 1 else THINKING_RESPONSE

        server = FakeServer(flaky)
        warn = io.StringIO()
        document = talk(server, lambda c: render_issue(
            items(5), client=c, warn=warn,
        ))
        head = document.split("\n---\n", 1)[0]
        self.assertIn(FAILURE_BADGE, head)
        self.assertIn("4 of 5", head)
        self.assertTrue(warn.getvalue().strip())

    def test_a_successful_run_says_nothing_about_failure(self):
        server = FakeServer(chat_ok(GOOD_ANSWER))
        warn = io.StringIO()
        document = talk(server, lambda c: render_issue(
            items(4), client=c, warn=warn,
        ))
        self.assertNotIn(FAILURE_BADGE, document)
        self.assertEqual(warn.getvalue(), "")
        self.assertIn("4/4 written by", document)

    def test_render_item_alone_carries_the_warning(self):
        failed = ItemSummary(
            what_happened="raw", who_is_affected="raw",
            how_serious="raw", what_to_do="raw",
            source="failed", error="model returned no content",
        )
        block = render_item(items(1)[0], failed, index=1)
        self.assertIn(FAILURE_BADGE, block)
        self.assertIn("model returned no content", block)
        for label in LABELS:
            self.assertIn(f"**{label}:**", block)


# --------------------------------------------------------------------------- #
# 4. the control: a silent renderer must FAIL every assertion above
# --------------------------------------------------------------------------- #

class TestTheLoudnessCheckCanFail(LoudnessAssertions):
    """Re-runs the loudness assertions against the behaviour that shipped.

    Without this class, `TestTheFailureIsLoud` could pass because of a badge
    that appears on every document, or an assertion that never bites. Here the
    failure is silenced exactly as the released renderer silenced it -- the
    fields fall back to raw text and nothing says so -- and each assertion is
    required to raise.
    """

    def silent_document(self, count=3) -> str:
        """What the old code produced: raw fallback, one line in the footer."""
        server = FakeServer(THINKING_RESPONSE)

        def silent_summarise(item, client=None):
            summary = render.raw_summary(item)
            if client is not None and client.available:
                client.complete(render._SYSTEM, render._prompt_for(item))
            return summary  # source stays "raw": the defect

        original = render.summarise_item
        render.summarise_item = silent_summarise
        try:
            return talk(server, lambda c: render_issue(
                items(count), client=c, warn=io.StringIO(),
                issue_date=date(2026, 9, 21),
            ))
        finally:
            render.summarise_item = original

    def test_the_silent_renderer_fails_the_loudness_check(self):
        document = self.silent_document()
        # It still looks like a normal issue -- that is the bug.
        self.assertIn("tls: fix handling of zero-length records", document)
        with self.assertRaises(AssertionError):
            self.assert_document_is_loud(document, "")

    def test_the_silent_renderer_would_not_raise_under_strict(self):
        """strict=True is only meaningful because the silent path ignored it."""
        document = self.silent_document(2)
        self.assertNotIn(FAILURE_BADGE, document)

    def test_a_document_that_drops_the_per_item_badge_is_caught(self):
        """Banner at the top, nothing on the items: still not loud enough.

        A reader who scrolls past the header to an item must not find four
        fields of raw NVD text presented as a summary, so stripping the badge
        from the item blocks alone has to break the check.
        """
        warn = io.StringIO()
        document = self.render_failing(3, warn=warn)
        head, sep, body = document.partition("\n---\n")
        mutilated = head + sep + body.replace(FAILURE_BADGE, "Note")
        with self.assertRaises(AssertionError):
            self.assert_document_is_loud(mutilated, warn.getvalue())

    def test_a_document_that_only_whispers_in_the_footer_is_caught(self):
        warn = io.StringIO()
        document = self.render_failing(2, warn=warn)
        head, sep, tail = document.partition("\n---\n")
        whispered = head.replace(FAILURE_BADGE, "note") + sep + tail
        with self.assertRaises(AssertionError):
            self.assert_document_is_loud(whispered, warn.getvalue())

    def test_a_silent_warning_stream_is_caught(self):
        document = self.render_failing(2, warn=io.StringIO())
        with self.assertRaises(AssertionError):
            self.assert_document_is_loud(document, "")

    def test_a_payload_without_the_flag_is_caught(self):
        """The wire assertion must bite when the flag is missing."""
        server = FakeServer(chat_ok(GOOD_ANSWER))

        original = LLMClient.complete

        def thinking_on(self, system, user, *, max_tokens=600):
            payload = {
                "model": self.model,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}],
                "max_tokens": max_tokens,
            }
            body = self._request("/chat/completions", payload)
            return body["choices"][0]["message"]["content"]

        LLMClient.complete = thinking_on
        try:
            talk(server, lambda c: summarise_item(items(1)[0], c))
        finally:
            LLMClient.complete = original

        body = server.chat_bodies()[0]
        checker = TestThinkingIsDisabledOnTheWire(
            "test_every_summarisation_call_transmits_enable_thinking_false"
        )
        with self.assertRaises(AssertionError):
            checker.assertIsInstance(
                body.get("chat_template_kwargs"), dict, "no flag sent"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
