"""The static site: every acceptance criterion of the delivery phase.

Each test here corresponds to one line of the card, plus the two dangers the
card does not name but publishing creates: attacker-controlled text in a CVE
description reaching the page as markup, and the internal LLM endpoint in the
issue footer reaching a public repository.

The real issues in ``issues/`` are used where the criterion is about them
("every file in issues/ produces one page"). Everything that has to be provable
on hostile input uses a crafted issue in a temp dir, so the test does not depend
on what today's feeds happened to contain.
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import build_site  # noqa: E402
from src import site  # noqa: E402

REAL_ISSUES = ROOT / "issues"

# A CVE description of the kind NVD actually publishes: it quotes the attacker's
# input. If the generator formats before escaping, this becomes a live element.
HOSTILE_ISSUE = """\
# CyberWatch Newsletter -- 2026-01-02

1 items out of 9 considered, known-exploited first, then severity and reach (cap 5).

Selection: 1 known-exploited (in the CISA KEV catalogue).

---

## 1. KNOWN EXPLOITED -- [CVE-2026-00001](https://nvd.nist.gov/vuln/detail/CVE-2026-00001)  \n`KNOWN EXPLOITED` `CRITICAL` `CVSS 9.8` `published 2026-01-01`

> **KNOWN EXPLOITED.** CISA lists this as known-exploited in Example Suite.

**What happened:** A crafted request containing <script>alert(1)</script> and
an <img src=x onerror="alert(2)"> payload is stored unescaped, and the parser
also mishandles a & b when value < 5 or value > 9.

**Who is affected:** Anyone running <Example Suite> 1.0 & earlier.

A <svg onload=alert(3)> payload sits before **the first bold run** on this
line, which is the only place a leading text run exists.

**How serious:** Critical. Rated `<b>9.8</b>` by the vendor's own advisory.

**What to do:** Patch. See <https://example.com/advisory>.

**Why this is here:** Known exploited -- CRITICAL (CVSS 9.8); reach 40/100.

---

_Summaries: 1/1 written by local LLM at http://localhost:8001/v1 (model: a local model)._
_Source: NVD CVE 2.0 API._
"""


class SiteTestCase(unittest.TestCase):
    """Builds a site in a temp dir from whatever issues the test supplies."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cyberwatch-site-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.issues = self.tmp / "issues"
        self.docs = self.tmp / "docs"
        self.issues.mkdir()

    def write_issue(self, name: str, text: str) -> Path:
        path = self.issues / name
        path.write_text(text, encoding="utf-8")
        return path

    def copy_real_issues(self) -> list[Path]:
        copied = []
        for src in sorted(REAL_ISSUES.glob("*.md")):
            dst = self.issues / src.name
            shutil.copyfile(src, dst)
            copied.append(dst)
        return copied

    def build(self):
        return site.build_site(self.issues, self.docs)

    def read(self, rel: str) -> str:
        return (self.docs / rel).read_text(encoding="utf-8")


class TestPageForEveryIssue(SiteTestCase):
    """ACCEPTANCE: every file in issues/ makes one page and one index entry."""

    def test_real_issues_each_get_a_page_and_an_index_entry(self) -> None:
        sources = self.copy_real_issues()
        self.assertGreaterEqual(len(sources), 2, "the repo should have real issues")

        report = self.build()
        self.assertEqual(report.issues, len(sources))

        pages = sorted(p.name for p in (self.docs / "issues").glob("*.html"))
        self.assertEqual(pages, sorted(f"{p.stem}.html" for p in sources))

        index = self.read("index.html")
        for src in sources:
            href = f'href="issues/{src.stem}.html"'
            self.assertEqual(
                index.count(href), 1,
                f"index.html should link {src.name} exactly once",
            )

    def test_a_new_issue_appears_without_touching_the_generator(self) -> None:
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()
        self.assertTrue((self.docs / "issues" / "2026-01-02.html").is_file())
        self.assertIn('href="issues/2026-01-02.html"', self.read("index.html"))

    def test_a_removed_issue_loses_its_page(self) -> None:
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()
        page = self.docs / "issues" / "2026-01-02.html"
        self.assertTrue(page.is_file())

        (self.issues / "2026-01-02.md").unlink()
        report = self.build()
        self.assertFalse(
            page.exists(),
            "a page whose issue is gone would keep being served by Pages",
        )
        self.assertIn("issues/2026-01-02.html", report.removed)

    def test_an_undated_issue_filename_is_refused(self) -> None:
        self.write_issue("draft.md", HOSTILE_ISSUE)
        with self.assertRaises(ValueError):
            self.build()


class TestNoMarkdownLeaks(SiteTestCase):
    """ACCEPTANCE: no output page contains raw markdown markers."""

    def _pages(self) -> list[tuple[str, str]]:
        out = [("index.html", self.read("index.html"))]
        for page in sorted((self.docs / "issues").glob("*.html")):
            out.append((f"issues/{page.name}", page.read_text(encoding="utf-8")))
        return out

    def test_real_issues_render_without_markdown_markers(self) -> None:
        self.copy_real_issues()
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()

        for name, text in self._pages():
            body = text.split("<body>", 1)[1]
            self.assertNotIn("**", body, f"{name}: bold markers leaked")
            self.assertNotIn("](", body, f"{name}: a markdown link leaked")
            for n, line in enumerate(body.splitlines(), start=1):
                self.assertFalse(
                    line.lstrip().startswith("#"),
                    f"{name}:{n}: a markdown heading leaked: {line!r}",
                )
                self.assertFalse(
                    line.lstrip().startswith(">") and not line.lstrip().startswith("&gt;"),
                    f"{name}:{n}: a blockquote marker leaked: {line!r}",
                )

    def test_the_constructs_the_issues_use_become_elements(self) -> None:
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()
        page = self.read("issues/2026-01-02.html")

        self.assertIn("<h2", page)                       # the issue title
        self.assertIn("<h3", page)                       # the item heading
        self.assertIn("<strong>What happened:</strong>", page)
        self.assertIn("<code>CRITICAL</code>", page)     # a tag
        self.assertIn(
            '<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-00001">', page
        )
        self.assertIn("<blockquote>", page)              # the KEV callout
        self.assertIn("<em>", page)                      # the italic footer

    def test_the_hard_broken_tag_line_stays_with_its_heading(self) -> None:
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()
        page = self.read("issues/2026-01-02.html")
        self.assertRegex(
            page,
            r"</h3>\s*<p class=\"tags\">",
            "the tag line under an item heading must be its own tag paragraph, "
            "not a continuation of the link text",
        )


class TestEscaping(SiteTestCase):
    """ACCEPTANCE: angle brackets in a CVE description are escaped."""

    def setUp(self) -> None:
        super().setUp()
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()
        self.page = self.read("issues/2026-01-02.html")

    def test_a_script_tag_in_the_description_is_not_an_element(self) -> None:
        self.assertNotIn("<script", self.page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", self.page)

    def test_an_event_handler_payload_is_not_an_element(self) -> None:
        # `onerror=` does appear on the page -- as text inside the escaped
        # payload. What must not exist is a tag carrying it, so assert on the
        # escaped form and on the absence of any real <img>.
        self.assertNotIn("<img", self.page)
        self.assertIn("&lt;img src=x onerror=&quot;alert(2)&quot;&gt;", self.page)
        self.assertNotRegex(
            self.page, r"<[a-zA-Z][^>]*onerror",
            "an event handler ended up inside a real tag",
        )

    def test_bare_angle_brackets_and_ampersands_survive_as_text(self) -> None:
        self.assertIn("a &amp; b", self.page)
        self.assertIn("value &lt; 5", self.page)
        self.assertIn("value &gt; 9", self.page)
        self.assertIn("&lt;Example Suite&gt; 1.0 &amp; earlier", self.page)

    def test_a_payload_before_an_inline_construct_is_escaped(self) -> None:
        # The text run BEFORE the first match on a line is a separate code path
        # from the trailing run. A generator that escapes only one of them
        # passes every other test here.
        self.assertNotIn("<svg", self.page)
        self.assertIn("&lt;svg onload=alert(3)&gt;", self.page)

    def test_a_payload_inside_a_code_span_is_escaped(self) -> None:
        self.assertNotIn("<b>", self.page)
        self.assertIn("<code>&lt;b&gt;9.8&lt;/b&gt;</code>", self.page)

    def test_the_page_has_no_unescaped_markup_from_the_description(self) -> None:
        # The set of tags the generator is allowed to emit. Anything else in the
        # body came from the issue text and is a hole.
        allowed = {
            "html", "head", "meta", "title", "link", "body", "header", "nav",
            "h1", "h2", "h3", "h4", "p", "a", "code", "strong", "em",
            "blockquote", "article", "footer", "br", "ul", "li", "span",
            "!doctype",
        }
        found = {
            tag.lower().lstrip("/")
            for tag in re.findall(r"<\s*(/?[a-zA-Z!][^\s>/]*)", self.page)
        }
        self.assertTrue(
            found <= allowed,
            f"unexpected tags on the page: {sorted(found - allowed)}",
        )


class TestFeed(SiteTestCase):
    """ACCEPTANCE: feed.xml parses and holds one item per issue."""

    def test_feed_parses_with_elementtree_and_matches_the_issues(self) -> None:
        sources = self.copy_real_issues()
        self.build()

        root = ET.fromstring(self.read("feed.xml"))
        items = root.findall("./channel/item")
        self.assertEqual(len(items), len(sources))

        for item in items:
            for tag in ("title", "link", "pubDate"):
                text = item.findtext(tag)
                self.assertIsNotNone(text, f"feed item is missing <{tag}>")
                self.assertTrue((text or "").strip(), f"<{tag}> is empty")

        links = [item.findtext("link") for item in items]
        self.assertEqual(len(set(links)), len(links), "duplicate feed links")
        for src in sources:
            self.assertIn(
                f"{site.SITE_BASE_URL}/issues/{src.stem}.html", links,
                f"{src.name} has no feed item",
            )

    def test_pubdate_comes_from_the_issue_date_not_the_clock(self) -> None:
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()
        root = ET.fromstring(self.read("feed.xml"))
        self.assertEqual(
            root.findtext("./channel/item/pubDate"),
            "Fri, 02 Jan 2026 07:00:00 +0000",
        )

    def test_feed_is_newest_first(self) -> None:
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.write_issue("2026-01-03.md", HOSTILE_ISSUE.replace("2026-01-02", "2026-01-03"))
        self.build()
        root = ET.fromstring(self.read("feed.xml"))
        links = [item.findtext("link") for item in root.findall("./channel/item")]
        self.assertEqual(links[0], f"{site.SITE_BASE_URL}/issues/2026-01-03.html")


class TestDeterminism(SiteTestCase):
    """ACCEPTANCE: a second run with no new issue changes no byte."""

    def _snapshot(self) -> dict[str, bytes]:
        return {
            p.relative_to(self.docs).as_posix(): p.read_bytes()
            for p in sorted(self.docs.rglob("*")) if p.is_file()
        }

    def test_two_builds_produce_identical_bytes(self) -> None:
        self.copy_real_issues()
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()
        first = self._snapshot()

        second_report = self.build()
        second = self._snapshot()

        self.assertEqual(first.keys(), second.keys())
        for rel in first:
            self.assertEqual(first[rel], second[rel], f"{rel} changed on rebuild")
        self.assertEqual(
            second_report.written, [],
            "a rebuild with no new issue must not rewrite any file",
        )
        self.assertEqual(len(second_report.unchanged), len(first))

    def test_check_mode_reports_current_then_stale(self) -> None:
        self.copy_real_issues()
        self.build()
        self.assertEqual(build_site.check(self.issues, self.docs), [])

        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        stale = build_site.check(self.issues, self.docs)
        self.assertTrue(any("2026-01-02.html" in line for line in stale), stale)
        self.assertTrue(any("index.html" in line for line in stale), stale)

    def test_check_mode_writes_nothing(self) -> None:
        self.copy_real_issues()
        self.build()
        before = self._snapshot()
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        build_site.check(self.issues, self.docs)
        self.assertEqual(before, self._snapshot())

    def test_the_committed_docs_directory_is_current(self) -> None:
        # The site is committed, not built on a server, so a stale docs/ is a
        # site that silently disagrees with the issues in the same commit.
        docs = ROOT / "docs"
        if not docs.is_dir():
            self.skipTest("docs/ has not been built in this checkout")
        stale = build_site.check(REAL_ISSUES, docs)
        self.assertEqual(
            stale, [],
            "docs/ does not match issues/ -- run: python3 build_site.py",
        )


class TestPublicRepoHygiene(SiteTestCase):
    """The repo is going public: nothing on the pages may name an internal host."""

    def test_the_internal_llm_endpoint_is_redacted_on_the_page(self) -> None:
        self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()
        page = self.read("issues/2026-01-02.html")
        self.assertNotIn("localhost", page)
        self.assertNotIn(":8001", page)
        self.assertIn(site.REDACTED, page)

    def test_the_markdown_issue_is_left_alone(self) -> None:
        path = self.write_issue("2026-01-02.md", HOSTILE_ISSUE)
        self.build()
        self.assertEqual(path.read_text(encoding="utf-8"), HOSTILE_ISSUE)

    def test_private_hosts_are_recognised_and_public_ones_are_not(self) -> None:
        for url in (
            "http://localhost:8001/v1",
            "http://localhost:8000/v1",
            "http://127.0.0.1:8000/v1",
            "http://192.168.1.40:8080/",
        ):
            self.assertTrue(site.is_private_url(url), url)
        for url in (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-00001",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ):
            self.assertFalse(site.is_private_url(url), url)

    def test_a_link_to_an_internal_host_never_becomes_an_anchor(self) -> None:
        html_out = site.inline("see [the box](http://localhost:8001/v1) for logs")
        self.assertNotIn("<a", html_out)
        self.assertNotIn("localhost", html_out)
        self.assertIn("the box", html_out)

    def test_a_javascript_url_never_becomes_an_anchor(self) -> None:
        html_out = site.inline("[click](javascript:alert(1))")
        self.assertNotIn("<a", html_out)
        self.assertNotIn("javascript:", html_out)

    def test_the_feed_carries_no_internal_host(self) -> None:
        self.copy_real_issues()
        self.build()
        self.assertNotIn("localhost", self.read("feed.xml"))


class TestPagesPlumbing(SiteTestCase):
    """The files GitHub Pages itself needs, which no page test would catch."""

    def test_cname_and_nojekyll_are_written(self) -> None:
        self.copy_real_issues()
        self.build()
        self.assertEqual(self.read("CNAME").strip(), site.CUSTOM_DOMAIN)
        self.assertTrue((self.docs / ".nojekyll").is_file())

    def test_pages_reference_the_stylesheet_that_exists(self) -> None:
        self.copy_real_issues()
        self.build()
        self.assertTrue((self.docs / "style.css").is_file())
        self.assertIn('href="style.css"', self.read("index.html"))
        page = sorted((self.docs / "issues").glob("*.html"))[0]
        self.assertIn('href="../style.css"', page.read_text(encoding="utf-8"))

    def test_an_empty_issues_directory_still_produces_a_valid_site(self) -> None:
        report = self.build()
        self.assertEqual(report.issues, 0)
        index = self.read("index.html")
        self.assertIn("No issue has been published yet", index)
        ET.fromstring(self.read("feed.xml"))

    def test_rfc822_matches_the_weekday_of_the_date(self) -> None:
        self.assertEqual(site.rfc822(date(2026, 9, 22)), "Tue, 22 Sep 2026 07:00:00 +0000")
        self.assertEqual(site.rfc822(date(2026, 9, 21)), "Mon, 21 Sep 2026 07:00:00 +0000")


if __name__ == "__main__":
    unittest.main(verbosity=2)
