"""Turn the markdown issues in ``issues/`` into a static site under ``docs/``.

Delivery stage. Nothing here fetches, ranks or phrases anything: the issues are
already written and are treated as the source of truth. This module reads them,
renders HTML, an index and an RSS feed, and writes the tree GitHub Pages
serves.

What it guarantees, because the acceptance criteria are about output and not
about intent:

  * **One page per issue, one index entry per issue.** The page set is derived
    from ``issues/*.md`` only, and a page in ``docs/issues/`` with no issue
    behind it is deleted -- otherwise a renamed issue leaves a ghost the index
    no longer links but the web still serves.

  * **No markdown leaks.** Every block and every inline construct the issues
    actually use is converted: headings, the hard-broken tag line under a
    heading, blockquote callouts, ``**bold**`` field labels, ``_italic_``
    footer lines, ``` `code` ``` tags and ``[text](url)`` links. Anything the
    converter does not recognise still ends up escaped inside a paragraph, so
    an unknown construct shows up as visible text in a test rather than as
    working HTML.

  * **Escaping before formatting.** Text is HTML-escaped first and markup is
    emitted afterwards, so a CVE description containing ``<script>`` or an
    ``<img>`` tag -- NVD descriptions quote attacker input freely -- cannot
    become an element on the page. `tests/test_site.py` proves it on a crafted
    issue.

  * **Byte-identical rebuilds.** No clock, no counter and no dictionary order
    reaches the output: the feed's dates come from the issue dates, not from
    ``now()``. Re-running the generator on an unchanged ``issues/`` produces
    the same bytes, which is what makes a daily launchd run safe to commit
    from.

  * **Internal endpoints stay internal.** The issue footer records which model
    wrote the summaries, including the URL of the box on the home network that
    served it. The repo is going public. Any URL pointing at a non-public host
    (``*.local``, ``localhost``, a bare IP, or a port on either) is redacted in
    the published HTML and feed. The markdown in ``issues/`` is left untouched.

The output is deliberately one stylesheet and static HTML: no JavaScript, no
build tool, no Actions workflow.
"""

from __future__ import annotations

import html
import re
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

SITE_TITLE = "CyberWatch Newsletter"
SITE_DESCRIPTION = (
    "Five security items a day: vulnerabilities actually being exploited "
    "first, from the CISA KEV catalogue, then high-severity CVEs in widely "
    "deployed software."
)
SITE_BASE_URL = "https://cyberwatch.asutera.dev"
CUSTOM_DOMAIN = "cyberwatch.asutera.dev"

ISSUE_SUBDIR = "issues"
REDACTED = "[internal endpoint redacted]"

_DATE_NAME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")

# A host we must not publish: the loopback, anything on the .local mDNS
# namespace, or a bare IPv4 literal. `localhost:8001` is in every issue
# footer this repo has produced so far.
_PRIVATE_HOST = re.compile(
    r"^(localhost|127(?:\.\d{1,3}){3}|\d{1,3}(?:\.\d{1,3}){3}|[^/]*\.local)$",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s<>\"')\]]+")


# --------------------------------------------------------------------------- #
# redaction
# --------------------------------------------------------------------------- #

def _host_of(url: str) -> str:
    rest = url.split("://", 1)[1] if "://" in url else url
    authority = rest.split("/", 1)[0].split("?", 1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    return authority.rsplit(":", 1)[0] if ":" in authority else authority


def is_private_url(url: str) -> bool:
    """True when `url` points at a host that must not appear on a public page."""
    return bool(_PRIVATE_HOST.match(_host_of(url)))


def redact(text: str) -> str:
    """Replace every URL pointing at a non-public host with a marker."""
    return _URL.sub(lambda m: REDACTED if is_private_url(m.group(0)) else m.group(0), text)


# --------------------------------------------------------------------------- #
# inline markdown
# --------------------------------------------------------------------------- #

_INLINE = re.compile(
    r"`(?P<code>[^`]+)`"
    r"|\[(?P<ltext>[^\]\n]+)\]\((?P<lhref>[^)\s]+)\)"
    r"|\*\*(?P<strong>[^\n]+?)\*\*"
    r"|(?<![0-9A-Za-z_])_(?P<em>[^_\n]+)_(?![0-9A-Za-z_])"
)


def _safe_href(url: str) -> str | None:
    """An href we are willing to emit, or None. Only http(s), only public."""
    low = url.strip().lower()
    if not (low.startswith("http://") or low.startswith("https://")):
        return None
    if is_private_url(url):
        return None
    return html.escape(url.strip(), quote=True)


def inline(text: str) -> str:
    """Convert one line of inline markdown to HTML.

    Escaping happens on every text run before any tag is emitted, so no part of
    the source can contribute markup. An unrecognised construct is left as
    escaped text on purpose -- a leaked ``**`` is a visible, testable defect,
    while silently dropping it is not.
    """
    out: list[str] = []
    pos = 0
    for match in _INLINE.finditer(text):
        out.append(html.escape(text[pos:match.start()]))
        pos = match.end()
        if match.group("code") is not None:
            out.append(f"<code>{html.escape(match.group('code'))}</code>")
        elif match.group("ltext") is not None:
            label = inline(match.group("ltext"))
            href = _safe_href(match.group("lhref"))
            if href is None:
                # Not a link we will publish: keep the words, drop the target.
                out.append(label)
            else:
                out.append(f'<a href="{href}">{label}</a>')
        elif match.group("strong") is not None:
            out.append(f"<strong>{inline(match.group('strong'))}</strong>")
        else:
            out.append(f"<em>{inline(match.group('em'))}</em>")
    out.append(html.escape(text[pos:]))
    return "".join(out)


# --------------------------------------------------------------------------- #
# block markdown
# --------------------------------------------------------------------------- #

def _slug(text: str) -> str:
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_text.lower()).strip("-")
    return slug or "section"


def _join(lines: Sequence[str]) -> str:
    """Join a paragraph's lines, honouring markdown's two-space hard break."""
    parts: list[str] = []
    for n, line in enumerate(lines):
        if n:
            parts.append("<br>\n" if lines[n - 1].endswith("  ") else " ")
        parts.append(inline(line.rstrip()))
    return "".join(parts)


def _groups(lines: Iterable[str]) -> list[list[str]]:
    """Split lines into blank-line-separated groups, dropping blanks."""
    groups: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip():
            current.append(line)
        elif current:
            groups.append(current)
            current = []
    if current:
        groups.append(current)
    return groups


def render_blocks(lines: Sequence[str], *, heading_shift: int = 0) -> str:
    """Render a run of markdown lines as HTML blocks.

    `heading_shift` pushes ``#``/``##`` down a level; the per-issue page already
    owns its ``<h1>``, so an issue's own title is rendered as an ``<h2>`` there.
    """
    out: list[str] = []
    for group in _groups(lines):
        first = group[0].strip()
        rest = group[1:]
        if first.startswith("#"):
            hashes = len(first) - len(first.lstrip("#"))
            level = min(6, max(1, hashes + heading_shift))
            body = first[hashes:].strip()
            ident = _slug(re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", body))
            out.append(f'<h{level} id="{html.escape(ident, quote=True)}">'
                       f"{inline(body)}</h{level}>")
            if rest:
                # The tag line under a heading: `KNOWN EXPLOITED` `CRITICAL`...
                # It is a hard-broken continuation of the heading in markdown,
                # not a paragraph of its own.
                out.append(f'<p class="tags">{_join(rest)}</p>')
        elif first.startswith(">"):
            quoted = [re.sub(r"^\s*>\s?", "", line) for line in group]
            out.append(f"<blockquote><p>{_join(quoted)}</p></blockquote>")
        else:
            out.append(f"<p>{_join(group)}</p>")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# issues
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Issue:
    """One markdown issue, parsed far enough to render and to index."""

    date: date
    slug: str
    title: str
    lead: str
    sections: tuple[tuple[str, ...], ...]
    cve_ids: tuple[str, ...]

    @property
    def page_name(self) -> str:
        return f"{self.slug}.html"

    @property
    def url(self) -> str:
        return f"{SITE_BASE_URL}/{ISSUE_SUBDIR}/{self.page_name}"


_CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def parse_issue(path: Path) -> Issue:
    """Read one ``issues/YYYY-MM-DD.md`` file.

    The date comes from the filename, never from the document body: the
    filename is what ``run.py`` controls and what the page URL must match.
    """
    stem = path.stem
    match = _DATE_NAME.match(stem)
    if not match:
        raise ValueError(
            f"{path.name}: issue filenames must be YYYY-MM-DD.md; this one is not, "
            "so the page URL and the feed date cannot be derived"
        )
    issue_date = date(int(match.group(1)), int(match.group(2)), int(match.group(3)))

    raw = redact(path.read_text(encoding="utf-8"))
    lines = raw.splitlines()

    # `---` on a line of its own separates the issue's sections. It is never a
    # setext underline here: render.py only ever emits it as a rule between the
    # header, each item and the footer.
    sections: list[list[str]] = [[]]
    for line in lines:
        if line.strip() == "---":
            sections.append([])
        else:
            sections[-1].append(line)

    title = ""
    lead = ""
    for line in sections[0]:
        stripped = line.strip()
        if not title and stripped.startswith("# "):
            title = stripped[2:].strip()
        elif title and stripped and not lead:
            lead = re.sub(r"[`*_]", "", stripped)

    kept = tuple(tuple(s) for s in sections if any(line.strip() for line in s))
    ids: list[str] = []
    for found in _CVE.findall(raw):
        if found not in ids:
            ids.append(found)

    return Issue(
        date=issue_date,
        slug=stem,
        title=title or f"{SITE_TITLE} -- {issue_date:%Y-%m-%d}",
        lead=lead,
        sections=kept,
        cve_ids=tuple(ids),
    )


def load_issues(issues_dir: Path) -> list[Issue]:
    """Every ``*.md`` in `issues_dir`, newest first."""
    paths = sorted(p for p in issues_dir.glob("*.md") if p.is_file())
    issues = [parse_issue(p) for p in paths]
    return sorted(issues, key=lambda i: (i.date, i.slug), reverse=True)


# --------------------------------------------------------------------------- #
# pages
# --------------------------------------------------------------------------- #

STYLESHEET = """\
:root {
  --ink: #16191d;
  --muted: #5a626d;
  --rule: #d9dde3;
  --paper: #fbfbf9;
  --accent: #8c1d18;
}
* { box-sizing: border-box; }
body {
  margin: 0 auto;
  padding: 2.5rem 1.25rem 4rem;
  max-width: 44rem;
  background: var(--paper);
  color: var(--ink);
  font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
a { color: var(--accent); }
header.masthead { border-bottom: 2px solid var(--ink); padding-bottom: 0.75rem; margin-bottom: 2rem; }
header.masthead h1 { margin: 0; font-size: 1.6rem; letter-spacing: 0.01em; }
header.masthead p { margin: 0.4rem 0 0; color: var(--muted); font-size: 0.95rem; }
nav.crumbs { margin-bottom: 1.5rem; font-size: 0.9rem; }
h2 { margin-top: 2.25rem; font-size: 1.2rem; line-height: 1.35; }
h3 { margin-top: 2rem; font-size: 1.05rem; }
p { margin: 0.7rem 0; }
code {
  background: #eceef1;
  border: 1px solid var(--rule);
  border-radius: 3px;
  padding: 0.05rem 0.3rem;
  font-size: 0.82rem;
  white-space: nowrap;
}
p.tags code { text-transform: uppercase; letter-spacing: 0.03em; }
blockquote {
  margin: 1rem 0;
  padding: 0.6rem 0.9rem;
  border-left: 4px solid var(--accent);
  background: #f4eceb;
}
blockquote p { margin: 0; }
article { border-top: 1px solid var(--rule); padding-top: 0.5rem; }
article:first-of-type { border-top: 0; }
footer.colophon {
  margin-top: 3rem;
  border-top: 1px solid var(--rule);
  padding-top: 0.9rem;
  color: var(--muted);
  font-size: 0.85rem;
}
ul.issues { list-style: none; padding: 0; }
ul.issues li { border-top: 1px solid var(--rule); padding: 0.9rem 0; }
ul.issues li:first-child { border-top: 0; }
ul.issues .when { display: block; color: var(--muted); font-size: 0.8rem; }
ul.issues .cves { color: var(--muted); font-size: 0.85rem; }
"""


def _document(title: str, body: str, *, css_href: str, feed_href: str) -> str:
    return "\n".join([
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{html.escape(title)}</title>",
        f'<meta name="description" content="{html.escape(SITE_DESCRIPTION, quote=True)}">',
        f'<link rel="stylesheet" href="{css_href}">',
        f'<link rel="alternate" type="application/rss+xml" '
        f'title="{html.escape(SITE_TITLE, quote=True)}" href="{feed_href}">',
        "</head>",
        "<body>",
        body,
        "</body>",
        "</html>",
        "",
    ])


def render_issue_page(issue: Issue) -> str:
    """The HTML page for one issue."""
    parts = [
        '<header class="masthead">',
        f"<h1>{html.escape(SITE_TITLE)}</h1>",
        f"<p>{html.escape(SITE_DESCRIPTION)}</p>",
        "</header>",
        '<nav class="crumbs"><a href="../index.html">&#8592; All issues</a></nav>',
    ]
    for n, section in enumerate(issue.sections):
        rendered = render_blocks(section, heading_shift=1)
        if not rendered:
            continue
        if n == 0 or n == len(issue.sections) - 1:
            parts.append(rendered)
        else:
            parts.append(f"<article>\n{rendered}\n</article>")
    parts.append(
        '<footer class="colophon"><p>'
        f'<a href="../index.html">All issues</a> &#183; '
        f'<a href="../feed.xml">RSS feed</a>'
        "</p></footer>"
    )
    return _document(
        f"{issue.title}",
        "\n".join(parts),
        css_href="../style.css",
        feed_href="../feed.xml",
    )


def render_index(issues: Sequence[Issue]) -> str:
    """The index page: one entry per issue, newest first."""
    parts = [
        '<header class="masthead">',
        f"<h1>{html.escape(SITE_TITLE)}</h1>",
        f"<p>{html.escape(SITE_DESCRIPTION)}</p>",
        "</header>",
    ]
    if not issues:
        parts.append(
            "<p>No issue has been published yet. This page is generated from the "
            "repository's <code>issues/</code> directory and there is nothing in "
            "it.</p>"
        )
    else:
        parts.append(f"<h2 id=\"issues\">Issues ({len(issues)})</h2>")
        parts.append('<ul class="issues">')
        for issue in issues:
            href = f"{ISSUE_SUBDIR}/{issue.page_name}"
            entry = [
                "<li>",
                f'<a href="{html.escape(href, quote=True)}">{html.escape(issue.title)}</a>',
                f'<span class="when">{issue.date:%A, %d %B %Y}</span>',
            ]
            if issue.lead:
                entry.append(f"<p>{html.escape(issue.lead)}</p>")
            if issue.cve_ids:
                entry.append(
                    '<p class="cves">' + html.escape(", ".join(issue.cve_ids)) + "</p>"
                )
            entry.append("</li>")
            parts.append("\n".join(entry))
        parts.append("</ul>")
    parts.append(
        '<footer class="colophon"><p>'
        'Generated from markdown in the repository by <code>build_site.py</code>. '
        '<a href="feed.xml">RSS feed</a>.'
        "</p></footer>"
    )
    return _document(SITE_TITLE, "\n".join(parts), css_href="style.css", feed_href="feed.xml")


# --------------------------------------------------------------------------- #
# feed
# --------------------------------------------------------------------------- #

_RFC822_DAY = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_RFC822_MONTH = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def rfc822(day: date) -> str:
    """RFC 822 date for a published issue, fixed at 07:00 UTC.

    A constant time of day rather than the build clock: the feed has to be
    byte-identical across rebuilds of the same issue set.
    """
    return (
        f"{_RFC822_DAY[day.weekday()]}, {day.day:02d} "
        f"{_RFC822_MONTH[day.month - 1]} {day.year} 07:00:00 +0000"
    )


def render_feed(issues: Sequence[Issue]) -> str:
    """RSS 2.0. Built with ElementTree, so escaping is the parser's problem."""
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = SITE_TITLE
    ET.SubElement(channel, "link").text = f"{SITE_BASE_URL}/"
    ET.SubElement(channel, "description").text = SITE_DESCRIPTION
    ET.SubElement(channel, "language").text = "en"
    if issues:
        ET.SubElement(channel, "lastBuildDate").text = rfc822(issues[0].date)

    for issue in issues:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = issue.title
        ET.SubElement(item, "link").text = issue.url
        ET.SubElement(item, "guid", {"isPermaLink": "true"}).text = issue.url
        ET.SubElement(item, "pubDate").text = rfc822(issue.date)
        summary = issue.lead or SITE_DESCRIPTION
        if issue.cve_ids:
            summary = f"{summary} Items: {', '.join(issue.cve_ids)}."
        ET.SubElement(item, "description").text = summary

    ET.indent(rss, space="  ")
    body = ET.tostring(rss, encoding="unicode")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + body + "\n"


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #

@dataclass
class BuildReport:
    issues: int = 0
    written: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.issues} issue(s): {len(self.written)} file(s) written, "
            f"{len(self.unchanged)} unchanged, {len(self.removed)} removed"
        )


def _write(path: Path, text: str, report: BuildReport, docs_dir: Path) -> None:
    """Write `text` only when it differs, and record which happened.

    Skipping an identical write is what keeps mtimes -- and therefore a daily
    `git status` -- quiet on a day with no new issue. The byte-identity
    guarantee does not depend on it: the rendered text is the same either way.
    """
    rel = path.relative_to(docs_dir).as_posix()
    data = text.encode("utf-8")
    if path.exists() and path.read_bytes() == data:
        report.unchanged.append(rel)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    report.written.append(rel)


def build_site(issues_dir: Path | str, docs_dir: Path | str) -> BuildReport:
    """Render every issue into `docs_dir`. Returns what changed."""
    issues_dir = Path(issues_dir)
    docs_dir = Path(docs_dir)
    if not issues_dir.is_dir():
        raise FileNotFoundError(f"no issues directory at {issues_dir}")

    issues = load_issues(issues_dir)
    report = BuildReport(issues=len(issues))
    pages_dir = docs_dir / ISSUE_SUBDIR
    pages_dir.mkdir(parents=True, exist_ok=True)

    for issue in issues:
        _write(pages_dir / issue.page_name, render_issue_page(issue), report, docs_dir)

    _write(docs_dir / "index.html", render_index(issues), report, docs_dir)
    _write(docs_dir / "feed.xml", render_feed(issues), report, docs_dir)
    _write(docs_dir / "style.css", STYLESHEET, report, docs_dir)
    # Pages runs Jekyll over docs/ unless told not to; nothing here needs it.
    _write(docs_dir / ".nojekyll", "", report, docs_dir)
    _write(docs_dir / "CNAME", CUSTOM_DOMAIN + "\n", report, docs_dir)

    # A page whose issue is gone stays served forever otherwise.
    expected = {issue.page_name for issue in issues}
    for stale in sorted(pages_dir.glob("*.html")):
        if stale.name not in expected:
            stale.unlink()
            report.removed.append(stale.relative_to(docs_dir).as_posix())

    return report
