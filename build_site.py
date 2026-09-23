#!/usr/bin/env python3
"""Publish the issues in ``issues/`` as the static site in ``docs/``.

    python3 build_site.py              # build
    python3 build_site.py --check      # build nothing, fail if docs/ is stale

No arguments needed. It reads only ``issues/*.md`` and writes only inside
``docs/``, which is the directory GitHub Pages serves from ``master``. There is
no Actions workflow: the site is generated on this Mac by the same daily run
that writes the issue (see ``deploy/`` ) and committed as ordinary files.

``--check`` renders in memory and compares against what is on disk. It is what
a test or a pre-commit hook should call: it never writes, and it exits non-zero
with the list of files that would change.

Exit codes:

    0  the site is built (or, with --check, already current)
    2  no issues/ directory, or an issue filename that is not YYYY-MM-DD.md
    3  --check found docs/ out of date
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.site import (  # noqa: E402
    ISSUE_SUBDIR,
    build_site,
    load_issues,
    render_feed,
    render_index,
    render_issue_page,
    STYLESHEET,
    CUSTOM_DOMAIN,
)

ISSUES_DIR = ROOT / "issues"
DOCS_DIR = ROOT / "docs"


def _expected(issues_dir: Path) -> dict[str, str]:
    """Every output file and its content, without touching the disk."""
    issues = load_issues(issues_dir)
    files = {
        "index.html": render_index(issues),
        "feed.xml": render_feed(issues),
        "style.css": STYLESHEET,
        ".nojekyll": "",
        "CNAME": CUSTOM_DOMAIN + "\n",
    }
    for issue in issues:
        files[f"{ISSUE_SUBDIR}/{issue.page_name}"] = render_issue_page(issue)
    return files


def check(issues_dir: Path, docs_dir: Path) -> list[str]:
    """Paths (relative to `docs_dir`) that a build would create, change or delete."""
    stale: list[str] = []
    expected = _expected(issues_dir)
    for rel, text in sorted(expected.items()):
        path = docs_dir / rel
        if not path.exists():
            stale.append(f"missing: {rel}")
        elif path.read_bytes() != text.encode("utf-8"):
            stale.append(f"out of date: {rel}")
    pages = docs_dir / ISSUE_SUBDIR
    if pages.is_dir():
        for page in sorted(pages.glob("*.html")):
            rel = f"{ISSUE_SUBDIR}/{page.name}"
            if rel not in expected:
                stale.append(f"orphan: {rel}")
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Publish the issues in issues/ as the static site in docs/."
    )
    parser.add_argument("--issues-dir", default=str(ISSUES_DIR))
    parser.add_argument("--docs-dir", default=str(DOCS_DIR))
    parser.add_argument(
        "--check", action="store_true",
        help="do not write; exit 3 if docs/ does not match issues/",
    )
    args = parser.parse_args(argv)

    issues_dir = Path(args.issues_dir)
    docs_dir = Path(args.docs_dir)

    try:
        if args.check:
            stale = check(issues_dir, docs_dir)
            if stale:
                print("docs/ is out of date with issues/:")
                for line in stale:
                    print(f"  {line}")
                print("run: python3 build_site.py")
                return 3
            print("docs/ is current")
            return 0

        report = build_site(issues_dir, docs_dir)
    except FileNotFoundError as exc:
        print(f"build_site: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"build_site: {exc}", file=sys.stderr)
        return 2

    print(f"build_site: {report.summary()}")
    for rel in report.written:
        print(f"  wrote   {rel}")
    for rel in report.removed:
        print(f"  removed {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
