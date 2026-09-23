#!/usr/bin/env python3
"""Break the site generator on a throwaway copy and check tests/test_site.py goes red.

`tests/test_site.py` claims three things the published site depends on:
attacker text in a CVE description cannot become markup, no markdown marker
reaches a page, and a rebuild with no new issue changes no byte. Each of those
is easy to assert in a way that passes against a generator that does not
actually hold it -- the escaping check in particular passes trivially if the
crafted input never reaches the page at all.

So: copy the repo to a temp dir, apply each mutation, run the site tests, and
assert they FAIL. A surviving mutant means that criterion is asserted but not
protected.

    python3 tools/mutation_site_check.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (name, file, find, replace) -- each is a plausible-looking bug in the
# generator, not in the test.
MUTATIONS = [
    (
        "text is formatted before it is escaped (the classic XSS hole)",
        "src/site.py",
        '        out.append(html.escape(text[pos:match.start()]))',
        '        out.append(text[pos:match.start()])  # mutant: no escaping',
    ),
    (
        "the trailing text run is emitted raw",
        "src/site.py",
        '    out.append(html.escape(text[pos:]))',
        '    out.append(text[pos:])  # mutant: no escaping',
    ),
    (
        "code spans pass their contents through unescaped",
        "src/site.py",
        "            out.append(f\"<code>{html.escape(match.group('code'))}</code>\")",
        "            out.append(f\"<code>{match.group('code')}</code>\")",
    ),
    (
        "any URL is accepted as an href (javascript:, internal hosts)",
        "src/site.py",
        '    if not (low.startswith("http://") or low.startswith("https://")):\n'
        '        return None',
        '    if False:\n'
        '        return None',
    ),
    (
        "the internal LLM endpoint is published verbatim",
        "src/site.py",
        "    return _URL.sub(lambda m: REDACTED if is_private_url(m.group(0)) else m.group(0), text)",
        "    return text  # mutant: no redaction",
    ),
    (
        "bold and links are left as markdown in a paragraph",
        "src/site.py",
        "            out.append(f\"<strong>{inline(match.group('strong'))}</strong>\")",
        "            out.append(f\"**{match.group('strong')}**\")",
    ),
    (
        "headings stay markdown inside the paragraph text",
        "src/site.py",
        '        if first.startswith("#"):',
        '        if False:',
    ),
    (
        "the feed date comes from the build clock, not the issue",
        "src/site.py",
        '    return (\n'
        '        f"{_RFC822_DAY[day.weekday()]}, {day.day:02d} "\n'
        '        f"{_RFC822_MONTH[day.month - 1]} {day.year} 07:00:00 +0000"\n'
        '    )',
        '    now = datetime.now(timezone.utc)\n'
        '    return (\n'
        '        f"{_RFC822_DAY[now.weekday()]}, {now.day:02d} "\n'
        '        f"{_RFC822_MONTH[now.month - 1]} {now.year} {now:%H:%M:%S} +0000"\n'
        '    )',
    ),
    (
        "a page whose issue is gone is left on the site",
        "src/site.py",
        "        if stale.name not in expected:\n"
        "            stale.unlink()",
        "        if False:\n"
        "            stale.unlink()",
    ),
    (
        "the index links only the newest issue",
        "src/site.py",
        "        for issue in issues:\n"
        "            href = f\"{ISSUE_SUBDIR}/{issue.page_name}\"",
        "        for issue in issues[:1]:  # mutant: index only the newest\n"
        "            href = f\"{ISSUE_SUBDIR}/{issue.page_name}\"",
    ),
]

TEST_ARGV = ["-m", "unittest", "tests.test_site"]


def run_tests(cwd: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, *TEST_ARGV],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, "PYTHONPATH": str(cwd)},
    )
    return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")


def main() -> int:
    survivors: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        # `issues/` is copied on purpose, unlike the other mutation tools here:
        # the "one page per issue" test reads the real issues.
        baseline = Path(tmp) / "baseline"
        shutil.copytree(
            ROOT, baseline,
            ignore=shutil.ignore_patterns(".git", ".worktrees", "__pycache__", "docs"),
        )
        ok, output = run_tests(baseline)
        if not ok:
            print("baseline is already red -- fix the tests before mutating")
            print(output[-2000:])
            return 1
        print("baseline: PASS")

        for index, (name, filename, find, replace) in enumerate(MUTATIONS, start=1):
            work = Path(tmp) / f"mutant{index}"
            shutil.copytree(baseline, work)
            target = work / filename
            text = target.read_text(encoding="utf-8")
            if find not in text:
                print(f"  {index}. {name}: MUTATION DID NOT APPLY (pattern moved)")
                survivors.append(f"{name} (pattern not found)")
                continue
            target.write_text(text.replace(find, replace, 1), encoding="utf-8")

            passed, _output = run_tests(work)
            verdict = "SURVIVED" if passed else "caught"
            print(f"  {index}. {name}: {verdict}")
            if passed:
                survivors.append(name)

    print()
    if survivors:
        print(f"FAILED: {len(survivors)} mutant(s) survived -- the site tests are decorative")
        for name in survivors:
            print(f"  - {name}")
        return 1
    print(f"PASSED: all {len(MUTATIONS)} mutants were caught")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
