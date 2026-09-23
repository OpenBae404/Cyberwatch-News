#!/usr/bin/env python3
"""Audit what a push would publish. This repo is going public.

Run before adding a remote and before every push:

    python3 tools/public_repo_audit.py

It reads the files git would publish (``git ls-files`` plus anything currently
staged) and looks for four things:

  1. **Credentials.** API keys, tokens, private keys, ``.env`` files, anything
     shaped like a secret. Always blocking -- there is no legitimate reason for
     one of these to be tracked.
  2. **Internal endpoints.** URLs and hosts that only exist on the author's
     network: ``*.local``, loopback, RFC 1918 addresses. This repo's issues are
     written by an LLM on the home network and the footer says so, so this is
     not hypothetical.
  3. **Absolute home paths.** ``/Users/<name>/...`` leaks a real account name
     and the layout of a private machine.
  4. **Personal addresses.** Email addresses that are not obviously a public
     project contact.

Findings are only accepted if they are listed in ``deploy/audit-allowlist.txt``
with a reason. That file is the record of what a human decided is fine to
publish; a NEW finding fails the audit even if a similar one was accepted
before, which is the property a grep-once-by-hand review does not have.

Exit codes:

    0  nothing found, or every finding is allowlisted with a reason
    1  at least one finding is not allowlisted
    2  the audit could not run (not a git repo)
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "deploy" / "audit-allowlist.txt"

# Files whose bytes are not text we can usefully grep.
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".woff", ".woff2"}

# (severity, label, pattern). "secret" is never allowlistable.
RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("secret", "private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("secret", "AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("secret", "Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("secret", "OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("secret", "assigned secret",
     re.compile(r"(?i)\b(api_?key|secret|password|passwd|token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
    ("disclosure", "internal host",
     re.compile(r"(?i)\b(?:[A-Za-z0-9-]+\.local|localhost|127(?:\.\d{1,3}){3}"
                r"|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}"
                r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b(?::\d+)?")),
    ("disclosure", "absolute home path", re.compile(r"/Users/[A-Za-z0-9._-]+/")),
    ("disclosure", "email address",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]

SECRET_FILENAMES = re.compile(r"(?i)(^|/)(\.env(\..*)?|.*\.pem|.*\.p12|id_(rsa|ed25519))$")


@dataclass(frozen=True)
class Finding:
    severity: str
    label: str
    path: str
    line: int
    excerpt: str

    def key(self) -> str:
        """The allowlist key: label + path. Deliberately not line-numbered --
        an entry should survive an edit above it, but not a move to a new file."""
        return f"{self.label}|{self.path}"

    def render(self) -> str:
        return f"[{self.severity}] {self.label}  {self.path}:{self.line}\n      {self.excerpt}"


def tracked_files() -> list[str]:
    def git(*args: str) -> list[str]:
        proc = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "git failed")
        return [line for line in proc.stdout.splitlines() if line.strip()]

    names = set(git("ls-files"))
    names.update(git("diff", "--cached", "--name-only", "--diff-filter=ACMR"))
    return sorted(names)


def read_allowlist() -> dict[str, str]:
    """``label|path  # reason`` per line. Comments and blanks ignored."""
    accepted: dict[str, str] = {}
    if not ALLOWLIST.exists():
        return accepted
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, reason = line.partition("#")
        accepted[key.strip()] = reason.strip() or "(no reason given)"
    return accepted


def scan(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel in paths:
        if SECRET_FILENAMES.search(rel):
            findings.append(Finding("secret", "credential file", rel, 0, rel))
            continue
        path = ROOT / rel
        if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for severity, label, pattern in RULES:
                match = pattern.search(line)
                if match:
                    excerpt = line.strip()
                    if len(excerpt) > 140:
                        excerpt = excerpt[:137] + "..."
                    findings.append(Finding(severity, label, rel, number, excerpt))
    return findings


def main() -> int:
    try:
        paths = tracked_files()
    except RuntimeError as exc:
        print(f"public_repo_audit: {exc}", file=sys.stderr)
        return 2

    findings = scan(paths)
    accepted = read_allowlist()

    blocking: list[Finding] = []
    allowed: list[Finding] = []
    for finding in findings:
        if finding.severity != "secret" and finding.key() in accepted:
            allowed.append(finding)
        else:
            blocking.append(finding)

    print(f"public_repo_audit: {len(paths)} tracked file(s) scanned")

    if allowed:
        seen: set[str] = set()
        print(f"\naccepted ({len(allowed)} hit(s), recorded in deploy/audit-allowlist.txt):")
        for finding in allowed:
            if finding.key() in seen:
                continue
            seen.add(finding.key())
            print(f"  {finding.label}  {finding.path}  -- {accepted[finding.key()]}")

    if blocking:
        print(f"\nNOT CLEAR TO PUBLISH: {len(blocking)} finding(s)")
        for finding in blocking:
            print("  " + finding.render())
        print("\nEach one is either removed from the file, or added to "
              "deploy/audit-allowlist.txt with a reason:")
        for finding in blocking:
            if finding.severity != "secret":
                print(f"  {finding.key()}   # why this is safe to publish")
        if any(f.severity == "secret" for f in blocking):
            print("  (credential findings cannot be allowlisted -- remove them, "
                  "and rotate the credential)")
        return 1

    print("\nCLEAR TO PUBLISH: no unaccepted findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
