#!/usr/bin/env python3
"""Score hand-written (vendor, product) rows against the shipped reach table.

A KEV row is two fields, and which half of a name lands in which field is the
feed's choice, not ours. This prints the score of rows in that exact shape so a
matching change can be checked against the shape it will meet live.

Usage:  python3 tools/reach_probe_rows.py ["Vendor|Product" ...]
With no arguments it prints the rows this card argued about.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.news_rank import DEFAULT_REACH_FILE, load_reach_table  # noqa: E402


@dataclass(frozen=True)
class NamedRow:
    vendor: str = ""
    product: str = ""


DEFAULT_ROWS = [
    # named by the file as software, filed by KEV under their own vendor word
    ("WordPress", "Core"),
    ("WordPress", "File Manager Plugin"),
    ("Drupal", "Core"),
    ("GitLab", "Community and Enterprise Editions"),
    ("PHP", "FastCGI Process Manager (FPM)"),
    ("PHP", "PHPMailer"),
    ("Jenkins", "Script Security Plugin"),
    ("OpenBSD", "OpenSMTPD"),
    ("Docker", "Desktop Community Edition"),
    # companies the file writes as vendor:/brand: -- must stay unrated
    ("Fortinet", "FortiWeb Cloud Connector"),
    ("Fortinet", "FortiPAM Chrome Extension"),
    ("Red Hat", "Build of Keycloak"),
    ("Apple", "Xcode Server"),
    ("Cisco", "Small Business RV Series Routers"),
    # the acceptance cases
    ("", "Net-IDN-Encode"),
    ("Microsoft", "Windows Server 2019"),
    ("Apple", "iOS and iPadOS"),
    ("Cisco", "IOS XE Web UI"),
]


def main(argv: list[str]) -> int:
    rows = [tuple(arg.split("|", 1)) for arg in argv] if argv else DEFAULT_ROWS
    table = load_reach_table(DEFAULT_REACH_FILE)
    for vendor, product in rows:
        weight, token = table.score(NamedRow(vendor, product))
        print(f"{vendor:>12} / {product:<40} -> {weight:>3}  {token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
