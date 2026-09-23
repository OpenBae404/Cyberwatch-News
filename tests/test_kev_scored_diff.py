#!/usr/bin/env python3
"""The reach audit must be able to fail on a regression it is meant to catch.

`tools/kev_scored_diff.py` is the instrument that says the 942 -> 750 drop in
scored KEV rows is the narrowing working and not software quietly losing a
weight the table still prices for it. Its verdict is only worth the paper it
prints if it can return CLEAN *and* can return a regression, so both
directions are exercised here on crafted before/after pairs -- no network, no
live catalogue.

The "still named" predicate is the part that can be wrong in two ways, and it
was: an earlier version let a token cover only part of a multi-word vendor
field ("npm" over "Npm package / System Information Library for Node.JS") and
reported a regression on a row no reach rule ever scored that way. Both the
false positive and the true positive are pinned below.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "kev_scored_diff", ROOT / "tools" / "kev_scored_diff.py",
)
kev_scored_diff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kev_scored_diff)

REACH_FILE = ROOT / "data" / "software_reach.txt"


def report(rows_before, rows_after):
    """Run the diff over two crafted reports; return (exit code, parsed json)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name, rows in (("before", rows_before), ("after", rows_after)):
            (tmp / f"{name}.json").write_text(json.dumps({
                "label": name,
                "rows": len(rows),
                "scored": len([r for r in rows if r["reach"]]),
                "per_row": rows,
            }), encoding="utf-8")
        out = tmp / "diff.json"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = kev_scored_diff.main([
                str(tmp / "before.json"), str(tmp / "after.json"),
                "--reach-file", str(REACH_FILE), "--json", str(out),
            ])
        return code, json.loads(out.read_text(encoding="utf-8"))


def row(cve_id, vendor, product, reach, match):
    return {"cve_id": cve_id, "vendor": vendor, "product": product,
            "reach": reach, "reach_match": match}


class TestTheAuditCanFail(unittest.TestCase):
    def test_a_named_product_losing_its_score_is_a_regression(self):
        """WordPress/Core at 0 while the file still prices `41 wordpress`."""
        before = [row("CVE-2026-60137", "WordPress", "Core", 41, "wordpress")]
        after = [row("CVE-2026-60137", "WordPress", "Core", 0, "")]
        code, out = report(before, after)
        self.assertEqual(code, 1)
        self.assertEqual(out["counts"]["lost-still-named"], 1)
        self.assertEqual(out["lost-still-named"][0]["table_still_prices"], "wordpress")

    def test_a_product_name_losing_its_leading_token_is_a_regression(self):
        before = [row("CVE-2020-1472", "Microsoft", "Windows Server 2019", 100, "windows")]
        after = [row("CVE-2020-1472", "Microsoft", "Windows Server 2019", 0, "")]
        code, out = report(before, after)
        self.assertEqual(code, 1)
        self.assertEqual(out["lost-still-named"][0]["table_still_prices"], "windows")

    def test_a_vendor_wildcard_losing_its_score_is_not_a_regression(self):
        """`vendor:fortinet` is the file saying fortinet is a company."""
        before = [row("CVE-2026-1", "Fortinet", "FortiWeb Cloud Connector", 62, "fortinet")]
        after = [row("CVE-2026-1", "Fortinet", "FortiWeb Cloud Connector", 0, "")]
        code, out = report(before, after)
        self.assertEqual(code, 0)
        self.assertEqual(out["counts"]["lost-vendor-wildcard"], 1)
        self.assertEqual(out["counts"]["lost-still-named"], 0)

    def test_software_the_table_never_named_is_not_a_regression(self):
        before = [row("CVE-2011-2462", "Adobe", "Reader and Acrobat", 31, "acrobat")]
        after = [row("CVE-2011-2462", "Adobe", "Reader and Acrobat", 0, "")]
        code, out = report(before, after)
        self.assertEqual(code, 0)
        self.assertEqual(out["counts"]["lost-never-named"], 1)

    def test_a_token_covering_part_of_a_vendor_field_is_not_still_named(self):
        """The false positive that was actually reported, pinned.

        "npm" is priced by the file, and the vendor field is "Npm package" --
        but no reach rule lets a token match part of a vendor field, so
        calling this a regression accuses the change of something it did not
        do. The predicate must require the vendor word ITSELF, or a token that
        reaches past the whole vendor word.
        """
        before = [row("CVE-2021-21315", "Npm package",
                      "System Information Library for Node.JS", 46, "node js")]
        after = [row("CVE-2021-21315", "Npm package",
                     "System Information Library for Node.JS", 0, "")]
        code, out = report(before, after)
        self.assertEqual(code, 0, "npm over 'Npm package' is not a named match")
        self.assertEqual(out["counts"]["lost-never-named"], 1)

    def test_an_unchanged_row_is_not_reported_at_all(self):
        rows = [row("CVE-2020-1472", "Microsoft", "Windows Server 2019", 100, "windows")]
        code, out = report(rows, rows)
        self.assertEqual(code, 0)
        self.assertEqual(sum(out["counts"].values()), 0)

    def test_gains_and_retokens_are_separated_from_losses(self):
        before = [row("CVE-A", "Microsoft", "Internet Explorer", 0, ""),
                  row("CVE-B", "Cisco", "IOS XE", 60, "cisco")]
        after = [row("CVE-A", "Microsoft", "Internet Explorer", 92, "internet explorer"),
                 row("CVE-B", "Cisco", "IOS XE", 60, "ios")]
        code, out = report(before, after)
        self.assertEqual(code, 0)
        self.assertEqual(out["counts"]["gained"], 1)
        self.assertEqual(out["counts"]["retokened"], 1)


class TestTheFileIsReadAsTheRuleDescribes(unittest.TestCase):
    def test_vendor_and_brand_lines_are_not_product_tokens(self):
        tokens = kev_scored_diff.product_tokens(REACH_FILE)
        companies = kev_scored_diff.company_names(REACH_FILE)
        self.assertIn("wordpress", tokens)
        self.assertIn("windows", tokens)
        self.assertIn("fortinet", companies)
        self.assertNotIn("fortinet", tokens)
        self.assertNotIn("cisco", tokens)

    def test_a_scoped_token_is_read_without_its_vendor(self):
        tokens = kev_scored_diff.product_tokens(REACH_FILE)
        self.assertIn("ios", tokens)
        self.assertNotIn("cisco/ios", tokens)


if __name__ == "__main__":
    unittest.main(verbosity=2)
