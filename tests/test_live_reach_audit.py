#!/usr/bin/env python3
"""The audit instrument must be able to say no.

`tools/live_reach_audit.py` exists to check one acceptance criterion: every
reach figure in a shipped issue traces to a CPE the live feed marks
*vulnerable*. An earlier version graded a reach score with no vulnerable CPE
behind it as `ok-label-only` and still returned `pass: true` / exit 0 -- the
criterion being violated while the instrument reported success. These tests
pin the pass rule so that cannot come back: only `ok-vulnerable-cpe` and
`no-reach` are passing verdicts, and every other way a token can get in
(platform CPE, unflagged CNA label, no surface at all) fails the run.

No network: `audit()` is a pure function over already-ranked items.
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
    "live_reach_audit", ROOT / "tools" / "live_reach_audit.py",
)
live_reach_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(live_reach_audit)
audit = live_reach_audit.audit


class FakeItem:
    """The attributes `audit()` reads off a ranked item, and nothing else."""

    def __init__(self, cve_id, reach, reach_match, *, vulnerable=(), platform=(),
                 labels=(), product_keys=(), tier=1, severity="CRITICAL",
                 cvss_score=9.3):
        self.cve_id = cve_id
        self.reach = reach
        self.reach_match = reach_match
        self.vulnerable_cpes = list(vulnerable)
        self.platform_cpes = list(platform)
        self.affected_products = list(labels)
        self.product_keys = tuple(product_keys)
        self.tier = tier
        self.severity = severity
        self.cvss_score = cvss_score


def one(item):
    return audit([item], [item], 5)


class TestVerdicts(unittest.TestCase):
    def test_reach_from_vulnerable_cpe_passes(self):
        item = FakeItem(
            "CVE-2025-39682", 100, "linux kernel",
            vulnerable=["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"],
            labels=["Linux Linux Kernel"],
            product_keys=[("linux", "linux_kernel")],
        )
        report = one(item)
        self.assertEqual(report["items"][0]["verdict"], "ok-vulnerable-cpe")
        self.assertTrue(report["pass"])

    def test_no_reach_passes(self):
        item = FakeItem("CVE-2026-87886", 0, "",
                        vulnerable=["cpe:2.3:a:acronis:acronis_backup:*:*:*:*:*:*:*:*"],
                        platform=["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"])
        report = one(item)
        self.assertEqual(report["items"][0]["verdict"], "no-reach")
        self.assertTrue(report["pass"])

    def test_reach_from_platform_cpe_fails(self):
        """CVE-2026-87886's shape: reach scored off a vulnerable:false CPE."""
        item = FakeItem(
            "CVE-2026-87886", 100, "linux kernel",
            vulnerable=["cpe:2.3:a:acronis:acronis_backup:*:*:*:*:*:*:*:*"],
            platform=["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"],
        )
        report = one(item)
        self.assertEqual(report["items"][0]["verdict"], "FAIL-platform-only")
        self.assertFalse(report["pass"])
        self.assertEqual(len(report["reach_failures"]), 1)

    def test_reach_from_cna_label_only_fails(self):
        """The same shape via an unflagged CNA `affected` label.

        Modelled on the live tier-1 item the reviewer caught: reach 56 via
        "big ip" with no CPEs of either kind on the record.
        """
        item = FakeItem("CVE-2026-94127", 56, "big ip", labels=["F5 BIG-IP"])
        report = one(item)
        self.assertEqual(report["items"][0]["verdict"], "FAIL-label-only")
        self.assertFalse(report["pass"])

    def test_reach_matching_no_surface_fails(self):
        item = FakeItem("CVE-2026-00001", 90, "windows",
                        vulnerable=["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"])
        report = one(item)
        self.assertEqual(report["items"][0]["verdict"], "FAIL-untraceable")
        self.assertFalse(report["pass"])

    def test_exit_code_reflects_the_failure(self):
        """`pass: false` is what main() turns into exit 1 -- pin them together."""
        bad = FakeItem("CVE-2026-94127", 56, "big ip", labels=["F5 BIG-IP"])
        report = one(bad)
        self.assertFalse(report["pass"])
        self.assertEqual(0 if report["pass"] else 1, 1)

    def test_verdict_counts_are_reported(self):
        good = FakeItem("CVE-A", 100, "linux kernel",
                        vulnerable=["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"])
        bad = FakeItem("CVE-B", 56, "big ip", labels=["F5 BIG-IP"])
        report = audit([good, bad], [good, bad], 5)
        self.assertEqual(report["verdict_counts"],
                         {"ok-vulnerable-cpe": 1, "FAIL-label-only": 1})
        self.assertFalse(report["pass"])


class TestProductKeyRule(unittest.TestCase):
    def test_collision_fails_even_when_reach_is_clean(self):
        a = FakeItem("CVE-A", 0, "", product_keys=[("adobe", "connect")])
        b = FakeItem("CVE-B", 0, "", product_keys=[("adobe", "connect")])
        report = audit([a, b], [a, b], 5)
        self.assertEqual(len(report["product_key_collisions"]), 1)
        self.assertFalse(report["pass"])

    def test_cap_exercised_is_reported_when_a_candidate_is_dropped(self):
        a = FakeItem("CVE-A", 0, "", product_keys=[("adobe", "connect")])
        b = FakeItem("CVE-B", 0, "", product_keys=[("adobe", "connect")])
        report = audit([a], [a, b], 5)
        self.assertTrue(report["cap_exercised"])
        self.assertEqual(report["cap_dropped"][0]["cve_id"], "CVE-B")
        self.assertTrue(report["pass"])


class TestTheCraftedFalsePositive(unittest.TestCase):
    """The shipped fixture must still be a false positive the audit rejects.

    `tests/fixtures/audit_false_positive.json` is what the acceptance
    criterion "the audit exits non-zero when fed a crafted false positive" is
    demonstrated with. If someone softens the fixture -- gives the F5 item a
    vulnerable CPE, say -- the demonstration silently becomes a pass on a
    clean input and proves nothing. These tests pin the fixture's shape and
    the exit code it produces, through `main()`, not through `audit()`.
    """

    FIXTURE = ROOT / "tests" / "fixtures" / "audit_false_positive.json"

    def test_the_fixture_exists_and_carries_an_untraceable_reach_figure(self):
        blob = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        offenders = [
            item for item in blob["chosen"]
            if item["reach"] and not item["vulnerable_cpes"]
        ]
        self.assertTrue(
            offenders,
            "the fixture no longer contains an item scoring reach with no "
            "vulnerable CPE, so it can no longer demonstrate a rejection",
        )

    def test_replaying_the_fixture_exits_non_zero(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = live_reach_audit.main(["--replay", str(self.FIXTURE)])
        self.assertEqual(code, 1)
        report = json.loads(buffer.getvalue())
        self.assertFalse(report["pass"])
        verdicts = {i["cve_id"]: i["verdict"] for i in report["items"]}
        self.assertEqual(verdicts["CVE-2026-94127"], "FAIL-label-only")
        self.assertEqual(verdicts["CVE-2026-87886"], "FAIL-platform-only")
        self.assertEqual(verdicts["CVE-2025-39682"], "ok-vulnerable-cpe")

    def test_replaying_a_clean_issue_exits_zero(self):
        """The exit code has to be able to say yes as well, or it says nothing."""
        clean = [{
            "cve_id": "CVE-2025-39682", "reach": 100, "reach_match": "linux kernel",
            "vulnerable_cpes": ["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"],
            "affected_products": ["Linux Linux Kernel"],
            "product_keys": [["linux", "linux_kernel"]],
        }]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.json"
            path.write_text(json.dumps(clean), encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = live_reach_audit.main(["--replay", str(path)])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(buffer.getvalue())["pass"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
