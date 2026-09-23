"""Scratch probe: print the raw CNA `affected` rows for named CVEs.

usage: python3 tools/probe_affected_rows.py <recorded_feed_dir> CVE-... [CVE-...]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    directory = Path(sys.argv[1])
    wanted = {c.upper() for c in sys.argv[2:]}
    for page in sorted(directory.glob("nvd_window_page*.json")):
        payload = json.loads(page.read_text())
        for entry in payload.get("vulnerabilities") or []:
            cve = entry.get("cve") or {}
            if str(cve.get("id", "")).upper() not in wanted:
                continue
            print("=" * 70)
            print(cve["id"])
            for block in cve.get("affected") or []:
                rows = block.get("affectedData")
                if not isinstance(rows, list):
                    rows = [block]
                for row in rows:
                    print("  vendor=%r product=%r packageName=%r cpes=%r" % (
                        row.get("vendor"), row.get("product"),
                        row.get("packageName"), row.get("cpes"),
                    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
