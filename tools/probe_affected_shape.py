"""Scratch probe: what shape do CNA `affected` rows take in the AG-8 recording?

Reads the recorded NVD pages and reports, per CVE, whether there is any
vulnerable CPE, and what vendor/product fields the CNA rows carry. Used while
fixing the product cap (AG-13); kept so the finding can be re-derived.

usage: python3 tools/probe_affected_shape.py <recorded_feed_dir>
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path


def main() -> int:
    directory = Path(sys.argv[1])
    pages = sorted(directory.glob("nvd_window_page*.json"))
    shapes = collections.Counter()
    row_keys = collections.Counter()
    samples: list[str] = []
    total = 0
    with_affected = 0
    with_vuln_cpe = 0

    for page in pages:
        payload = json.loads(page.read_text())
        for entry in payload.get("vulnerabilities") or []:
            cve = entry.get("cve") or {}
            total += 1
            affected = cve.get("affected") or []
            if affected:
                with_affected += 1
            for block in affected:
                if not isinstance(block, dict):
                    continue
                shapes[tuple(sorted(block.keys()))] += 1
                rows = block.get("affectedData")
                if not isinstance(rows, list):
                    rows = [block]
                for row in rows:
                    if isinstance(row, dict):
                        row_keys[tuple(sorted(row.keys()))] += 1
                        if len(samples) < 6:
                            samples.append(json.dumps(row)[:300])
            for config in (cve.get("configurations") or []) + (cve.get("cpeApplicability") or []):
                for node in config.get("nodes") or []:
                    for match in node.get("cpeMatch") or []:
                        if match.get("vulnerable") is True:
                            with_vuln_cpe += 1
                            break

    print(json.dumps({
        "pages": [p.name for p in pages],
        "cves": total,
        "with_affected_block": with_affected,
        "with_vulnerable_cpe_match": with_vuln_cpe,
        "block_shapes": {str(k): v for k, v in shapes.most_common(10)},
        "row_shapes": {str(k): v for k, v in row_keys.most_common(10)},
        "row_samples": samples,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
