#!/usr/bin/env python3
"""Dump the reach score of every CVE in a recorded NVD window, as text.

    python3 tools/reach_dump.py DIR > reach.txt

One line per CVE: ``CVE-ID<TAB>reach<TAB>reach_match``, sorted by id. The
product cap does not appear here on purpose -- this file exists so a change to
the cap can be proven to have left the reach scoring byte-identical, by
diffing this output against the same command run on the base revision.

Every item is scored, not just the five that ship: capping the output at the
issue would hide a reach change on item six.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.news_rank import load_reach_table  # noqa: E402
from src.sources import nvd  # noqa: E402


def main() -> int:
    directory = Path(sys.argv[1])
    table = load_reach_table()
    rows: list[tuple[str, int, str]] = []
    for path in sorted(directory.glob("nvd_window_page*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for entry in payload.get("vulnerabilities") or []:
            item = nvd.parse_vulnerability(entry)
            if item is None:
                continue
            weight, token = table.score(item)
            rows.append((item.cve_id, weight, token))
    for cve_id, weight, token in sorted(rows):
        print(f"{cve_id}\t{weight}\t{token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
