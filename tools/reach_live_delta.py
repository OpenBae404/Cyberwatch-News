#!/usr/bin/env python3
"""Score every row of the LIVE CISA KEV catalogue, at two revisions.

The reach rule is a matching rule, so the only honest measure of it is the
catalogue it will meet. This scores all ~1700 live KEV rows under this
worktree and under any other revision of the repo, and prints:

  * how many rows score at each revision;
  * every row that LOSES its score, split into the two classes that matter --
    software this file never named (fine: it used to score its vendor's weight
    through a rule that never measured it) and software the file still prices
    by name (a defect: the weight exists and is being ignored);
  * every row that gains one, and every row whose token changed.

Usage:  python3 tools/reach_live_delta.py [BASE_REV]   (default HEAD~1)

The other revision is materialised with `git archive` into a temp dir and run
in its own subprocess, so neither revision's import shadows the other.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCORE_SCRIPT = r'''
import json, sys
from dataclasses import dataclass
sys.path.insert(0, sys.argv[1])
from src.news_rank import DEFAULT_REACH_FILE, load_reach_table

@dataclass(frozen=True)
class NamedRow:
    vendor: str = ""
    product: str = ""

rows = json.load(open(sys.argv[2]))
table = load_reach_table(DEFAULT_REACH_FILE)
out = {}
for cve, vendor, product in rows:
    weight, token = table.score(NamedRow(vendor, product))
    out[cve] = [weight, token]
json.dump(out, open(sys.argv[3], "w"))
'''


def live_kev_rows() -> list[tuple[str, str, str]]:
    sys.path.insert(0, str(ROOT))
    from src.sources.kev import fetch_kev_catalog  # noqa: E402

    catalog = fetch_kev_catalog()
    rows = []
    for entry in catalog.entries:
        rows.append((entry.cve_id, entry.vendor or "", entry.product or ""))
    return rows


def score_at(revision: str | None, rows_path: Path, tmp: Path) -> dict:
    out_path = tmp / f"scores_{revision or 'worktree'}.json".replace("/", "_")
    if revision is None:
        tree = ROOT
    else:
        tree = tmp / "base"
        tree.mkdir(parents=True, exist_ok=True)
        archive = subprocess.run(
            ["git", "archive", revision], cwd=ROOT, check=True, capture_output=True)
        subprocess.run(["tar", "-x", "-C", str(tree)], input=archive.stdout, check=True)
    script = tmp / "score.py"
    script.write_text(SCORE_SCRIPT)
    subprocess.run(
        [sys.executable, str(script), str(tree), str(rows_path), str(out_path)],
        check=True, cwd=str(tree))
    return json.loads(out_path.read_text())


def product_tokens(tree: Path) -> dict[str, int]:
    sys.path.insert(0, str(tree))
    from src.news_rank import DEFAULT_REACH_FILE, load_reach_table

    table = load_reach_table(DEFAULT_REACH_FILE)
    return {e.token: e.weight for e in table.entries if e.kind == "product"}


def main(argv: list[str]) -> int:
    base_rev = argv[0] if argv else "HEAD~1"
    rows = live_kev_rows()
    print(f"live CISA KEV rows: {len(rows)}")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        rows_path = tmp / "rows.json"
        rows_path.write_text(json.dumps(rows))
        head = score_at(None, rows_path, tmp)
        base = score_at(base_rev, rows_path, tmp)

    tokens = product_tokens(ROOT)
    by_cve = {cve: (vendor, product) for cve, vendor, product in rows}

    head_scored = sum(1 for v in head.values() if v[0])
    base_scored = sum(1 for v in base.values() if v[0])
    print(f"rows scored: {base_rev} {base_scored}   worktree {head_scored}")

    lost_named, lost_unnamed, gained, retoken = [], [], [], []
    for cve, (weight, token) in head.items():
        b_weight, b_token = base[cve]
        vendor, product = by_cve[cve]
        if b_weight and not weight:
            # is this software still priced by name in the file?
            named = None
            for field in (vendor, product):
                key = field.strip().lower()
                if key in tokens:
                    named = (key, tokens[key])
            (lost_named if named else lost_unnamed).append((cve, vendor, product, b_weight, b_token, named))
        elif weight and not b_weight:
            gained.append((cve, vendor, product, weight, token))
        elif weight and token != b_token:
            retoken.append((cve, vendor, product, b_token, token, b_weight, weight))

    print()
    print(f"LOST a score, and the file still prices that name as a product: {len(lost_named)}")
    for cve, vendor, product, w, t, named in sorted(lost_named):
        print(f"   {cve:<16} {vendor} / {product:<38} was {w} '{t}'   table: {named[0]} {named[1]}")
    print()
    print(f"LOST a score, software this file never named: {len(lost_unnamed)}")
    for cve, vendor, product, w, t, _ in sorted(lost_unnamed)[:200]:
        print(f"   {cve:<16} {vendor} / {product:<38} was {w} '{t}'")
    print()
    print(f"GAINED a score: {len(gained)}")
    for cve, vendor, product, w, t in sorted(gained)[:200]:
        print(f"   {cve:<16} {vendor} / {product:<38} now {w} '{t}'")
    print()
    print(f"kept a score under a different token: {len(retoken)}")
    for cve, vendor, product, bt, t, bw, w in sorted(retoken)[:200]:
        print(f"   {cve:<16} {vendor} / {product:<34} {bw} '{bt}' -> {w} '{t}'")
    print()
    print("VERDICT:", "clean" if not lost_named else f"{len(lost_named)} named-but-unmatched row(s)")
    return 1 if lost_named else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
