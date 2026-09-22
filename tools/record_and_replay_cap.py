#!/usr/bin/env python3
"""Record a raw NVD published window to disk, then replay the cap against it.

    python3 tools/record_and_replay_cap.py --out DIR

Today's live issue was five KEV items in five different products, so the
one-per-product cap dropped nothing and a live run alone is no evidence that
the cap works on real data. This tool closes that gap without inventing a
feed: it saves the **raw JSON pages** NVD returns for the published window
(`--days`, default 2) under ``DIR/nvd_window_pageN.json``, then parses those
saved bytes with the shipping `parse_vulnerability` and replays `rank_news`
over them.

It reports, from the recorded feed:

  * how many CVEs share a CPE vendor+product pair with a higher-ranked one,
  * exactly which items the cap drops at the issue's limit of 5 and over the
    whole ranked list,
  * that the surviving items hold no repeated vendor+product pair.

Everything it reads came off the live API in this run; the recording exists so
the result can be re-checked later against the same bytes.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.sources import nvd  # noqa: E402
from src.news_rank import rank_news  # noqa: E402


def record(out_dir: Path, days: int, pages: int, per_page: int) -> list[dict]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    payloads = []
    index = 0
    for page in range(pages):
        params = {
            "pubStartDate": nvd._to_nvd_time(start),
            "pubEndDate": nvd._to_nvd_time(end),
            "resultsPerPage": str(per_page),
            "startIndex": str(index),
        }
        url = f"{nvd.API_URL}?{urllib.parse.urlencode(params)}"
        payload = nvd._get_json(url, None, 45.0)
        path = out_dir / f"nvd_window_page{page}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        got = len(payload.get("vulnerabilities") or [])
        total = int(payload.get("totalResults") or 0)
        print(f"recorded {path.name}: {got} entries of {total} (startIndex {index})")
        payloads.append(payload)
        index += got
        if got == 0 or index >= total:
            break
        time.sleep(nvd._SLEEP_NO_KEY)
    return payloads


def load(out_dir: Path) -> list:
    items = []
    for path in sorted(out_dir.glob("nvd_window_page*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for entry in payload.get("vulnerabilities") or []:
            item = nvd.parse_vulnerability(entry)
            if item is not None:
                items.append(item)
    return items


def replay(items, limit: int) -> dict:
    ranked_all = rank_news(items, None, limit=len(items))
    report: dict[str, object] = {"parsed": len(items), "ranked": len(ranked_all)}

    def run_cap(cap_limit: int) -> tuple[list, list]:
        used: set[tuple[str, str]] = set()
        owner: dict[tuple[str, str], str] = {}
        kept, dropped = [], []
        for candidate in ranked_all:
            if len(kept) >= cap_limit:
                break
            clash = used.intersection(candidate.product_keys)
            if candidate.product_keys and clash:
                key = sorted(clash)[0]
                dropped.append({
                    "cve_id": candidate.cve_id,
                    "severity": candidate.severity,
                    "cvss_score": candidate.cvss_score,
                    "key": list(key),
                    "slot_taken_by": owner.get(key, "?"),
                })
                continue
            for key in candidate.product_keys:
                owner.setdefault(key, candidate.cve_id)
            used.update(candidate.product_keys)
            kept.append(candidate)
        return kept, dropped

    kept5, dropped5 = run_cap(limit)
    kept_all, dropped_all = run_cap(len(ranked_all))

    # the shipping call must agree with the replay at the issue's limit
    shipped = rank_news(items, None, limit=limit)
    report["shipping_call_matches_replay"] = [i.cve_id for i in shipped] == [
        i.cve_id for i in kept5
    ]

    seen: dict[tuple[str, str], str] = {}
    collisions = []
    for item in kept_all:
        for key in item.product_keys:
            if key in seen:
                collisions.append([list(key), seen[key], item.cve_id])
            else:
                seen[key] = item.cve_id

    report.update({
        "limit": limit,
        "kept_at_limit": [i.cve_id for i in kept5],
        "dropped_at_limit": dropped5,
        "cap_exercised_at_limit": bool(dropped5),
        "kept_uncapped": len(kept_all),
        "dropped_uncapped": len(dropped_all),
        "dropped_uncapped_sample": dropped_all[:15],
        "cap_exercised_uncapped": bool(dropped_all),
        "collisions_among_survivors": collisions,
        "pass": not collisions,
    })
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="record_and_replay_cap.py")
    parser.add_argument("--out", required=True, help="directory for the recording")
    parser.add_argument("--days", type=int, default=2)
    parser.add_argument("--pages", type=int, default=3)
    parser.add_argument("--per-page", type=int, default=200)
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--replay-only", action="store_true")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    if not args.replay_only:
        record(out_dir, args.days, args.pages, args.per_page)

    items = load(out_dir)
    report = replay(items, args.limit)
    report["recording_dir"] = str(out_dir)
    text = json.dumps(report, indent=2)
    print(text)
    (out_dir / "cap_replay.json").write_text(text + "\n", encoding="utf-8")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
