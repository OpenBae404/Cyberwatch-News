#!/usr/bin/env python3
"""Audit a live run of the pipeline against the two rules AG-7 introduced.

    python3 tools/live_reach_audit.py [--json PATH]

It fetches the same live feeds `run.py` does (CISA KEV, then NVD by id and by
published window), ranks the deduped candidates with `rank_news`, and then
checks the two claims the fix makes, item by item:

  1. **Every reach figure traces to a CPE the live feed marks vulnerable.**
     For each chosen item with `reach > 0`, the matched token is looked for in
     the vendor/product fields of `vulnerable_cpes`, and separately in
     `platform_cpes` and in the `affected_products` display labels. Anything
     other than a hit in `vulnerable_cpes` is a FAIL, because the criterion is
     traceability to a vulnerable CPE and nothing else satisfies it. The failure
     is sub-typed by where the token *did* come from, so the report says how the
     score got in: `FAIL-platform-only` is the CVE-2026-87886 shape arriving
     through a `vulnerable: false` CPE; `FAIL-label-only` is the same shape
     arriving through a CNA `affected` display label, which carries no
     `vulnerable` flag at all; `FAIL-untraceable` is a token that matches no
     surface on the item.

  2. **No two items share one CPE vendor+product pair.** The chosen items'
     `product_keys` are intersected pairwise.

It also reports whether the one-per-product cap was *exercised* on this run --
that is, whether any ranked candidate was actually dropped because a
higher-ranked item had already taken its product's slot. A run where nothing
was dropped does not test the cap; it only shows the cap did no harm.

No LLM is involved: this audits selection, not prose. The issue itself is
written by `run.py`; this is a second, independent read of the same feeds.

`--replay PATH` audits items from a JSON file instead of the live feeds. It
exists because the pass rule and the exit code are the whole value of this
tool, and a live run only ever demonstrates them when the feeds happen to
contain a failing shape. `tests/fixtures/audit_false_positive.json` is a
crafted one: a reach figure whose token appears only on a CNA display label,
which is the shape the criterion forbids. Replaying it must print
`"pass": false` and exit 1.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from run import (  # noqa: E402
    MAX_NVD_ITEMS,
    WINDOW_DAYS,
    collect_candidates,
    collect_kev_candidates,
    load_kev,
)
from src.dedupe import dedupe_by_cve_id  # noqa: E402
from src.news_rank import (  # noqa: E402
    MAX_ITEMS,
    _cpe_vendor_product,
    _normalise,
    _resolve_reach,
    rank_news,
)


def _surface(values) -> str:
    """Space-padded normalised text of a list of raw strings."""
    joined = " ".join(_normalise(v) for v in values if str(v).strip())
    return f" {joined} " if joined else ""


def _cpe_surface(criteria_list) -> str:
    parts = []
    for criteria in criteria_list or ():
        vendor, product = _cpe_vendor_product(criteria)
        parts.extend([p for p in (vendor, product) if p])
    return _surface(parts)


def audit(chosen, all_ranked, limit: int) -> dict:
    findings = []
    for rank_pos, item in enumerate(chosen, start=1):
        vulnerable = list(getattr(item, "vulnerable_cpes", ()) or ())
        platform = list(getattr(item, "platform_cpes", ()) or ())
        labels = list(getattr(item, "affected_products", ()) or ())

        vuln_surface = _cpe_surface(vulnerable)
        plat_surface = _cpe_surface(platform)
        label_surface = _surface(labels)

        # The token arrives from the reach file verbatim ("big-ip"); every
        # surface above has been through `_normalise` ("big ip"). Comparing the
        # two without normalising the token makes any hyphenated or punctuated
        # token untraceable on every surface, so the audit reports a
        # FAIL-untraceable for a reach figure that is in fact sitting in the
        # vulnerable CPE. Normalise both sides or the instrument invents faults.
        token = _normalise(item.reach_match) if item.reach_match else ""
        padded = f" {token} " if token else ""
        in_vuln = bool(token) and padded in vuln_surface
        in_label = bool(token) and padded in label_surface
        in_plat_only = bool(token) and padded in plat_surface and not in_vuln

        if not token:
            verdict = "no-reach"          # reach 0, nothing to trace
        elif in_vuln:
            verdict = "ok-vulnerable-cpe"
        elif in_plat_only:
            verdict = "FAIL-platform-only"   # the CVE-2026-87886 shape, via the CPE
        elif in_label:
            verdict = "FAIL-label-only"      # same shape, via an unflagged CNA label
        else:
            verdict = "FAIL-untraceable"     # token matches no surface at all

        findings.append({
            "position": rank_pos,
            "cve_id": item.cve_id,
            "tier": item.tier,
            "severity": item.severity,
            "cvss_score": item.cvss_score,
            "reach": item.reach,
            "reach_match": token,
            "verdict": verdict,
            "product_keys": [list(k) for k in item.product_keys],
            "vulnerable_cpes": vulnerable,
            "platform_cpes": platform,
            "affected_products": labels,
        })

    # rule 2: pairwise product-key collision among the chosen items
    seen: dict[tuple[str, str], str] = {}
    collisions = []
    for item in chosen:
        for key in item.product_keys:
            if key in seen:
                collisions.append({
                    "key": list(key), "first": seen[key], "second": item.cve_id,
                })
            else:
                seen[key] = item.cve_id

    # was the cap exercised? replay the cap and record what it dropped
    used: set[tuple[str, str]] = set()
    kept = 0
    dropped = []
    for candidate in all_ranked:
        if kept >= limit:
            break
        keys = candidate.product_keys
        clash = used.intersection(keys)
        if keys and clash:
            dropped.append({
                "cve_id": candidate.cve_id,
                "tier": candidate.tier,
                "severity": candidate.severity,
                "blocked_by_key": [list(k) for k in sorted(clash)],
                "taken_by": seen.get(sorted(clash)[0], "?"),
            })
            continue
        used.update(keys)
        kept += 1

    failures = [f for f in findings if f["verdict"].startswith("FAIL")]
    verdicts: dict[str, int] = {}
    for f in findings:
        verdicts[f["verdict"]] = verdicts.get(f["verdict"], 0) + 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "items": findings,
        "verdict_counts": verdicts,
        "product_key_collisions": collisions,
        "cap_exercised": bool(dropped),
        "cap_dropped": dropped,
        "reach_failures": failures,
        "pass": not failures and not collisions,
    }


class ReplayItem:
    """A ranked item rebuilt from JSON, carrying only what `audit()` reads.

    `--replay` exists so the audit's own pass rule can be exercised end to end,
    exit code included, without waiting for the live feeds to happen to contain
    a failing shape. An instrument that has never been seen to return non-zero
    on real invocation is an instrument nobody has tested.
    """

    def __init__(self, blob):
        self.cve_id = blob.get("cve_id", "CVE-0000-0000")
        self.reach = int(blob.get("reach", 0))
        self.reach_match = blob.get("reach_match", "")
        self.vulnerable_cpes = list(blob.get("vulnerable_cpes", ()))
        self.platform_cpes = list(blob.get("platform_cpes", ()))
        self.affected_products = list(blob.get("affected_products", ()))
        self.product_keys = tuple(tuple(k) for k in blob.get("product_keys", ()))
        self.tier = blob.get("tier", 1)
        self.severity = blob.get("severity", "CRITICAL")
        self.cvss_score = blob.get("cvss_score", 9.8)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="live_reach_audit.py")
    parser.add_argument("--json", default=None, help="also write the report as JSON")
    parser.add_argument("--max-items", type=int, default=MAX_ITEMS)
    parser.add_argument(
        "--replay", default=None,
        help="audit items from a JSON list instead of the live feeds "
             "(a list of objects, or {chosen: [...], ranked: [...]})",
    )
    args = parser.parse_args(argv)

    if args.replay:
        blob = json.loads(Path(args.replay).read_text(encoding="utf-8"))
        chosen_blobs = blob["chosen"] if isinstance(blob, dict) else blob
        ranked_blobs = blob.get("ranked", chosen_blobs) if isinstance(blob, dict) else blob
        chosen = [ReplayItem(b) for b in chosen_blobs]
        all_ranked = [ReplayItem(b) for b in ranked_blobs]
        report = audit(chosen, all_ranked, args.max_items)
        report["feed"] = {"replayed_from": args.replay, "chosen": len(chosen)}
        text = json.dumps(report, indent=2, sort_keys=False)
        print(text)
        if args.json:
            Path(args.json).write_text(text + "\n", encoding="utf-8")
        return 0 if report["pass"] else 1

    catalog = load_kev()
    kev_items, kev_recent = collect_kev_candidates(catalog)
    window_items, window_days, considered = collect_candidates(
        windows=WINDOW_DAYS, max_items=MAX_NVD_ITEMS, want=args.max_items,
    )
    candidates = list(dedupe_by_cve_id(kev_items + window_items))

    table = _resolve_reach(None)
    all_ranked = rank_news(candidates, catalog, reach=table, limit=len(candidates))
    chosen = rank_news(candidates, catalog, reach=table, limit=args.max_items)

    report = audit(chosen, all_ranked, args.max_items)
    report["feed"] = {
        "kev_entries": len(catalog),
        "kev_listed_recently": kev_recent,
        "kev_records_fetched": len(kev_items),
        "window_days": window_days,
        "window_considered": considered,
        "candidates_after_dedupe": len(candidates),
        "chosen": len(chosen),
        "reach_table": table.source,
    }

    text = json.dumps(report, indent=2, sort_keys=False)
    print(text)
    if args.json:
        Path(args.json).write_text(text + "\n", encoding="utf-8")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
