#!/usr/bin/env python3
"""Print the live audit JSON as a short table. Reading aid, not a check."""
import json
import sys
from pathlib import Path

path = Path(sys.argv[1] if len(sys.argv) > 1 else "live_reach_audit.json")
d = json.loads(path.read_text())
print("pass:", d["pass"], " cap_exercised:", d["cap_exercised"])
print("feed:", json.dumps(d["feed"]))
for i in d["items"]:
    print(
        i["position"], i["cve_id"], "tier", i["tier"], "reach", i["reach"],
        repr(i["reach_match"]), i["verdict"],
        "keys", i["product_keys"],
        "nvuln", len(i["vulnerable_cpes"]), "nplat", len(i["platform_cpes"]),
        "labels", i["affected_products"][:3],
    )
print("collisions:", d["product_key_collisions"])
print("dropped:", json.dumps(d["cap_dropped"], indent=1))
