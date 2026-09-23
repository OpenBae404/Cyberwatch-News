"""Probe: is the live audit's FAIL-untraceable a real defect, or an artifact of
the instrument? The reach token arrives from the reach file verbatim
("big-ip"); the CPE surfaces are _normalise()d ("big ip"). Print both sides."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.news_rank import _cpe_vendor_product, _normalise  # noqa: E402

token = "big-ip"
cpes = [
    "cpe:2.3:a:f5:big-ip_access_policy_manager:*:*:*:*:*:*:*:*",
    "cpe:2.3:a:f5:big-ip_access_policy_manager:21.1.0:*:*:*:*:*:*:*",
]
parts = []
for criteria in cpes:
    vendor, product = _cpe_vendor_product(criteria)
    parts.extend([x for x in (vendor, product) if x])
surface = " " + " ".join(_normalise(x) for x in parts) + " "

print("token raw        :", repr(token))
print("token normalised :", repr(_normalise(token)))
print("vuln cpe surface :", repr(surface))
print("raw padded in    :", f" {token} " in surface)
print("norm padded in   :", f" {_normalise(token)} " in surface)
