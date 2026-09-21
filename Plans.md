# CyberWatch Newsletter

**Project 2** in `the project's private planning notes`. The
audience-building side of CyberWatch:

> **5 Cybersecurity Things You Actually Need to Know Today**

## This is NOT CyberWatch

Two different products, repeatedly confused. Keep them apart.

| | CyberWatch (Project 1) | Newsletter (Project 2) |
|---|---|---|
| Repo | `~/Projects/cyberwatch` | this one |
| For | one subscriber's environment | a general audience |
| Selection | does this CVE hit **your** stack | would a security reader want to know |
| Mechanism | exact CPE match against a profile | known-exploited first, then severity |
| Status | built and working | this project |

CyberWatch answers *"these 4 vulnerabilities matter to your environment."*
The newsletter answers *"here is what happened in security today."* A profile
matcher cannot do the second job — pointed at one homelab it returns nothing
most days, which is correct for CyberWatch and useless for a newsletter.

**Do not copy `rank.py` or `profile.yaml` from the CyberWatch repo.** They are
deliberately absent. The ranker here is a different rule.

## Selection rule (decided 2026-09-21)

Two tiers, so an issue always ships:

1. **Known-exploited first.** Anything in the CISA KEV catalogue outranks
   everything else. Being actively exploited is the strongest signal that a
   reader needs to know.
2. **Severity plus reach as the fallback.** On a day with no new KEV entries,
   fill from high-severity CVEs in widely-deployed software.

Daily cadence. Cap of 5 items.

Rejected: KEV-only (goes silent for days), severity-only (CVSS is
self-reported and inflated), fixed category slots (not enough daily candidates
to fill them honestly — revisit if one vendor starts dominating).

## Inherited from the CyberWatch repo

`src/sources/nvd.py`, `src/dedupe.py`, `src/render.py` and their tests were
copied as working plumbing. This is a deliberate fork, not a library: two small
products, and copying beats a shared package nobody has designed yet. If a
third consumer appears, extract one instead of copying again.

**Known bug carried over:** `nvd.py` is fetched by the old entrypoint with a
`lastMod` window alongside the `published` one, so a CVE published in July can
appear in a September issue because somebody edited it. The newsletter must use
the published window only.

## Out of scope

Subscriber storage, opt-in, email delivery, scheduling, a web archive, payment,
per-reader personalisation (that is CyberWatch), a third source.
