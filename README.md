# CyberWatch Newsletter

A daily security newsletter: five vulnerabilities a reader should know about,
chosen for an audience rather than for one person's machine. Items that are
actually being exploited lead the issue; when nothing new is being exploited,
high-severity CVEs in widely deployed software fill the page so an issue always
ships.

Python 3, standard library only. No API key is required for either source.


## Run it

    python3 run.py

One command, no arguments. It writes one dated markdown file:

    issues/YYYY-MM-DD.md

A full run takes a few minutes: NVD's public API is rate limited to five
requests per thirty seconds without a key, and a normal day costs one request
per KEV-listed CVE plus the window fetch.

Useful flags (none of them are needed for the daily run):

    --dry-run              print the issue instead of writing it
    --no-llm               write the four fields from raw NVD text only
    --llm-url URL          OpenAI-compatible base URL
                           (default: $CYBERWATCH_LLM_BASE_URL or
                            http://localhost:8001/v1)
    --days N               pin the published window instead of widening 2 -> 4 -> 7
    --max-items N          cap on items (default 5)
    --issues-dir PATH      where the dated file goes

Exit codes, so a scheduler can tell the failures apart:

    0  an issue was written
    2  KEV outage: catalogue unreachable, malformed, or implausibly small
    3  NVD feed failure
    4  both feeds worked and produced no candidate at all

Nothing is written on a non-zero exit.


## Publish it

The issues in `issues/` are the source of truth; the website is generated from
them and is not edited by hand.

    python3 build_site.py            # write docs/ from issues/
    python3 build_site.py --check    # write nothing; exit 3 if docs/ is stale

`docs/` is what GitHub Pages serves from `master` -- one HTML page per issue, an
index, `feed.xml`, a stylesheet, `.nojekyll`, and a `CNAME` for
`cyberwatch.asutera.dev`. There is no Actions workflow: the site is built on the
Mac that builds the issue and committed as ordinary files.

Three properties the generator holds, each with a test behind it in
`tests/test_site.py` and a mutant behind that in `tools/mutation_site_check.py`:

  * **Text is escaped before markup is emitted.** NVD descriptions quote
    attacker input; a description containing `<script>` or an `onerror=`
    attribute reaches the page as visible text and never as an element.
  * **The internal LLM endpoint is redacted.** The issue footer names the
    machine that wrote the summaries. Any URL pointing at a `*.local` host,
    loopback or a bare IP becomes `[internal endpoint redacted]` in `docs/`.
    The markdown in `issues/` is left untouched.
  * **A rebuild changes no byte.** Nothing in the output comes from a clock; the
    feed's dates come from the issue filenames. A day with no new issue produces
    an empty `git status`.

### Daily run (launchd)

    cp deploy/ai.cyberwatch.daily.plist ~/Library/LaunchAgents/
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.cyberwatch.daily.plist
    launchctl kickstart -p gui/$(id -u)/ai.cyberwatch.daily     # run it now

Same shape as `ai.hermes.update-sweep`: a user LaunchAgent at 07:10 local, logs
under `~/.hermes/logs/cyberwatch-daily*.log`. It runs `deploy/cyberwatch-daily.sh`,
which builds the issue, regenerates the site, and commits `issues/` and `docs/`
only. Edit the absolute paths in the plist if the checkout is not at
`/Users/YOURNAME/Projects/cyberwatch-news`; launchd does not expand variables.

### Before making the repo public

    python3 tools/public_repo_audit.py

It scans every tracked file for credentials, internal hosts, absolute home
paths and personal email addresses, and exits non-zero unless each finding is
recorded in `deploy/audit-allowlist.txt` with a reason. Credentials cannot be
recorded there at all. `deploy/audit-allowlist.txt` is the written record of
what was judged safe to publish, including the decision about `localhost`
appearing in the source but never on the site.


## Sources

Both are public JSON, fetched live on every run. Neither is cached to disk.

  * **CISA Known Exploited Vulnerabilities (KEV) catalogue** -- tier 1, the
    vulnerabilities attackers are using right now.
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    Read by `src/sources/kev.py`.

  * **NVD CVE API 2.0** -- tier 2 candidates and the full record (CVSS,
    affected products, references) for every item, including the KEV ones.
    https://services.nvd.nist.gov/rest/json/cves/2.0
    Read by `src/sources/nvd.py`.

The local LLM at `http://localhost:8001/v1` (a local model) rewrites the four
per-item fields when it is reachable. It is not a source and it is not
required: when it is missing, slow, or answers with junk, every field falls
back to text already on the NVD record, and the issue still ships.


## How an issue is chosen

`Plans.md` is the authority; this is the short version.

1. **Fetch the KEV catalogue first.** If it cannot be fetched, parsed, or comes
   back implausibly small, the run aborts with exit code 2 and writes nothing.
   This is the one failure the rest of the pipeline cannot catch: the ranker
   accepts an absent catalogue and cheerfully returns five severity-picked
   items, producing an issue that silently claims nothing is known-exploited.
   A quiet KEV day -- a full catalogue with no recent listings -- is not an
   outage; that is what tier 2 is for.

2. **Fetch tier-1 candidates by CVE id.** The CVEs CISA listed in the last
   seven days are pulled from NVD individually. They have to be, because a KEV
   listing almost never falls inside the published window: CISA lists a CVE
   when exploitation is observed, typically weeks or months after publication.
   Measured on 2026-09-21: 0 of 181 CVEs in a two-day published window were in
   KEV, and 1 of 600 in a seven-day window, while CISA had listed 7 that week.
   Without the by-id fetch, tier 1 is unreachable and the two-tier rule is
   decorative.

3. **Fetch tier-2 candidates from the published window only.** `by="published"`
   is hard-coded in `run.py` and is never offered as a choice. A `lastMod`
   window dates the issue by when somebody last edited a record, which puts a
   CVE from July in today's issue. The window widens 2 -> 4 -> 7 days only if a
   short one is too thin.

4. **Dedupe across both sources, then rank.** A KEV-listed CVE that the
   published window also returned must not appear twice. Ranking is tier first
   (KEV is absolute -- a MEDIUM that is being exploited outranks a CRITICAL
   that is not), then severity band, then how widely the software is deployed
   (`data/software_reach.txt`), then CVSS.

5. **Render five items.** Every item says in words why it is in the issue;
   known-exploited items are visually distinct from severity-chosen ones.

There is deliberately **no profile matcher** here. Selection is for readers,
not for one machine. This repo is not the CyberWatch profile matcher, and
`rank.py` / `profile.yaml` from that project must not be copied in.


## Tests

    python3 tests/run.py

Runs every module, offline and live, and exits non-zero on the first failure.
The live tests hit the real CISA and NVD feeds, so the suite needs network.

Two entries in the suite are mutation checks rather than tests: they break a
control on a throwaway copy of the source and assert that the tests go red. A
guard nobody has watched fail is not evidence, and the KEV-outage guard in
particular exists to stop a run that otherwise looks perfectly healthy. The
site generator gets the same treatment, because an escaping test passes
trivially against a generator whose hostile input never reaches the page.


## Layout

    run.py                  the entrypoint: fetch, dedupe, rank, render, write
    build_site.py           generate docs/ from issues/ (--check to verify only)
    Plans.md                scope, the two-tier rule, why this is not the matcher
    src/sources/kev.py      CISA KEV catalogue
    src/sources/nvd.py      NVD CVE API, published/lastMod windows, fetch by id
    src/dedupe.py           collapse repeated CVE ids to the newest revision
    src/news_rank.py        the two-tier selection
    src/render.py           the markdown issue, LLM fields with raw fallback
    src/site.py             markdown -> HTML, the index, the feed, redaction
    data/software_reach.txt how widely deployed each named product is
    deploy/                 the launchd plist, the daily script, the audit record
    tests/run.py            the whole suite
    tools/                  live probes and mutation checks, run by hand
    issues/                 the output, one dated markdown file per run
    docs/                   the published site, generated -- never edited by hand
