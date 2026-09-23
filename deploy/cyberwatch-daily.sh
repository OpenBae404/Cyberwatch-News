#!/bin/bash
# The daily CyberWatch run, as launchd invokes it.
#
#   1. build today's issue   (run.py, writes issues/YYYY-MM-DD.md)
#   2. regenerate the site   (build_site.py, writes docs/)
#   3. commit, and push ONLY if CYBERWATCH_PUBLISH=1 is set
#
# Deliberately not a python script: the interesting failure modes here are
# process-level (a feed outage exiting 2, nothing to commit, no remote yet) and
# that is what a shell reads naturally.
#
# PUSHING IS OFF BY DEFAULT, and a remote existing does not turn it on. This
# repo is about to become public, and an unattended job that pushes whatever is
# on master every morning publishes the first mistake nobody reviewed -- a
# redaction that regressed, a file somebody left staged, an issue built from a
# half-broken feed. Set CYBERWATCH_PUBLISH=1 in the plist's EnvironmentVariables
# once the repo is public, the audit is clean, and that trade is wanted.
# Until then the commit is local and a human pushes it after looking.
#
# Install and check:
#   cp deploy/ai.cyberwatch.daily.plist ~/Library/LaunchAgents/
#   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.cyberwatch.daily.plist
#   launchctl kickstart -p gui/$(id -u)/ai.cyberwatch.daily     # run it now
#   launchctl print gui/$(id -u)/ai.cyberwatch.daily | head
#
# Exit codes are run.py's, passed through, so `launchctl print` shows which
# stage failed:
#   0 issue written and site rebuilt   2 KEV outage
#   3 NVD failure                      4 nothing to ship
#   5 the site generator refused (bad issue filename, or docs/ unwritable)
#   6 the commit itself failed
#   7 publishing was on and the push failed
#   8 publishing was on and there is no remote to push to

set -o pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1

PYTHON="${CYBERWATCH_PYTHON:-/usr/bin/python3}"
stamp() { date -u "+%Y-%m-%dT%H:%M:%SZ"; }

echo "[$(stamp)] cyberwatch daily run in $REPO"

"$PYTHON" run.py
status=$?
if [ "$status" -ne 0 ]; then
  echo "[$(stamp)] run.py exited $status -- no issue written, site left alone"
  exit "$status"
fi

"$PYTHON" build_site.py
status=$?
if [ "$status" -ne 0 ]; then
  echo "[$(stamp)] build_site.py exited $status -- the site was NOT rebuilt"
  exit 5
fi

# An issue is worth nothing unpublished, so the commit is part of the run. Only
# issues/ and docs/ are staged: a daily job must never commit a source change
# somebody left in the tree.
git add issues docs
if git diff --cached --quiet; then
  echo "[$(stamp)] nothing new to commit (same issue, same site)"
  exit 0
fi

git -c user.name="cyberwatch-daily" \
    -c user.email="cyberwatch-daily@localhost" \
    commit --quiet -m "Publish issue $(date -u '+%Y-%m-%d')" || {
  echo "[$(stamp)] commit failed"
  exit 6
}
echo "[$(stamp)] committed $(git rev-parse --short HEAD)"

# The gate. Not `if a remote exists` -- that would mean the act of adding a
# remote silently turns an unattended publisher on, which is exactly the
# surprise this repo cannot afford once it is public.
if [ "${CYBERWATCH_PUBLISH:-0}" != "1" ]; then
  echo "[$(stamp)] publishing is off (CYBERWATCH_PUBLISH is not 1) -- commit is local only"
  exit 0
fi

if ! git remote | grep -q .; then
  echo "[$(stamp)] CYBERWATCH_PUBLISH=1 but no git remote is configured -- nothing pushed"
  exit 8
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
if git push origin "$branch"; then
  echo "[$(stamp)] pushed $branch"
else
  echo "[$(stamp)] push failed -- the commit is local, publish it by hand"
  exit 7
fi
