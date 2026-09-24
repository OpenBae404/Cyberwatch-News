#!/bin/bash
# The daily CyberWatch run, as launchd invokes it.
#
#   1. build today's issue   (run.py, writes issues/YYYY-MM-DD.md)
#   2. regenerate the site   (build_site.py, writes docs/)
#   3. commit, then ASK A HUMAN and push only if they approve
#
# Deliberately not a python script: the interesting failure modes here are
# process-level (a feed outage exiting 2, nothing to commit, no remote yet) and
# that is what a shell reads naturally.
#
# PUSHING REQUIRES A PERSON, every morning. The gate used to be
# CYBERWATCH_PUBLISH=1 in the plist, which is a decision made once and then
# never revisited: after the day it was set, every issue publishes unreviewed,
# which is the thing the gate existed to prevent. So the gate is now a request
# the operator answers per run:
#
#   approve-gate "<action>" --ttl N --requester X --detail Y
#
# It posts the request to Telegram, blocks until Approve or Deny is tapped, and
# exits 0 approved, 1 denied or expired. It is NOT part of this repo -- it lives
# in ~/.local/bin on the author's machine. When it is absent, which is the case
# for anybody else who clones this, the run builds, rebuilds and commits exactly
# as before and simply does not push; there is no configuration that turns
# unattended publishing on, because the fallback for a missing approver is
# "publish nothing", never "publish anyway".
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
#   7 the operator approved and the push failed
#   8 the approver is available but there is no remote to push to
#
# A denied or expired approval, and an absent approver, are both exit 0: the
# issue is written and committed, which is the run succeeding. Only the push
# did not happen, and `git push origin master` by hand finishes it.

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

# The same identity as every hand-made commit. A separate "cyberwatch-daily
# <...@localhost>" author would publish a second, broken-looking address into
# the history of a public repo -- exactly the metadata this repo's history was
# rewritten to remove. That an issue is machine-written is already stated on
# the page itself; the commit author does not need to repeat it.
git -c user.name="OpenBae404" \
    -c user.email="OpenBae404@users.noreply.github.com" \
    commit --quiet -m "Publish issue $(date -u '+%Y-%m-%d')" || {
  echo "[$(stamp)] commit failed"
  exit 6
}
echo "[$(stamp)] committed $(git rev-parse --short HEAD)"

# The gate. Not an environment variable, and not `if a remote exists`: both are
# decisions taken once, long before the issue they publish exists. This asks
# about THIS issue, and asks the person whose name is on the site.
#
# Three ways not to push, all of them exit 0, because the run itself succeeded:
# no approver installed, the operator denied, the request expired unanswered.
#
# The approver is looked up on PATH by name, with no environment variable to
# redirect it. A CYBERWATCH_APPROVER=/bin/true would be the env gate this card
# removed, wearing a different name.
if ! command -v approve-gate >/dev/null 2>&1; then
  echo "[$(stamp)] no approve-gate on PATH -- nothing was asked and nothing pushed; the commit is local"
  exit 0
fi

if ! git remote | grep -q .; then
  echo "[$(stamp)] no git remote is configured -- not asking for an approval that could not be acted on"
  exit 8
fi

# What the operator is shown. An approval request that says only "push?" trains
# the reader to tap Approve, so the detail names the CVEs in the issue being
# published and the page they will appear on.
issue_files="$(git show --name-only --format= HEAD | grep '^issues/.*\.md$')"
cves="$(printf '%s\n' "$issue_files" \
  | while IFS= read -r f; do [ -n "$f" ] && git show "HEAD:$f"; done \
  | grep -Eo 'CVE-[0-9]{4}-[0-9]{4,7}' | sort -u | paste -sd ', ' -)"
[ -n "$cves" ] || cves="no CVE id found in the commit"
today="$(date -u '+%Y-%m-%d')"
detail="$(printf '%s\n%s\n%s\n%s' \
  "commit $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)" \
  "issue file(s): $(printf '%s' "$issue_files" | paste -sd ' ' -)" \
  "CVEs: $cves" \
  "goes live at https://cyberwatch.asutera.dev/")"

echo "[$(stamp)] asking for approval to publish"
if approve-gate "Publish CyberWatch issue $today" \
     --ttl "${CYBERWATCH_APPROVAL_TTL:-21600}" \
     --requester cyberwatch-daily \
     --detail "$detail"; then
  echo "[$(stamp)] approved"
else
  echo "[$(stamp)] not approved (denied or expired) -- the commit is local only, publish it by hand if that was wrong"
  exit 0
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
if git push origin "$branch"; then
  echo "[$(stamp)] pushed $branch"
else
  echo "[$(stamp)] push failed -- the commit is local, publish it by hand"
  exit 7
fi
