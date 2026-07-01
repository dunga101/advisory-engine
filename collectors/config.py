# Verdict rubric constant (Section 6 of the build brief). KEV-listed/actively
# exploited always bypasses this and gets deploy_now regardless.
WAIT_DAYS = 7

# Field report source weight for the verdict engine's "wait" duration estimate
# (Section 6: "duration scaled to source weight and report count"). Ordering
# matches Section 5's stated source weight: microsoft_release_health > vendor_kb
# > community.
SOURCE_WEIGHT = {
    "microsoft_release_health": 3,
    "vendor_kb": 2,
    "community": 1,
}

# Cisco PSIRT openVuln API v2 rate limits (build brief Section 4) — a hard
# API constraint, not a tunable preference. Verify against Cisco's docs
# before changing.
CISCO_MAX_REQUESTS_PER_SECOND = 5
CISCO_MAX_REQUESTS_PER_MINUTE = 30
CISCO_MAX_REQUESTS_PER_DAY = 5000

# Matches MSRC's 90-day backfill window (build brief Section 11: "90-day
# backfill for Cisco/MSRC on first run").
CISCO_BACKFILL_DAYS = 90

# Fortinet PSIRT RSS feed only ever returns ~50 most-recent entries (no
# date-range query param like Cisco/MSRC), so this just bounds the initial
# backfill / guards against re-ingesting an advisory whose RSS `published`
# date happens to be old — see fortinet.py's module docstring for why that
# date field is an imperfect staleness signal in the first place.
FORTINET_BACKFILL_DAYS = 90

# Phase 4 review gate (migration 0011). True: an advisory's raw structured
# facts that pass every pre-check validation auto-publish immediately —
# the build brief's original stance that vendor-sourced facts don't need a
# human gate, only AI narratives do (advisory_guidance.verification_status
# stays a real manual gate regardless of this flag). False: passing items
# stay draft/pending instead of publishing, for a fully-manual workflow if
# this ever needs tightening back. Items that fail pre-check always land
# in blocked_pending_review no matter what this is set to.
PRECHECK_AUTO_APPROVE = True
