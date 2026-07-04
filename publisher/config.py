import os
from datetime import date

# Public site repo — separate from advisory-engine (build brief Section 3:
# publisher is the only one-way export path, db-01 never reachable from
# GitHub). Auth token (GITHUB_PUSH_TOKEN) comes from the environment only,
# via publisher/remote.py — never hardcoded, never logged.
PUBLISH_REPO_HOST_PATH = "dunga101/advisory-site"
PUBLISH_REPO_BRANCH = "main"

GIT_COMMIT_AUTHOR_NAME = "advisory-engine publisher"
GIT_COMMIT_AUTHOR_EMAIL = "publisher@advisory-engine.local"

# Homepage "recent verdicts" list length.
RECENT_VERDICTS_LIMIT = 20

# --- Monitoring (architecture review item 3) ---

# GITHUB_PUSH_TOKEN's actual expiry date, set when the token was issued.
# This is intentionally hardcoded, not read from GitHub's API — update
# this constant whenever the token is rotated. Checked at the start of
# every publisher run; see publisher/monitoring.py.
TOKEN_EXPIRES = date(2026, 9, 29)
TOKEN_EXPIRY_WARN_DAYS = 30
TOKEN_EXPIRY_URGENT_DAYS = 7

# Uptime Kuma push-monitor URL, e.g. http://192.168.4.130:3001/api/push/<id>.
# Pinged at the end of every run_publisher_job (success or failure). None
# (unset) disables the ping with a logged warning rather than failing the
# run — monitoring must never be able to break publishing.
UPTIME_KUMA_PUSH_URL = os.environ.get("UPTIME_KUMA_PUSH_URL") or None

# Live site's machine-readable freshness endpoint (see status.json written
# by publisher/render.py). None (unset) disables the freshness check with
# a logged warning — the real site domain isn't hardcoded here since it's
# operator-specific and not otherwise recorded anywhere in this repo.
SITE_STATUS_URL = os.environ.get("SITE_STATUS_URL") or None

# How stale the live site's generated_at is allowed to get (daily 04:00
# schedule + buffer) before the freshness check alerts.
FRESHNESS_THRESHOLD_HOURS = 26
