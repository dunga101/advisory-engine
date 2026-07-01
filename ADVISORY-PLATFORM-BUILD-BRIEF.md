Security Advisory Platform — Build Brief

Project: advisory-engine

Repo: https://github.com/dunga101/advisory-engine

Host: security-02 @ 192.168.4.130


CLAUDE CODE STARTING PROMPT

Paste this into the Claude Code session on security-02 to begin:

I am building a security advisory platform called advisory-engine.
Read ADVISORY-PLATFORM-BUILD-BRIEF.md in full before doing anything else.

Infrastructure:
- This host (security-02): 192.168.4.130, Ubuntu Server 24.04 LTS,
  4 vCPU / 6 GB RAM. Wazuh agent, Grafana Alloy, qemu-guest-agent,
  and PBS backup are already installed and configured.
  Skip VM provisioning entirely — we are already on the target host.
- Database: db-01 at 192.168.4.124, Postgres + TimescaleDB already running.
- File server: fileserver-01 at 192.168.4.111
- All hosts are on a flat 192.168.4.x/22 LAN. No host is publicly reachable.
- Project lives at: ~/projects/advisory-engine

Today's goal is Phase 1 only, end-to-end:

1. Scaffold the full repo structure per Section 9 phase order
2. Docker Compose with three skeleton services:
   - collectors (Python + APScheduler)
   - review-app (FastAPI, bind LAN-only to 192.168.4.130:8080, never 0.0.0.0)
   - publisher (Python, queries published rows, git-pushes static output)
3. Postgres schema + Alembic migrations on db-01 at 192.168.4.124
   covering ALL tables in Section 5. Use Alembic from day one —
   schema changes must be versioned.
4. KEV collector only:
   - URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
   - No auth required
   - Daily schedule via APScheduler
   - Normalizes into the cves table on db-01
   - Writes to cve_revision_history on any field diff detected on existing rows
   - This is the only collector for today
5. End-to-end verification CLI:
   - Runs KEV collector once manually
   - Confirms rows land in cves table on db-01 at 192.168.4.124
   - Prints row count and any cve_revision_history entries written

Constraints:
- Secrets via Ansible Vault only — never plaintext, never in a committed .env
- Python only for collectors and publisher
- db-01 at 192.168.4.124 is the only database — never expose beyond the LAN
- review-app binds to 192.168.4.130:8080 only, never 0.0.0.0
- Do NOT provision a new VM — we are developing directly on security-02
- Use Plan Mode first: show me the full proposed repo structure and
  Alembic migration plan before writing any code. List every assumption
  you are making and ask me to confirm before proceeding.


1. Project Overview

A standalone, publicly-published security advisory platform for general
sysadmin use. Aggregates vendor security advisories, Patch Tuesday releases,
and exploited-status data into a normalized schema, then publishes plain-English
guidance covering: what an issue means, whether it is actively exploited, who is
affected, how to check exposure manually (platform-specific commands), what to
back up, how to deploy safely, known field issues, rollback procedures, and
post-patch verification steps.

Primary emphasis on Windows Patch Tuesday / Server 2019+ / Windows 10/11 updates,
including an explicit time-stamped "install now vs. wait" verdict with rationale.

2. Explicit Scope Boundaries (non-goals)


NOT Raven. Raven is a private project correlating Wazuh + OpenVAS against the
homelab fleet. Zero data sharing between the two projects. This platform never
checks the user's own environment — every exposure check is a manual,
platform-general command or procedure readable by any sysadmin anywhere.
v1 explicitly excludes: second-model AI cross-check, Telegram/push
notifications, LXC optimization.


3. Infrastructure Map

ComponentHostIPReachable fromTechCollectorssecurity-02192.168.4.130internal onlyPython, DockerReview appsecurity-02192.168.4.130home LAN only (:8080)FastAPI, DockerPublishersecurity-02192.168.4.130internal → GitHub pushPython, DockerDatabasedb-01192.168.4.124internal onlyPostgres + TimescaleDBAI nodeai-nodeTBDinternal onlyGemini APIFile serverfileserver-01192.168.4.111internal onlyshared storagePublic siteCloudflare Pagespublicpublic internetstatic, GH Actions build

Docker Compose on security-02 runs three services: collectors, review-app,
publisher. review-app binds to 192.168.4.130:8080 only — never 0.0.0.0.

db-01 is never reachable from GitHub or the public internet. publisher is the
only one-way export path: queries published rows → writes markdown/JSON files →
git-pushes → triggers GitHub Actions build → Cloudflare Pages deploy.

4. Data Sources

SourceAuthMethodNotesCISA KEVNoneJSON feedSole source of exploited-status truth. Never LLM-inferred.Microsoft MSRCNoneREST API (v3)No key required as of 2025. Free, open.Fortinet PSIRTNoneRSS XML feedhttps://www.fortiguard.com/rss/ir.xml + mirror at https://filestore.fortinet.com/fortiguard/rss/ir.xml. Two-step: RSS discovers new entries, then fetch individual advisory page for structured data. Use feedparser library.Cisco PSIRT openVuln API v2OAuth2REST APIClient ID + Secret via apiconsole.cisco.com. Registered as "advisory-engine", Service type, Client Credentials grant. Rate limits: 5/sec, 30/min. Store credentials in Ansible Vault only.Ubuntu USNNoneRSS/APISeparate collector — confirm format at build time.Debian DSANoneRSS/trackerSeparate collector — confirm format at build time.RHEL errataNoneOVAL/CSAFSeparate collector — confirm format at build time.Community field reportsNoneManual entryLowest-weight source. source_type = community.

Cisco credentials: stored in Ansible Vault as cisco_client_id and
cisco_client_secret. Inject as environment variables at deploy time.

5. Database Schema (db-01 @ 192.168.4.124)

CVE is the atomic unit, not the vendor bulletin. A Patch Tuesday bulletin
may reference 60+ CVEs — advisory rows are wrappers, not the unit of analysis.

cves


cve_id (PK), cvss_score (numeric), cvss_vector (text), cwe_id
kev_listed (bool), kev_date_added (date), kev_ransomware_use (bool)
description_raw (text) — source material, private, never published verbatim


cve_revision_history


id (PK), cve_id (FK → cves), captured_at (timestamptz), field_changed,
old_value (text), new_value (text)
Append-only. Populated automatically whenever ingestion detects a diff
on an existing cves row. KEV entries and CVSS scores are revised after
initial publication — never silently overwrite.


advisories


id (PK), source_vendor, source_advisory_id, title, published_date,
last_updated_date, source_url, severity_vendor
UNIQUE constraint on (source_vendor, source_advisory_id) — dedup key.


advisory_cve


advisory_id (FK → advisories), cve_id (FK → cves)
Junction table: one bulletin → many CVEs; one CVE → many bulletins.


products


id (PK), vendor, product_name, product_family
exposure_check_method (text) — the exact manual command or procedure to
determine if a specific platform is affected. Written once per platform,
reused across every advisory for that platform. Examples:
Windows Server: Get-HotFix / registry build number check
Ubuntu: dpkg -l <package>
Cisco IOS-XE: show version
FortiOS: get system status


advisory_product_affected


advisory_id (FK), product_id (FK), affected_version_range, fixed_version
NOT used for Windows cumulative updates (see windows_updates below).


advisory_guidance


advisory_id (FK → advisories)
plain_english_summary (text)
what_to_backup (text)
deployment_notes (text)
known_issues_after_patch (text)
rollback_procedure (text)
post_patch_verification (text)
publish_status: draft | published | blocked_pending_review
verification_status: ai_drafted | human_verified | rejected
reviewed_by (text), published_at (timestamptz)
precheck_flags (jsonb) — output of automated pre-check run


Publish logic:


Structured-fact-only rows (no guidance needed) → published / human_verified
automatically. No AI, no review gate.
Guidance rows passing ALL pre-checks → published immediately with
ai_drafted badge. Flips to human_verified after human review.
Guidance rows failing ANY pre-check → blocked_pending_review.
Never goes live until a human resolves the flag. This prevents a
fabricated rollback step from ever reaching the public site.


windows_updates


advisory_id (FK), kb_number (text), os_product (text), os_build (text)
update_channel: b_release | c_d_preview | out_of_band
cumulative (bool), non_security_fixes (text[])
supersedes_kb (text), superseded_by_kb (text)
KB chain is the exposure model for Windows — "is this KB or a later
superseding KB installed?" replaces the generic version-range model
which does not fit cumulative updates.


field_reports


id (PK), windows_update_id (FK nullable), advisory_id (FK nullable)
source_type: microsoft_release_health | community | vendor_kb
issue_description (text), affected_configuration (text)
report_date (date)
status: unconfirmed | confirmed | workaround_available | resolved
Source weight: microsoft_release_health > vendor_kb > community


patch_verdict_history


id (PK), windows_update_id (FK), as_of_date (date)
recommendation: deploy_now | pilot_ring | wait
wait_days_estimate (int), rationale (text), field_report_count_at_time (int)
Timescale hypertable on as_of_date. Populated by scheduled daily job only —
never computed ad hoc. New row written only when recommendation changes.


platform_reliability_notes


os_product (PK), notes (text)
Operator's own track record context per platform. Used to inform verdict
rationale. Pre-populate: Windows Server 2019 and 2022 — clean history.


6. Verdict Rubric (Windows Patch Tuesday)

Evaluated daily by a scheduled job. Writes to patch_verdict_history only
on recommendation change.


KEV-listed or actively exploited → deploy_now. Always. No exceptions.
Field reports do not override active exploitation.
No exploitation + zero field reports at release → pilot_ring immediately,
broad rollout after 5 business days (global constant WAIT_DAYS = 5).
No exploitation + field reports present → wait. Duration scaled to
source weight and report count. Re-evaluated daily as reports resolve.
C/D-week optional/preview updates flagged separately from mandatory
B-release cumulative updates. Never recommend broad rollout for previews.


WAIT_DAYS = 5 is a single config constant. KEV always bypasses it.

7. Automated Pre-Check Engine

Runs on every AI-generated advisory_guidance row before it is visible anywhere.
Checks:


Every CVE ID mentioned in the draft exists in advisory_cve for that advisory
kev_listed boolean matches the draft's exploited-status language exactly
CVSS score quoted in the draft matches cves.cvss_score
Affected-version claims match advisory_product_affected rows
Every known_issues_after_patch claim links to a real field_reports row


Pass all → publish_status = published, verification_status = ai_drafted
Fail any → publish_status = blocked_pending_review, precheck_flags populated

8. Review Tooling

Human reviewer checks exactly three things per guidance row:


Does the rollback_procedure look like a real, legitimate mechanism for
this platform? (Not verifying syntax — checking it isn't fabricated)
Does every known_issues_after_patch claim link to a real, verifiable source?
Does the plain_english_summary severity framing match the actual CVSS/KEV data?


CLI queue (sorted KEV-first, then by severity):
[1/N] CVE-XXXX-XXXXX — Windows Server CU — KEV: YES
✓ CVEs verified  ✓ CVSS matches  ✗ known-issue claim unlinked
Draft: "..."
[a]pprove  [e]dit  [r]eject  [s]kip

Approving sets verification_status = human_verified.

Review web app (Phase 11): same checks, browser-based, LAN-only at
192.168.4.130:8080. For reviewing from any device on the home network.

9. Publisher


Queries advisory_guidance WHERE publish_status = published
verification_status is a badge on the page, not a publish gate
Exports to markdown + JSON per advisory
Generates: per-advisory pages, weekly Patch Tuesday digest page
Git-pushes to main → GitHub Actions build → Cloudflare Pages deploy
Pagefind crawls the built static site for search — no separate index step
required as long as pages use semantic HTML


10. Build Phase Order

Phase 1 — TODAY:
1a. Scaffold repo structure (Docker Compose skeleton, directory layout)
1b. Alembic migrations for ALL tables in Section 5 on db-01
1c. KEV collector — ingestion → db-01 → cve_revision_history on diff
1d. Verification CLI — manual run, print row count + revision entries

Phase 2:
2a. MSRC collector (no auth, REST API v3)
2b. windows_updates + field_reports tables populated
2c. Verdict engine (daily job, patch_verdict_history)
2d. Manual guidance entries first — AI layer added after rubric is validated

Phase 3:
3a. Cisco openVuln collector (OAuth2, credentials from Ansible Vault)
3b. Fortinet PSIRT collector (RSS via feedparser, two-step fetch)
3c. Ubuntu USN, Debian DSA, RHEL errata (three separate collectors)

Phase 4:
4a. Automated pre-check engine
4b. CLI review tool

Phase 5:
5a. Publisher service
5b. Static site generator + GitHub Actions workflow
5c. Cloudflare Pages deployment
5d. End-to-end pipeline live on KEV data

Phase 6:
6a. Gemini summarization layer (applied retroactively, behind review gate)

Phase 7:
7a. Review web app (LAN-only, 192.168.4.130:8080)

Phase 8:
8a. Staleness alerting → existing Grafana/Loki stack on monitor-01

11. Resolved Decisions

All settled. Do not re-open without explicit user instruction.


Site content: fully generated from published rows. Per-advisory pages +
weekly Patch Tuesday digest. No hand-curated content.
Secrets: Ansible Vault only. Never plaintext .env committed to repo.
Cisco credentials already registered and ready to vault.
Backfill: full backfill for KEV (one-time, trivial). 90-day backfill
for Cisco/MSRC on first run.
Wait-day default: WAIT_DAYS = 5 business days. Single constant. KEV bypasses.
Postgres backup: nightly pg_dump cron on db-01 to a path covered by
existing PBS target. No WAL/point-in-time — data is mostly re-ingestable.
Repo: github.com/dunga101/advisory-engine, public.
Fortinet: no registration needed. Public RSS feed, no credentials.
MSRC: no registration needed. Public REST API v3, no credentials.
Cisco: registered. Service type, Client Credentials grant, PSIRT API
only selected. Rate limits: 5/sec, 30/min.
Static site generator: Hugo or Astro (Claude Code to recommend based
on template flexibility and Pagefind compatibility — confirm in Plan Mode).
Search: Pagefind, crawls built static output, no separate index service.
LAN review access: home network only (192.168.4.x). No Tailscale or
Cloudflare Tunnel needed for v1.
