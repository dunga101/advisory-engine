-- Architecture review item 2 (secret isolation): review-app (the one
-- LAN-exposed service, :8080) and publisher currently connect with the
-- same full-privilege `advisory_engine` role collectors uses -- a
-- compromise of either would read/write everything collectors can,
-- including tables it never touches.
--
-- This creates two additional, narrowly-scoped roles. `advisory_engine`
-- itself is untouched and stays collectors-only.
--
-- Run once, manually, as a Postgres superuser against db-01
-- (192.168.4.124), database `advisory_engine`:
--   psql "postgresql://<superuser>@192.168.4.124:5432/advisory_engine" \
--        -f db/sql/001_create_service_roles.sql
--
-- Before running: replace the two <...DB_PASSWORD> placeholders below
-- with the real values from the vault --
--   ansible-vault view --vault-password-file ansible/.vault_pass.txt ansible/vault/secrets.yml
-- -- (database_url_publisher / database_url_review). Never commit the
-- real passwords in this file -- that's the exact class of leak this
-- item exists to close.
--
-- If a password is ever rotated: ALTER ROLE ... WITH PASSWORD '...' here,
-- update the matching vault key, then re-run scripts/render_env.py.

-- publisher: read-only. publisher/data.py (gather_published_advisories)
-- only ever SELECTs -- it builds the static site from already-published
-- rows and never writes to the database.
CREATE ROLE advisory_publisher WITH LOGIN PASSWORD '<PUBLISHER_DB_PASSWORD>';
GRANT CONNECT ON DATABASE advisory_engine TO advisory_publisher;
GRANT USAGE ON SCHEMA public TO advisory_publisher;
GRANT SELECT ON
    advisories,
    advisory_cve,
    advisory_guidance,
    advisory_revision_history,
    cves,
    cve_revision_history,
    products,
    advisory_product_affected,
    windows_updates,
    patch_verdict_history,
    field_reports,
    platform_reliability_notes
TO advisory_publisher;

-- review-app (review_cli.py today; the future FastAPI review-app):
-- read/write only on the tables a human reviewer actually
-- approves/rejects/flags through. Read-only on every reference table it
-- displays for context (CVE/CVSS/KEV facts, product/KB/verdict info) --
-- it never needs to mutate data collectors own.
CREATE ROLE advisory_review WITH LOGIN PASSWORD '<REVIEW_DB_PASSWORD>';
GRANT CONNECT ON DATABASE advisory_engine TO advisory_review;
GRANT USAGE ON SCHEMA public TO advisory_review;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    advisories,
    advisory_cve,
    advisory_guidance,
    advisory_revision_history
TO advisory_review;
GRANT SELECT ON
    cves,
    cve_revision_history,
    products,
    advisory_product_affected,
    windows_updates,
    patch_verdict_history,
    field_reports,
    platform_reliability_notes
TO advisory_review;
-- Integer/BigInteger primary_key=True columns are backed by an implicit
-- Postgres sequence (<table>_id_seq) -- INSERT needs USAGE on it, not
-- just table-level INSERT.
GRANT USAGE, SELECT ON
    advisories_id_seq,
    advisory_guidance_id_seq,
    advisory_revision_history_id_seq
TO advisory_review;
