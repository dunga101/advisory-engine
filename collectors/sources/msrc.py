import logging
from datetime import date, datetime, timedelta, timezone

import requests
from sqlalchemy import select

from collectors.sources.base import upsert_and_diff, upsert_by_lookup
from common.db import get_session_factory
from common.models import Advisory, AdvisoryCve, Cve, CveRevisionHistory, WindowsUpdate

UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
CVRF_URL_TEMPLATE = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc_id}"
BACKFILL_DAYS = 90

# CVRF enums (verified against a live document): Remediation.Type == 2 is "Vendor
# Fix" (the actual KB), Threat.Type == 3 is the severity rating.
REMEDIATION_TYPE_VENDOR_FIX = 2
THREAT_TYPE_SEVERITY = 3

SEVERITY_RANK = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}

logger = logging.getLogger(__name__)


def _parse_msrc_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _within_backfill_window(doc: dict, now: datetime) -> bool:
    """InitialReleaseDate only. MSRC routinely bumps CurrentReleaseDate on
    documents from decades ago (verified live: 1999-Sep and 2013-Aug both had
    CurrentReleaseDate within the last few months) — checking CurrentReleaseDate
    here would defeat the point of a 90-day window and re-pull most of the
    ~300-month archive on every run."""
    raw = doc.get("InitialReleaseDate")
    if not raw:
        return False
    parsed = _parse_msrc_datetime(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed >= now - timedelta(days=BACKFILL_DAYS)


def _current_and_previous_month_ids(now: datetime) -> list[str]:
    """Doc IDs ("YYYY-Mon") for this calendar month and last. Verified live: the
    /updates list can lag the individual CVRF document endpoint by several
    weeks after Patch Tuesday (2026-Jun was fully fetchable directly while
    entirely absent from a freshly-fetched /updates list) — the most recent
    bulletin is exactly the one an operator cares about most, so it's fetched
    directly rather than trusting list indexing to have caught up."""
    year, month = now.year, now.month
    ids = []
    for _ in range(2):
        ids.append(date(year, month, 1).strftime("%Y-%b"))
        month -= 1
        if month == 0:
            month, year = 12, year - 1
    return ids


def fetch_update_list() -> list[dict]:
    response = requests.get(UPDATES_URL, headers={"Accept": "application/json"}, timeout=30)
    response.raise_for_status()
    return response.json()["value"]


def fetch_cvrf_document(doc_id: str) -> dict:
    url = CVRF_URL_TEMPLATE.format(doc_id=doc_id)
    response = requests.get(url, headers={"Accept": "application/json"}, timeout=60)
    response.raise_for_status()
    return response.json()


def _walk_product_tree(product_tree: dict) -> dict[str, str]:
    """Flatten ProductTree into {ProductID: product name}. Names live both in the
    flat FullProductName list and nested arbitrarily deep under Branch[].Items."""
    products: dict[str, str] = {}
    for entry in product_tree.get("FullProductName", []) or []:
        products[entry["ProductID"]] = entry["Value"]

    def _walk(node):
        if not isinstance(node, dict):
            return
        if "ProductID" in node and "Items" not in node:
            products[node["ProductID"]] = node.get("Value", products.get(node["ProductID"]))
            return
        for item in node.get("Items", []) or []:
            _walk(item)

    for branch in product_tree.get("Branch", []) or []:
        _walk(branch)

    return products


def _is_windows_product(name: str | None) -> bool:
    """True only for genuine Windows OS SKUs (Server 20xx, Windows 10/11 builds),
    not components that merely run "on Windows" (.NET Framework, Edge, Defender,
    Adobe Flash Player) or non-OS artifacts like the Windows 10 HLK (driver
    certification kit, not an installable OS) — all of which would otherwise
    match a bare "windows" substring check and pollute the KB-chain model."""
    if not name:
        return False
    normalized = name.strip().lower()
    if not normalized.startswith("windows"):
        return False
    if "hlk" in normalized:
        return False
    return True


def _normalize_os_product(name: str) -> str:
    """Collapse Server Core install variants into the same os_product as their
    full-GUI counterpart so both upsert into a single windows_updates row."""
    return name.replace(" (Server Core installation)", "").strip()


def _classify_update_channel(release_date: date) -> str:
    """CVRF documents only carry a single per-bulletin date (verified live: the
    per-vulnerability ReleaseDate and per-remediation Date are always unset), so
    every windows_update parsed from one document shares this classification."""
    if release_date.weekday() != 1:  # Tuesday
        return "out_of_band"
    week_of_month = (release_date.day - 1) // 7 + 1
    if week_of_month == 2:
        return "b_release"
    if week_of_month in (3, 4):
        return "c_d_preview"
    return "out_of_band"


def _highest_cvss(score_sets: list[dict]) -> tuple[float | None, str | None]:
    best_score, best_vector = None, None
    for score_set in score_sets or []:
        score = score_set.get("BaseScore")
        if score is None:
            continue
        if best_score is None or score > best_score:
            best_score, best_vector = score, score_set.get("Vector")
    return best_score, best_vector


def _description(notes: list[dict]) -> str | None:
    for note in notes or []:
        if note.get("Title") == "Description":
            return note.get("Value")
    return None


def _highest_severity(vulnerabilities: list[dict]) -> str | None:
    best_label, best_rank = None, -1
    for vuln in vulnerabilities:
        for threat in vuln.get("Threats", []) or []:
            if threat.get("Type") != THREAT_TYPE_SEVERITY:
                continue
            label = (threat.get("Description") or {}).get("Value")
            rank = SEVERITY_RANK.get(label, 0)
            if label and rank > best_rank:
                best_label, best_rank = label, rank
    return best_label


def _normalize_cve(vuln: dict) -> dict:
    """Never includes kev_listed/kev_date_added/kev_ransomware_use — CISA KEV is
    the sole source of truth for exploited-status (build brief Section 4)."""
    cvss_score, cvss_vector = _highest_cvss(vuln.get("CVSSScoreSets"))
    cwes = vuln.get("CWE") or []
    return {
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_id": cwes[0]["ID"] if cwes else None,
        "description_raw": _description(vuln.get("Notes")),
    }


def run_once(session=None) -> dict:
    """Fetch MSRC monthly security bulletins (90-day window) and upsert into
    advisories, advisory_cve, cves, and windows_updates."""
    owns_session = session is None
    session = session or get_session_factory()()

    docs_processed = 0
    cves_inserted = 0
    cves_updated = 0
    advisories_upserted = 0
    windows_updates_upserted = 0

    try:
        now = datetime.now(timezone.utc)
        update_list = fetch_update_list()
        doc_ids = {doc["ID"] for doc in update_list if _within_backfill_window(doc, now)}
        doc_ids |= set(_current_and_previous_month_ids(now))

        for doc_id in sorted(doc_ids):
            try:
                doc = fetch_cvrf_document(doc_id)
            except requests.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 404:
                    logger.info("MSRC document %s not yet published, skipping", doc_id)
                    continue
                raise
            docs_processed += 1

            product_names = _walk_product_tree(doc.get("ProductTree", {}))
            vulnerabilities = doc.get("Vulnerability", [])
            tracking = doc["DocumentTracking"]

            initial_release = _parse_msrc_datetime(tracking["InitialReleaseDate"]).date()
            current_release = _parse_msrc_datetime(tracking["CurrentReleaseDate"]).date()
            update_channel = _classify_update_channel(initial_release)
            severity_vendor = _highest_severity(vulnerabilities)

            upsert_by_lookup(
                session,
                model_cls=Advisory,
                lookup={"source_vendor": "microsoft", "source_advisory_id": doc_id},
                fields={
                    "title": (doc.get("DocumentTitle") or {}).get("Value"),
                    "published_date": initial_release,
                    "last_updated_date": current_release,
                    "source_url": f"https://msrc.microsoft.com/update-guide/releaseNote/{doc_id}",
                    "severity_vendor": severity_vendor,
                },
            )
            advisories_upserted += 1
            session.flush()
            advisory = session.execute(
                select(Advisory).filter_by(source_vendor="microsoft", source_advisory_id=doc_id)
            ).scalar_one()

            for vuln in vulnerabilities:
                cve_id = vuln.get("CVE")
                if not cve_id:
                    continue

                diff_result = upsert_and_diff(
                    session,
                    model_cls=Cve,
                    revision_cls=CveRevisionHistory,
                    pk_column="cve_id",
                    revision_fk_column="cve_id",
                    pk_value=cve_id,
                    fields=_normalize_cve(vuln),
                )
                if diff_result.inserted:
                    cves_inserted += 1
                elif diff_result.changed_fields:
                    cves_updated += 1

                if session.get(AdvisoryCve, (advisory.id, cve_id)) is None:
                    session.add(AdvisoryCve(advisory_id=advisory.id, cve_id=cve_id))

                for remediation in vuln.get("Remediations", []) or []:
                    if remediation.get("Type") != REMEDIATION_TYPE_VENDOR_FIX:
                        continue
                    kb_number = (remediation.get("Description") or {}).get("Value")
                    # Real Microsoft KB article numbers are always digit strings.
                    # Continuously-released products (Windows Admin Center, Windows
                    # App Client) use non-numeric placeholders like "Release Notes"
                    # instead of a KB — not a cumulative update, so skip it.
                    if not kb_number or not kb_number.isdigit():
                        continue

                    for product_id in remediation.get("ProductID", []) or []:
                        product_name = product_names.get(product_id)
                        if not _is_windows_product(product_name):
                            continue

                        os_product = _normalize_os_product(product_name)
                        upsert_by_lookup(
                            session,
                            model_cls=WindowsUpdate,
                            lookup={"kb_number": kb_number, "os_product": os_product},
                            fields={
                                "advisory_id": advisory.id,
                                "os_build": remediation.get("FixedBuild"),
                                "update_channel": update_channel,
                                "cumulative": True,
                                "supersedes_kb": remediation.get("Supercedence") or None,
                            },
                        )
                        windows_updates_upserted += 1

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

    summary = {
        "docs_processed": docs_processed,
        "cves_inserted": cves_inserted,
        "cves_updated": cves_updated,
        "advisories_upserted": advisories_upserted,
        "windows_updates_upserted": windows_updates_upserted,
    }
    logger.info("MSRC collector run complete: %s", summary)
    return summary
