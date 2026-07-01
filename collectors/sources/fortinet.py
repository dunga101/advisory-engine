"""Fortinet PSIRT collector: public RSS feed (build brief Section 4, no
auth) for advisory discovery, CVRF XML per advisory for structured facts.

No HTML page fetch is needed — the CVRF URL is directly derivable from the
RSS entry's own link (".../psirt/{ir_id}" -> ".../psirt/cvrf/{ir_id}"),
confirmed live against 4 real advisories (2026-07-01 probe).

CVE-ID discovery is a union of three methods, since the structured
<cvrf:CVE> element alone was observed to miss a second CVE on a chained
multi-CVE advisory (FG-IR-26-144: CVE-2026-43284 chained with
CVE-2026-43500, only the first captured structurally):
  1. the structured <cvrf:CVE> element (primary)
  2. nvd.nist.gov/vuln/detail/CVE-... links within the Vulnerability's own
     <References>
  3. CVE-shaped text found in the document's free-text Summary note
All three are best-effort discovery — validated against 4 real advisories
(1 known multi-CVE, 3 single-CVE) with zero false positives, not proven
exhaustive. Every discovered ID still has to pass is_valid_cve_id() before
touching the DB, same final gate as Cisco/MSRC.

The RSS feed's `published` date does not update when Fortinet later
revises an advisory ("Revised on <date>" only appears as free text inside
the HTML-formatted RSS summary, there is no separate `updated` field) — so
the backfill-window filter below can in principle miss a substantively
revised but originally-old advisory. Accepted tradeoff, same category as
Cisco's missing fixed_version.

fixed_version is left None throughout — Fortinet's CVRF has no
remediation/fixed-version field at all (only the HTML page's "Solution"
column does, and this collector deliberately doesn't fetch HTML pages).
"""

import logging
import re
from datetime import date, datetime, timedelta, timezone

import feedparser
import requests
from lxml import etree
from sqlalchemy import select

from collectors.config import FORTINET_BACKFILL_DAYS
from collectors.sources.base import is_valid_cve_id, upsert_and_diff, upsert_by_lookup
from common.db import get_session_factory
from common.models import (
    Advisory,
    AdvisoryCve,
    AdvisoryProductAffected,
    Cve,
    CveRevisionHistory,
    Product,
)

RSS_URL = "https://www.fortiguard.com/rss/ir.xml"
RSS_FALLBACK_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
CVRF_URL_TEMPLATE = "https://fortiguard.fortinet.com/psirt/cvrf/{ir_id}"
ADVISORY_URL_TEMPLATE = "https://fortiguard.fortinet.com/psirt/{ir_id}"

CWE_PATTERN = re.compile(r"\[CWE-(\d+)\]")
NVD_CVE_PATTERN = re.compile(r"nvd\.nist\.gov/vuln/detail/(CVE-\d{4}-\d{4,})")
CVE_TEXT_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

logger = logging.getLogger(__name__)


# --- lxml helpers: Fortinet's CVRF mixes cvrf:-prefixed elements
# (DocumentTitle, CVE, ...) with unprefixed ones (Vulnerability, Title,
# ProductTree, ...) in the same document. Matching by localname only,
# ignoring namespace, sidesteps that inconsistency — there's no localname
# collision between the two groups in practice. ---


def _local(elem) -> str:
    return etree.QName(elem).localname


def _children_local(elem, name: str) -> list:
    return [child for child in elem if _local(child) == name]


def _find_local(elem, name: str):
    children = _children_local(elem, name)
    return children[0] if children else None


def _text_local(elem, name: str) -> str | None:
    found = _find_local(elem, name)
    return found.text if found is not None and found.text else None


def fetch_feed() -> list:
    """Fetch the PSIRT RSS feed, falling back to the mirror if the primary
    is unreachable or fails to parse. Confirmed live 2026-07-01 — both
    serve the same feed format."""
    for url in (RSS_URL, RSS_FALLBACK_URL):
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.info("Fortinet RSS feed %s unreachable: %s", url, exc)
            continue
        feed = feedparser.parse(response.content)
        if feed.bozo:
            logger.info("Fortinet RSS feed %s failed to parse: %s", url, feed.bozo_exception)
            continue
        return feed.entries
    raise RuntimeError("Both Fortinet RSS feed URLs failed or were unparseable")


def fetch_cvrf(ir_id: str) -> bytes:
    response = requests.get(CVRF_URL_TEMPLATE.format(ir_id=ir_id), timeout=30)
    response.raise_for_status()
    return response.content


def _ir_id_from_link(link: str) -> str:
    return link.rstrip("/").rsplit("/", 1)[-1]


def _within_backfill_window(entry, now: datetime) -> bool:
    published_parsed = entry.get("published_parsed")
    if not published_parsed:
        return False
    published_dt = datetime(*published_parsed[:6], tzinfo=timezone.utc)
    return published_dt >= now - timedelta(days=FORTINET_BACKFILL_DAYS)


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    return datetime.fromisoformat(value).date()


def _document_summary_note(root) -> str:
    notes = _find_local(root, "DocumentNotes")
    if notes is None:
        return ""
    for note in _children_local(notes, "Note"):
        if note.get("Title") == "Summary":
            return note.text or ""
    return ""


def _extract_cwe(summary_text: str) -> str | None:
    match = CWE_PATTERN.search(summary_text)
    return f"CWE-{match.group(1)}" if match else None


def _cvss_from_vulnerability(vuln) -> tuple[float | None, str | None]:
    score_sets = _find_local(vuln, "CVSSScoreSets")
    if score_sets is None:
        return None, None
    score_set_v3 = _find_local(score_sets, "ScoreSetV3")
    if score_set_v3 is None:
        return None, None
    score_text = _text_local(score_set_v3, "BaseScoreV3")
    vector_text = _text_local(score_set_v3, "VectorV3")
    return (float(score_text) if score_text else None), vector_text


def _discover_cve_ids(vuln, document_summary_text: str) -> list[str]:
    """Union of the three discovery methods described in the module
    docstring. Assumes one <Vulnerability> block per document — every
    live-tested advisory has exactly one; if Fortinet ever ships a
    multi-vulnerability document this document-level text scan would need
    to be re-scoped per block instead of applied to all of them."""
    candidates: list[str] = []

    cve_elem = None
    for child in vuln:
        if _local(child) == "CVE":
            cve_elem = child
            break
    if cve_elem is not None and cve_elem.text:
        candidates.append(cve_elem.text.strip())

    references = _find_local(vuln, "References")
    if references is not None:
        for ref in _children_local(references, "Reference"):
            url_text = _text_local(ref, "URL") or ""
            candidates.extend(NVD_CVE_PATTERN.findall(url_text))

    candidates.extend(CVE_TEXT_PATTERN.findall(document_summary_text))

    return sorted(set(candidates))


def _walk_product_tree(branch, product_name: str | None = None, out: dict | None = None) -> dict:
    """Flatten ProductTree into {ProductID: (product_name, version)}.
    Fortinet nests Vendor > Product Name > Product Version >
    FullProductName; the "Product Version" branch's own Name IS the
    affected version string."""
    if out is None:
        out = {}
    branch_type = branch.get("Type")
    branch_name = branch.get("Name")
    current_product_name = branch_name if branch_type == "Product Name" else product_name
    current_version = branch_name if branch_type == "Product Version" else None

    for child in branch:
        tag = _local(child)
        if tag == "Branch":
            _walk_product_tree(child, current_product_name, out)
        elif tag == "FullProductName":
            product_id = child.get("ProductID")
            if product_id:
                out[product_id] = (current_product_name, current_version)
    return out


def _normalize_advisory(root, ir_id: str) -> dict:
    tracking = _find_local(root, "DocumentTracking")
    initial_release = _text_local(tracking, "InitialReleaseDate") if tracking is not None else None
    current_release = _text_local(tracking, "CurrentReleaseDate") if tracking is not None else None
    return {
        "title": _text_local(root, "DocumentTitle"),
        "published_date": _parse_date(initial_release),
        "last_updated_date": _parse_date(current_release),
        "source_url": ADVISORY_URL_TEMPLATE.format(ir_id=ir_id),
    }


def _normalize_cve_fields(vuln, summary_text: str) -> dict:
    """Never includes kev_listed/kev_date_added/kev_ransomware_use — CISA
    KEV is the sole source of truth for exploited-status. All CVEs
    discovered within one Vulnerability block share this CVSS/CWE data —
    Fortinet's CVRF has no way to distinguish per-CVE scoring when
    multiple CVEs are chained/scored together under one block."""
    cvss_score, cvss_vector = _cvss_from_vulnerability(vuln)
    return {
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_id": _extract_cwe(summary_text),
        "description_raw": summary_text.strip() or None,
    }


def _process_advisory(session, root, ir_id: str) -> tuple[int, int, int]:
    """Upsert one advisory plus its CVEs and products. Raises on any
    mapping/write failure — run_once catches it, rolls back just this
    advisory's uncommitted work, and moves on, rather than losing every
    advisory already committed this run."""
    cves_inserted = 0
    cves_updated = 0
    products_upserted = 0

    upsert_by_lookup(
        session,
        model_cls=Advisory,
        lookup={"source_vendor": "fortinet", "source_advisory_id": ir_id},
        fields=_normalize_advisory(root, ir_id),
    )
    session.flush()
    advisory = session.execute(
        select(Advisory).filter_by(source_vendor="fortinet", source_advisory_id=ir_id)
    ).scalar_one()

    product_tree = _find_local(root, "ProductTree")
    product_map: dict = {}
    if product_tree is not None:
        for vendor_branch in _children_local(product_tree, "Branch"):
            product_map.update(_walk_product_tree(vendor_branch))

    summary_text = _document_summary_note(root)

    for vuln in _children_local(root, "Vulnerability"):
        cve_fields = _normalize_cve_fields(vuln, summary_text)
        cve_ids = [cve_id for cve_id in _discover_cve_ids(vuln, summary_text) if is_valid_cve_id(cve_id)]

        for cve_id in cve_ids:
            diff_result = upsert_and_diff(
                session,
                model_cls=Cve,
                revision_cls=CveRevisionHistory,
                pk_column="cve_id",
                revision_fk_column="cve_id",
                pk_value=cve_id,
                fields=cve_fields,
            )
            if diff_result.inserted:
                cves_inserted += 1
            elif diff_result.changed_fields:
                cves_updated += 1

            if session.get(AdvisoryCve, (advisory.id, cve_id)) is None:
                session.add(AdvisoryCve(advisory_id=advisory.id, cve_id=cve_id))

        product_statuses = _find_local(vuln, "ProductStatuses")
        if product_statuses is None:
            continue
        for status in _children_local(product_statuses, "Status"):
            if status.get("Type") != "Known Affected":
                continue
            for product_id_elem in _children_local(status, "ProductID"):
                product_id = (product_id_elem.text or "").strip()
                product_name, version = product_map.get(product_id, (None, None))
                if not product_name:
                    continue

                upsert_by_lookup(
                    session,
                    model_cls=Product,
                    lookup={"vendor": "Fortinet", "product_name": product_name},
                    fields={},
                )
                session.flush()
                product = session.execute(
                    select(Product).filter_by(vendor="Fortinet", product_name=product_name)
                ).scalar_one()

                upsert_by_lookup(
                    session,
                    model_cls=AdvisoryProductAffected,
                    lookup={
                        "advisory_id": advisory.id,
                        "product_id": product.id,
                        "affected_version_range": version,
                    },
                    fields={"fixed_version": None},
                )
                products_upserted += 1

    return cves_inserted, cves_updated, products_upserted


def run_once(session=None) -> dict:
    """Fetch the PSIRT RSS feed, filter to the backfill window, fetch each
    advisory's CVRF XML directly (no HTML page fetch), and upsert into
    advisories/advisory_cve/cves/advisory_product_affected. Never touches
    windows_updates — Fortinet advisories use the generic
    advisory_product_affected model, same as Cisco.

    Commits per advisory rather than once at the end, same resilience
    pattern as cisco.py: one advisory with an unexpected shape must not
    roll back every other advisory already processed this run."""
    owns_session = session is None
    session = session or get_session_factory()()

    advisories_upserted = 0
    cves_inserted = 0
    cves_updated = 0
    products_upserted = 0
    skipped_advisories: list[dict] = []

    try:
        entries = fetch_feed()
        now = datetime.now(timezone.utc)
        candidates = [entry for entry in entries if _within_backfill_window(entry, now)]

        for entry in candidates:
            link = entry.get("link")
            if not link:
                skipped_advisories.append({"ir_id": None, "reason": "RSS entry missing link"})
                continue
            ir_id = _ir_id_from_link(link)

            try:
                raw_cvrf = fetch_cvrf(ir_id)
                root = etree.fromstring(raw_cvrf)
                entry_cves_inserted, entry_cves_updated, entry_products_upserted = (
                    _process_advisory(session, root, ir_id)
                )
                session.commit()
            except Exception as exc:
                session.rollback()
                logger.exception("Skipping Fortinet advisory %s — failed to fetch/map/write", ir_id)
                skipped_advisories.append(
                    {"ir_id": ir_id, "reason": f"{type(exc).__name__}: {exc}"}
                )
                continue

            advisories_upserted += 1
            cves_inserted += entry_cves_inserted
            cves_updated += entry_cves_updated
            products_upserted += entry_products_upserted

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

    summary = {
        "advisories_upserted": advisories_upserted,
        "cves_inserted": cves_inserted,
        "cves_updated": cves_updated,
        "products_upserted": products_upserted,
        "skipped_advisories": skipped_advisories,
    }
    logger.info("Fortinet collector run complete: %s", summary)
    return summary
