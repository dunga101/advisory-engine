"""Architecture review item 5: KEV never detected a CVE removed from the
current KEV feed while kev_listed=True in the DB. run_once now diffs the
DB's currently-listed set against each pull's cveID set and flips
anything missing back to kev_listed=False, logging the change and
reopening review on any advisory linked to that CVE.
"""
from unittest.mock import patch

from collectors.sources.kev import run_once
from common.models import Advisory, AdvisoryCve, Cve, CveRevisionHistory

KEV_ENTRY = {
    "cveID": "CVE-2026-11111",
    "dateAdded": "2026-06-01",
    "knownRansomwareCampaignUse": "Unknown",
    "shortDescription": "Test vuln",
    "cwes": ["CWE-79"],
}


def _fake_feed(entries):
    return patch("collectors.sources.kev.fetch_kev_feed", return_value=entries)


def test_cve_absent_from_feed_is_flipped_to_unlisted(session):
    with _fake_feed([KEV_ENTRY]):
        run_once(session)
    session.commit()

    with _fake_feed([{**KEV_ENTRY, "cveID": "CVE-2026-22222"}]):
        summary = run_once(session)
    session.commit()

    cve = session.get(Cve, "CVE-2026-11111")
    assert cve.kev_listed is False
    assert summary["unlisted"] == 1

    revisions = (
        session.query(CveRevisionHistory)
        .filter_by(cve_id="CVE-2026-11111", field_changed="kev_listed")
        .all()
    )
    assert any(r.old_value == "True" and r.new_value == "False" for r in revisions)


def test_cve_still_present_in_feed_stays_listed(session):
    with _fake_feed([KEV_ENTRY]):
        run_once(session)
    session.commit()

    with _fake_feed([KEV_ENTRY]):
        summary = run_once(session)
    session.commit()

    cve = session.get(Cve, "CVE-2026-11111")
    assert cve.kev_listed is True
    assert summary["unlisted"] == 0


def test_empty_feed_response_skips_unlisting_entirely(session):
    """A single bad/empty fetch must never mass-delist the whole catalog —
    KEV always fetches the full current feed, so zero entries means the
    fetch broke, not that CISA actually emptied the catalog."""
    with _fake_feed([KEV_ENTRY]):
        run_once(session)
    session.commit()

    with _fake_feed([]):
        summary = run_once(session)
    session.commit()

    cve = session.get(Cve, "CVE-2026-11111")
    assert cve.kev_listed is True
    assert summary["unlisted"] == 0
    assert summary["feed_entry_count"] == 0


def test_unlisting_reopens_review_gate_on_linked_advisory(session):
    with _fake_feed([KEV_ENTRY]):
        run_once(session)
    session.commit()

    advisory = Advisory(
        source_vendor="microsoft",
        source_advisory_id="TEST-ADV-1",
        publish_status="published",
        verification_status="approved",
    )
    session.add(advisory)
    session.flush()
    session.add(AdvisoryCve(advisory_id=advisory.id, cve_id="CVE-2026-11111"))
    session.commit()

    with _fake_feed([{**KEV_ENTRY, "cveID": "CVE-2026-22222"}]):
        run_once(session)
    session.commit()

    session.refresh(advisory)
    assert advisory.publish_status == "blocked_pending_review"
    assert advisory.verification_status == "pending"
