"""Regression tests for architecture review item 4's gating fields, as
applied to the Fortinet collector specifically: fortinet.py used to be
the odd one out among the three collectors — its Cve upsert never passed
cve_gate_hook (so a CVSS/kev_listed change on a Fortinet-sourced CVE
never reopened review), and a new product/version link never called
reopen_review_gate at all (unlike cisco.py's equivalent code path).
"""
from lxml import etree

from collectors.sources.fortinet import _process_advisory
from common.models import Advisory

DOC_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<cvrf:cvrfdoc xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf">
    <cvrf:DocumentTitle>Test advisory</cvrf:DocumentTitle>
    <cvrf:DocumentTracking>
        <cvrf:InitialReleaseDate>2026-06-01T00:00:00</cvrf:InitialReleaseDate>
        <cvrf:CurrentReleaseDate>2026-06-01T00:00:00</cvrf:CurrentReleaseDate>
    </cvrf:DocumentTracking>
    <cvrf:DocumentNotes>
        <cvrf:Note Title="Summary" Type="Summary" Ordinal="1">Test summary.</cvrf:Note>
    </cvrf:DocumentNotes>
    <ProductTree>
        <Branch Name="Fortinet" Type="Vendor">
            <Branch Name="FortiOS" Type="Product Name">
                <Branch Name="7.6.0" Type="Product Version">
                    <FullProductName ProductID="FortiOS-7.6.0">FortiOS 7.6.0</FullProductName>
                </Branch>
                <Branch Name="7.4.7" Type="Product Version">
                    <FullProductName ProductID="FortiOS-7.4.7">FortiOS 7.4.7</FullProductName>
                </Branch>
            </Branch>
        </Branch>
    </ProductTree>
    <Vulnerability Ordinal="1">
        <Title>Test vuln</Title>
        <cvrf:CVE>CVE-2026-11111</cvrf:CVE>
        <ProductStatuses>
            <Status Type="Known Affected">
                <ProductID>FortiOS-7.6.0</ProductID>
                {extra_product_status}
            </Status>
        </ProductStatuses>
        <CVSSScoreSets>
            <ScoreSetV3>
                <BaseScoreV3>{score}</BaseScoreV3>
                <VectorV3>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N</VectorV3>
            </ScoreSetV3>
        </CVSSScoreSets>
    </Vulnerability>
</cvrf:cvrfdoc>
"""


def _doc(score: str, extra_product: bool = False) -> etree._Element:
    extra = "<ProductID>FortiOS-7.4.7</ProductID>" if extra_product else ""
    xml = DOC_TEMPLATE.format(score=score, extra_product_status=extra)
    return etree.fromstring(xml.encode())


def _publish_and_approve(advisory: Advisory) -> None:
    advisory.publish_status = "published"
    advisory.verification_status = "approved"


def test_cvss_jump_on_fortinet_cve_reopens_review_gate(session):
    _process_advisory(session, _doc(score="3.9"), "FG-IR-TEST-1")
    session.commit()

    advisory = session.query(Advisory).filter_by(source_advisory_id="FG-IR-TEST-1").one()
    _publish_and_approve(advisory)
    session.commit()

    _process_advisory(session, _doc(score="8.5"), "FG-IR-TEST-1")
    session.commit()

    session.refresh(advisory)
    assert advisory.publish_status == "blocked_pending_review"
    assert advisory.verification_status == "pending"


def test_small_cvss_move_on_fortinet_cve_does_not_reopen_gate(session):
    """Same gating threshold as every other collector (CVSS_GATING_DELTA)
    — routine cross-source noise must not flag."""
    _process_advisory(session, _doc(score="3.9"), "FG-IR-TEST-2")
    session.commit()

    advisory = session.query(Advisory).filter_by(source_advisory_id="FG-IR-TEST-2").one()
    _publish_and_approve(advisory)
    session.commit()

    _process_advisory(session, _doc(score="3.95"), "FG-IR-TEST-2")
    session.commit()

    session.refresh(advisory)
    assert advisory.publish_status == "published"
    assert advisory.verification_status == "approved"


def test_new_product_version_link_reopens_review_gate(session):
    _process_advisory(session, _doc(score="3.9", extra_product=False), "FG-IR-TEST-3")
    session.commit()

    advisory = session.query(Advisory).filter_by(source_advisory_id="FG-IR-TEST-3").one()
    _publish_and_approve(advisory)
    session.commit()

    _process_advisory(session, _doc(score="3.9", extra_product=True), "FG-IR-TEST-3")
    session.commit()

    session.refresh(advisory)
    assert advisory.publish_status == "blocked_pending_review"
    assert advisory.verification_status == "pending"


def test_unchanged_reprocessing_does_not_reopen_gate(session):
    _process_advisory(session, _doc(score="3.9"), "FG-IR-TEST-4")
    session.commit()

    advisory = session.query(Advisory).filter_by(source_advisory_id="FG-IR-TEST-4").one()
    _publish_and_approve(advisory)
    session.commit()

    _process_advisory(session, _doc(score="3.9"), "FG-IR-TEST-4")
    session.commit()

    session.refresh(advisory)
    assert advisory.publish_status == "published"
    assert advisory.verification_status == "approved"
