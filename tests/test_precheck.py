from decimal import Decimal

from collectors.precheck import _validate_advisory_facts


class FakeCve:
    def __init__(self, cvss_score=None):
        self.cvss_score = cvss_score


def test_passes_with_valid_facts_and_no_cves():
    """Cisco's notice-only bulletins (zero valid CVEs after
    _extract_valid_cve_ids filters the "NA" sentinel) must not be blocked
    just for having no CVE link."""
    reasons = _validate_advisory_facts(
        title="Cisco Advance Notification for Publication of July 1, 2026, Security Advisories",
        source_url=(
            "https://sec.cloudapps.cisco.com/security/center/content/"
            "CiscoSecurityAdvisory/cisco-sa-notice-vwL7b0S7"
        ),
        cve_lookups=[],
        product_ids_exist=[],
    )
    assert reasons == []


def test_passes_with_valid_cve_and_decimal_score():
    reasons = _validate_advisory_facts(
        title="Some Advisory",
        source_url="https://example.com/advisory",
        cve_lookups=[("CVE-2026-31431", FakeCve(cvss_score=Decimal("7.8")))],
        product_ids_exist=[],
    )
    assert reasons == []


def test_passes_with_null_cvss_score():
    reasons = _validate_advisory_facts(
        title="Some Advisory",
        source_url="https://example.com/advisory",
        cve_lookups=[("CVE-2026-31431", FakeCve(cvss_score=None))],
        product_ids_exist=[],
    )
    assert reasons == []


def test_flags_missing_title():
    reasons = _validate_advisory_facts(
        title=None,
        source_url="https://example.com/advisory",
        cve_lookups=[],
        product_ids_exist=[],
    )
    assert "missing title" in reasons


def test_flags_blank_title():
    reasons = _validate_advisory_facts(
        title="   ",
        source_url="https://example.com/advisory",
        cve_lookups=[],
        product_ids_exist=[],
    )
    assert "missing title" in reasons


def test_flags_missing_source_url():
    reasons = _validate_advisory_facts(
        title="Some Advisory",
        source_url="",
        cve_lookups=[],
        product_ids_exist=[],
    )
    assert "missing source_url" in reasons


def test_flags_malformed_cve_id_slipping_through():
    """Defense in depth: cisco.py/msrc.py already filter these before
    insert, but the gate must not trust that blindly."""
    reasons = _validate_advisory_facts(
        title="Some Advisory",
        source_url="https://example.com/advisory",
        cve_lookups=[("NA", FakeCve())],
        product_ids_exist=[],
    )
    assert any("malformed CVE ID" in r for r in reasons)


def test_flags_orphaned_cve_reference():
    reasons = _validate_advisory_facts(
        title="Some Advisory",
        source_url="https://example.com/advisory",
        cve_lookups=[("CVE-2026-31431", None)],
        product_ids_exist=[],
    )
    assert any("non-existent cve_id" in r for r in reasons)


def test_flags_raw_float_cvss_score_not_decimal():
    """The exact class of bug the Cisco/MSRC diffing fixes targeted — if a
    raw float ever slips into cvss_score, precheck must catch it rather
    than let it reach the reviewer/site."""
    reasons = _validate_advisory_facts(
        title="Some Advisory",
        source_url="https://example.com/advisory",
        cve_lookups=[("CVE-2026-31431", FakeCve(cvss_score=7.5))],
        product_ids_exist=[],
    )
    assert any("not Decimal/null" in r for r in reasons)


def test_flags_raw_string_cvss_score_not_decimal():
    reasons = _validate_advisory_facts(
        title="Some Advisory",
        source_url="https://example.com/advisory",
        cve_lookups=[("CVE-2026-31431", FakeCve(cvss_score="7.5"))],
        product_ids_exist=[],
    )
    assert any("not Decimal/null" in r for r in reasons)


def test_flags_orphaned_product_reference():
    reasons = _validate_advisory_facts(
        title="Some Advisory",
        source_url="https://example.com/advisory",
        cve_lookups=[],
        product_ids_exist=[(42, False)],
    )
    assert any("non-existent product_id" in r for r in reasons)


def test_multiple_failures_all_reported_not_just_first():
    reasons = _validate_advisory_facts(
        title=None,
        source_url=None,
        cve_lookups=[("NA", None)],
        product_ids_exist=[(1, False)],
    )
    assert len(reasons) >= 3
