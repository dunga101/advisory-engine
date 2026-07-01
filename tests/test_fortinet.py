from datetime import datetime, timezone

import pytest
from lxml import etree

from collectors.sources.fortinet import (
    _children_local,
    _cvss_from_vulnerability,
    _discover_cve_ids,
    _document_summary_note,
    _extract_cwe,
    _find_local,
    _ir_id_from_link,
    _local,
    _normalize_advisory,
    _normalize_cve_fields,
    _parse_date,
    _text_local,
    _walk_product_tree,
    _within_backfill_window,
)

# Real single-CVE document (trimmed), FG-IR-24-257, fetched live 2026-07-01.
SINGLE_CVE_DOC = b"""<?xml version="1.0" encoding="UTF-8"?>
<cvrf:cvrfdoc xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf">
    <cvrf:DocumentTitle>Information Disclosure on SSLVPN endpoint</cvrf:DocumentTitle>
    <cvrf:DocumentTracking>
        <cvrf:InitialReleaseDate>2025-06-10T00:00:00</cvrf:InitialReleaseDate>
        <cvrf:CurrentReleaseDate>2026-06-15T00:00:00</cvrf:CurrentReleaseDate>
    </cvrf:DocumentTracking>
    <cvrf:DocumentNotes>
        <cvrf:Note Title="Summary" Type="Summary" Ordinal="1">
            An Exposure of Sensitive Information to an Unauthorized Actor vulnerability [CWE-200] in FortiOS SSL-VPN web-mode may allow an authenticated user to access full SSL-VPN settings via crafted URL.
        </cvrf:Note>
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
        <Title>Information Disclosure on SSLVPN endpoint</Title>
        <cvrf:CVE>CVE-2025-25250</cvrf:CVE>
        <ProductStatuses>
            <Status Type="Known Affected">
                <ProductID>FortiOS-7.6.0</ProductID>
                <ProductID>FortiOS-7.4.7</ProductID>
            </Status>
        </ProductStatuses>
        <CVSSScoreSets>
            <ScoreSetV3>
                <BaseScoreV3>3.9</BaseScoreV3>
                <VectorV3>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N/E:P/RL:O/RC:C</VectorV3>
            </ScoreSetV3>
        </CVSSScoreSets>
        <References Type="Self">
            <Reference>
                <URL>https://fortiguard.fortinet.com/psirt/FG-IR-24-257</URL>
                <Description>Information Disclosure on SSLVPN endpoint</Description>
            </Reference>Reference>
        </References>
    </Vulnerability>
</cvrf:cvrfdoc>
"""

# Real multi-CVE document (trimmed), FG-IR-26-144, fetched live 2026-07-01 —
# structured <cvrf:CVE> only captures CVE-2026-43284, CVE-2026-43500 only
# shows up via the nvd.nist.gov Reference link and the free-text summary.
MULTI_CVE_DOC = b"""<?xml version="1.0" encoding="UTF-8"?>
<cvrf:cvrfdoc xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf">
    <cvrf:DocumentTitle>Linux Kernel vulnerability Dirty Frag</cvrf:DocumentTitle>
    <cvrf:DocumentTracking>
        <cvrf:InitialReleaseDate>2026-06-03T00:00:00</cvrf:InitialReleaseDate>
        <cvrf:CurrentReleaseDate>2026-06-03T00:00:00</cvrf:CurrentReleaseDate>
    </cvrf:DocumentTracking>
    <cvrf:DocumentNotes>
        <cvrf:Note Title="Summary" Type="Summary" Ordinal="1">
            Linux kernel is impacted by CVE-2026-43284 and CVE-2026-43500 which chained together create the Dirty Frag vulnerability.
        </cvrf:Note>
    </cvrf:DocumentNotes>
    <Vulnerability Ordinal="1">
        <Title>Linux Kernel vulnerability Dirty Frag</Title>
        <cvrf:CVE>CVE-2026-43284</cvrf:CVE>
        <CVSSScoreSets>
            <ScoreSetV3>
                <BaseScoreV3>7.9</BaseScoreV3>
                <VectorV3>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/E:P/RL:O/RC:C</VectorV3>
            </ScoreSetV3>
        </CVSSScoreSets>
        <References Type="Self">
            <Reference>
                <URL>https://fortiguard.fortinet.com/psirt/FG-IR-26-144</URL>
                <Description>Linux Kernel vulnerability Dirty Frag</Description>
            </Reference>Reference>
            <Reference>
                <URL>https://nvd.nist.gov/vuln/detail/CVE-2026-43500</URL>
                <Description>https://nvd.nist.gov/vuln/detail/CVE-2026-43500</Description>
            </Reference>
            <Reference>
                <URL>https://nvd.nist.gov/vuln/detail/CVE-2026-43284</URL>
                <Description>https://nvd.nist.gov/vuln/detail/CVE-2026-43284</Description>
            </Reference>
        </References>
    </Vulnerability>
</cvrf:cvrfdoc>
"""


def test_lxml_tolerates_fortinet_stray_reference_text_artifact():
    """Fortinet's own CVRF generator emits a stray '</Reference>Reference>'
    text artifact on every real document fetched (2026-07-01 probe, 4/4
    advisories). This locks in that lxml's strict (non-recovering) parser
    tolerates it today — a future regression in Fortinet's generator that
    makes this worse, or an lxml upgrade that stops tolerating it, should
    fail this test rather than silently break the collector."""
    root = etree.fromstring(SINGLE_CVE_DOC)
    assert _local(root) == "cvrfdoc"

    vuln = _children_local(root, "Vulnerability")[0]
    references = _find_local(vuln, "References")
    refs = _children_local(references, "Reference")
    assert len(refs) == 1
    assert _text_local(refs[0], "URL") == "https://fortiguard.fortinet.com/psirt/FG-IR-24-257"


def test_ir_id_from_link():
    assert _ir_id_from_link("https://fortiguard.fortinet.com/psirt/FG-IR-24-257") == "FG-IR-24-257"


def test_ir_id_from_link_trailing_slash():
    assert _ir_id_from_link("https://fortiguard.fortinet.com/psirt/FG-IR-24-257/") == "FG-IR-24-257"


def test_extract_cwe_found():
    assert _extract_cwe("blah blah [CWE-200] blah") == "CWE-200"


def test_extract_cwe_missing():
    assert _extract_cwe("no cwe mentioned here") is None


def test_within_backfill_window_recent():
    now = datetime(2026, 7, 1, tzinfo=timezone.utc)
    entry = {"published_parsed": (2026, 6, 1, 0, 0, 0, 0, 0, 0)}
    assert _within_backfill_window(entry, now) is True


def test_within_backfill_window_too_old():
    now = datetime(2026, 7, 1, tzinfo=timezone.utc)
    entry = {"published_parsed": (2024, 1, 1, 0, 0, 0, 0, 0, 0)}
    assert _within_backfill_window(entry, now) is False


def test_within_backfill_window_missing_date():
    now = datetime(2026, 7, 1, tzinfo=timezone.utc)
    assert _within_backfill_window({}, now) is False


def test_parse_date():
    assert _parse_date("2026-06-03T00:00:00").isoformat() == "2026-06-03"


def test_parse_date_none():
    assert _parse_date(None) is None


class TestSingleCveDocument:
    root = etree.fromstring(SINGLE_CVE_DOC)
    vuln = _children_local(root, "Vulnerability")[0]
    summary = _document_summary_note(root)

    def test_cvss_from_vulnerability(self):
        score, vector = _cvss_from_vulnerability(self.vuln)
        assert score == 3.9
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N/E:P/RL:O/RC:C"

    def test_discover_cve_ids_single_cve_no_extras(self):
        assert _discover_cve_ids(self.vuln, self.summary) == ["CVE-2025-25250"]

    def test_walk_product_tree(self):
        product_tree = _find_local(self.root, "ProductTree")
        vendor_branch = _children_local(product_tree, "Branch")[0]
        mapping = _walk_product_tree(vendor_branch)
        assert mapping == {
            "FortiOS-7.6.0": ("FortiOS", "7.6.0"),
            "FortiOS-7.4.7": ("FortiOS", "7.4.7"),
        }

    def test_normalize_advisory(self):
        result = _normalize_advisory(self.root, "FG-IR-24-257")
        assert result["title"] == "Information Disclosure on SSLVPN endpoint"
        assert result["published_date"].isoformat() == "2025-06-10"
        assert result["last_updated_date"].isoformat() == "2026-06-15"
        assert result["source_url"] == "https://fortiguard.fortinet.com/psirt/FG-IR-24-257"

    def test_normalize_cve_fields_excludes_kev_fields(self):
        fields = _normalize_cve_fields(self.vuln, self.summary)
        assert fields["cvss_score"] == 3.9
        assert fields["cwe_id"] == "CWE-200"
        assert "kev_listed" not in fields
        assert "kev_date_added" not in fields
        assert "kev_ransomware_use" not in fields


class TestMultiCveDocument:
    root = etree.fromstring(MULTI_CVE_DOC)
    vuln = _children_local(root, "Vulnerability")[0]
    summary = _document_summary_note(root)

    def test_structured_cve_alone_misses_second_cve(self):
        """Documents the exact gap that motivated the union approach: the
        structured element alone is insufficient."""
        cve_elem = next(child for child in self.vuln if _local(child) == "CVE")
        assert cve_elem.text.strip() == "CVE-2026-43284"

    def test_discover_cve_ids_union_catches_both(self):
        assert _discover_cve_ids(self.vuln, self.summary) == [
            "CVE-2026-43284",
            "CVE-2026-43500",
        ]
