from decimal import Decimal
from unittest.mock import Mock, patch

import pytest

from collectors.sources.base import _comparable, upsert_and_diff
from collectors.sources.cisco import (
    DailyQuotaExceeded,
    RateLimiter,
    _extract_valid_cve_ids,
    _normalize_advisory,
    _normalize_cve,
    _parse_cvss_score,
    _split_multi,
    fetch_access_token,
)

# Real example advisory from Cisco's own DevNet documentation
# (developer.cisco.com/docs/psirt/latestnumber/), used verbatim as the
# "real advisory" mapping fixture.
SAMPLE_ADVISORY = {
    "advisoryId": "cisco-sa-lsplus-Z6AQEOjk",
    "advisoryTitle": (
        "Cisco IOS XR Software for ASR 9000 Series Routers Lightspeed-Plus "
        "Line Cards Denial of Service Vulnerability"
    ),
    "bugIDs": "CSCvy48962",
    "ipsSignatures": "NA",
    "cves": "CVE-2022-20714",
    "cvrfUrl": (
        "https://tools.cisco.com/security/center/contentxml/CiscoSecurityAdvisory/"
        "cisco-sa-lsplus-Z6AQEOjk/cvrf/cisco-sa-lsplus-Z6AQEOjk_cvrf.xml"
    ),
    "csafUrl": (
        "https://tools.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/"
        "cisco-sa-lsplus-Z6AQEOjk/csaf/cisco-sa-lsplus-Z6AQEOjk_csaf.json"
    ),
    "cvssBaseScore": 8.6,
    "cwe": "CWE-12",
    "firstPublished": "2022-04-13T23:00:00",
    "lastUpdated": "2022-04-29T04:28:53",
    "status": "Final",
    "version": 1.1,
    "productNames": "Cisco IOS XR Software",
    "publicationUrl": (
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/"
        "cisco-sa-lsplus-Z6AQEOjk"
    ),
    "sir": "High",
    "summary": "A vulnerability in Cisco IOS XR Software could allow an "
    "unauthenticated, adjacent attacker to cause a denial of service.",
}


class FakeCve:
    def __init__(self, cve_id, cvss_score=None, cwe_id=None, description_raw=None):
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.cwe_id = cwe_id
        self.description_raw = description_raw


class FakeRevision:
    def __init__(self, cve_id, captured_at, field_changed, old_value, new_value):
        self.cve_id = cve_id
        self.captured_at = captured_at
        self.field_changed = field_changed
        self.old_value = old_value
        self.new_value = new_value


class FakeSession:
    def __init__(self, existing=None):
        self._existing = existing
        self.added = []

    def get(self, model_cls, pk_value):
        return self._existing

    def add(self, obj):
        self.added.append(obj)


# --- OAuth2 token fetch ---


def test_fetch_access_token_success(monkeypatch):
    monkeypatch.setenv("CISCO_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("CISCO_CLIENT_SECRET", "test-client-secret")

    fake_response = Mock()
    fake_response.json.return_value = {"access_token": "test-token-value", "expires_in": 3600}
    fake_response.raise_for_status.return_value = None

    with patch("collectors.sources.cisco.requests.post", return_value=fake_response) as post:
        token = fetch_access_token()

    assert token == "test-token-value"
    _, kwargs = post.call_args
    assert kwargs["data"] == {
        "grant_type": "client_credentials",
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
    }
    assert kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


def test_fetch_access_token_missing_credentials_raises(monkeypatch):
    monkeypatch.delenv("CISCO_CLIENT_ID", raising=False)
    monkeypatch.delenv("CISCO_CLIENT_SECRET", raising=False)

    with pytest.raises(KeyError):
        fetch_access_token()


# --- Rate limiter ---


def test_rate_limiter_sleeps_when_per_second_limit_reached():
    fake_time = [0.0]
    sleep_calls = []

    def fake_time_fn():
        return fake_time[0]

    def fake_sleep(seconds):
        sleep_calls.append(seconds)
        fake_time[0] += seconds

    limiter = RateLimiter(
        per_second=2, per_minute=100, per_day=100, sleep_fn=fake_sleep, time_fn=fake_time_fn
    )

    limiter.acquire()
    limiter.acquire()
    assert sleep_calls == []

    limiter.acquire()
    assert len(sleep_calls) == 1
    assert sleep_calls[0] > 0


def test_rate_limiter_raises_when_daily_quota_reached():
    fake_time = [0.0]

    def fake_time_fn():
        fake_time[0] += 100  # advance well past per-second/per-minute windows each call
        return fake_time[0]

    limiter = RateLimiter(
        per_second=1000, per_minute=1000, per_day=3, sleep_fn=lambda s: None, time_fn=fake_time_fn
    )

    limiter.acquire()
    limiter.acquire()
    limiter.acquire()
    with pytest.raises(DailyQuotaExceeded):
        limiter.acquire()


# --- Schema mapping ---


def test_split_multi_handles_string_list_and_none():
    assert _split_multi("CVE-2022-20714") == ["CVE-2022-20714"]
    assert _split_multi("CVE-2022-20714, CVE-2022-20715") == [
        "CVE-2022-20714",
        "CVE-2022-20715",
    ]
    assert _split_multi(["CVE-2022-20714", "CVE-2022-20715"]) == [
        "CVE-2022-20714",
        "CVE-2022-20715",
    ]
    assert _split_multi(None) == []
    assert _split_multi("") == []


def test_normalize_advisory_maps_real_example():
    result = _normalize_advisory(SAMPLE_ADVISORY)
    assert result == {
        "title": (
            "Cisco IOS XR Software for ASR 9000 Series Routers Lightspeed-Plus "
            "Line Cards Denial of Service Vulnerability"
        ),
        "published_date": _normalize_advisory(SAMPLE_ADVISORY)["published_date"],
        "last_updated_date": _normalize_advisory(SAMPLE_ADVISORY)["last_updated_date"],
        "source_url": (
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/"
            "cisco-sa-lsplus-Z6AQEOjk"
        ),
        "severity_vendor": "High",
    }
    assert result["published_date"].isoformat() == "2022-04-13"
    assert result["last_updated_date"].isoformat() == "2022-04-29"


def test_normalize_cve_maps_real_example_and_excludes_kev_fields():
    result = _normalize_cve(SAMPLE_ADVISORY)

    assert result == {
        "cvss_score": Decimal("8.6"),
        "cwe_id": "CWE-12",
        "description_raw": SAMPLE_ADVISORY["summary"],
    }
    assert "kev_listed" not in result
    assert "kev_date_added" not in result
    assert "kev_ransomware_use" not in result


def test_cve_upsert_and_diff_inserts_mapped_fields():
    """The mapped fields must flow through the same upsert_and_diff path
    used by kev.py/msrc.py — no separate diffing logic for Cisco."""
    session = FakeSession(existing=None)
    cve_fields = _normalize_cve(SAMPLE_ADVISORY)

    for cve_id in _split_multi(SAMPLE_ADVISORY["cves"]):
        result = upsert_and_diff(
            session,
            model_cls=FakeCve,
            revision_cls=FakeRevision,
            pk_column="cve_id",
            revision_fk_column="cve_id",
            pk_value=cve_id,
            fields=cve_fields,
        )

    assert result.inserted is True
    assert len(session.added) == 1
    inserted_cve = session.added[0]
    assert inserted_cve.cve_id == "CVE-2022-20714"
    assert inserted_cve.cvss_score == Decimal("8.6")
    assert inserted_cve.cwe_id == "CWE-12"


# --- cvssBaseScore string-vs-Decimal regression (live probe, 2026-07-01) ---
#
# Cisco's live API returned {"cvssBaseScore": "7.5"} — a string — despite
# their documented schema saying "number". base.py's _comparable() only
# special-cases float -> Decimal(str(...)); a bare string compared against
# the Decimal that comes back from the DB's Numeric column would never
# match, silently reproducing the original MSRC float/Decimal bug via a
# different input type.


def test_normalize_cve_maps_live_string_cvss_score_to_decimal():
    entry = {**SAMPLE_ADVISORY, "cvssBaseScore": "7.5"}
    result = _normalize_cve(entry)

    assert result["cvss_score"] == Decimal("7.5")
    assert isinstance(result["cvss_score"], Decimal)


def test_string_cvss_score_matches_existing_decimal_db_value_via_comparable():
    """This is the actual bug condition: an existing DB row already holds
    Decimal('7.5') (from a prior run); the live API hands back the string
    "7.5" on this run. _comparable() must treat them as equal so no
    spurious cve_revision_history row gets written."""
    existing_db_value = Decimal("7.5")
    incoming_value = _normalize_cve({**SAMPLE_ADVISORY, "cvssBaseScore": "7.5"})["cvss_score"]

    assert _comparable(existing_db_value) == _comparable(incoming_value)


def test_string_cvss_score_no_float_round_trip_imprecision():
    """A value that is famously lossy through a float round-trip (0.1 + 0.2
    != 0.3 territory) must still compare equal when both sides are cast to
    Decimal directly from their string representation."""
    assert _parse_cvss_score("7.1") == Decimal("7.1")
    assert _comparable(Decimal("7.1")) == _comparable(_parse_cvss_score("7.1"))


@pytest.mark.parametrize("raw_value", [None, "", "   ", "not-a-number"])
def test_parse_cvss_score_missing_or_invalid_returns_none(raw_value):
    assert _parse_cvss_score(raw_value) is None


def test_normalize_cve_missing_cvss_score_key_does_not_crash():
    entry = dict(SAMPLE_ADVISORY)
    del entry["cvssBaseScore"]
    assert _normalize_cve(entry)["cvss_score"] is None


# --- "NA" / non-CVE sentinel filtering (live probe, 2026-07-01) ---
#
# cisco-sa-notice-vwL7b0S7 and cisco-sa-asaftd-persist-CISAED25-03 both
# returned {"cves": ["NA"]} — Cisco's convention for "no CVE assigned yet",
# not an actual CVE ID. Confirmed live: this got inserted as a garbage
# cve_id='NA' row before the fix.


def test_extract_valid_cve_ids_filters_na_sentinel():
    entry = {"cves": ["NA"]}
    assert _extract_valid_cve_ids(entry) == []


def test_extract_valid_cve_ids_keeps_real_cves_and_drops_sentinels():
    entry = {"cves": ["CVE-2026-20213", "NA", "CVE-2026-20214"]}
    assert _extract_valid_cve_ids(entry) == ["CVE-2026-20213", "CVE-2026-20214"]


def test_extract_valid_cve_ids_empty_when_no_cves_key():
    assert _extract_valid_cve_ids({}) == []
