from decimal import Decimal

import pytest

from collectors.sources.base import is_valid_cve_id, upsert_and_diff


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
    def __init__(self, existing):
        self._existing = existing
        self.added = []

    def get(self, model_cls, pk_value):
        return self._existing

    def add(self, obj):
        self.added.append(obj)


def test_decimal_from_db_vs_float_from_json_is_not_a_diff():
    """Postgres Numeric returns Decimal('7.8'); MSRC JSON gives float 7.8.
    Decimal(7.8) == 7.8 is False in raw Python — must not log a spurious
    cve_revision_history row when nothing actually changed."""
    existing = FakeCve(cve_id="CVE-2026-31431", cvss_score=Decimal("7.8"))
    session = FakeSession(existing)

    result = upsert_and_diff(
        session,
        model_cls=FakeCve,
        revision_cls=FakeRevision,
        pk_column="cve_id",
        revision_fk_column="cve_id",
        pk_value="CVE-2026-31431",
        fields={"cvss_score": 7.8},
    )

    assert result.changed_fields == []
    assert session.added == []
    assert existing.cvss_score == Decimal("7.8")


def test_real_cvss_score_change_is_still_logged():
    existing = FakeCve(cve_id="CVE-2026-31431", cvss_score=Decimal("7.8"))
    session = FakeSession(existing)

    result = upsert_and_diff(
        session,
        model_cls=FakeCve,
        revision_cls=FakeRevision,
        pk_column="cve_id",
        revision_fk_column="cve_id",
        pk_value="CVE-2026-31431",
        fields={"cvss_score": 8.8},
    )

    assert result.changed_fields == ["cvss_score"]
    assert len(session.added) == 1
    assert session.added[0].old_value == "7.8"
    assert existing.cvss_score == 8.8


def test_null_incoming_value_does_not_overwrite_existing_value():
    """A second collector (e.g. MSRC) with no CWE/description for a CVE must
    not blank out data a prior collector (e.g. KEV) already populated."""
    existing = FakeCve(
        cve_id="CVE-2026-31431",
        cwe_id="CWE-669",
        description_raw="Linux Kernel privilege escalation.",
    )
    session = FakeSession(existing)

    result = upsert_and_diff(
        session,
        model_cls=FakeCve,
        revision_cls=FakeRevision,
        pk_column="cve_id",
        revision_fk_column="cve_id",
        pk_value="CVE-2026-31431",
        fields={"cwe_id": None, "description_raw": ""},
    )

    assert result.changed_fields == []
    assert session.added == []
    assert existing.cwe_id == "CWE-669"
    assert existing.description_raw == "Linux Kernel privilege escalation."


def test_non_null_to_non_null_change_is_still_logged():
    """The null-overwrite guard must not suppress legitimate diffs."""
    existing = FakeCve(cve_id="CVE-2026-31431", cwe_id="CWE-669")
    session = FakeSession(existing)

    result = upsert_and_diff(
        session,
        model_cls=FakeCve,
        revision_cls=FakeRevision,
        pk_column="cve_id",
        revision_fk_column="cve_id",
        pk_value="CVE-2026-31431",
        fields={"cwe_id": "CWE-284"},
    )

    assert result.changed_fields == ["cwe_id"]
    assert existing.cwe_id == "CWE-284"


# --- CVE-ID validator ---
# Real-world non-CVE values confirmed in this project's own data: Cisco's
# "NA" sentinel (cisco-sa-notice-vwL7b0S7, live probe 2026-07-01) and MSRC's
# pre-CVE "ADV------" advisory IDs / malformed "-M" suffixed IDs (found in
# the existing cves table).


@pytest.mark.parametrize(
    "value",
    [
        "CVE-2026-31431",
        "CVE-2022-20714",
        "CVE-2024-0001",
        "CVE-2026-123456789",  # more than 4 digits is still valid
    ],
)
def test_is_valid_cve_id_accepts_real_cve_shapes(value):
    assert is_valid_cve_id(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "NA",  # Cisco's "no CVE assigned yet" sentinel
        "ADV170010",  # Microsoft pre-CVE advisory ID
        "ADV990001",
        "CVE-2022-2601-M",  # malformed "-M" suffix
        "CVE-2024-0132-M",
        "cve-2026-31431",  # wrong case
        "CVE-26-31431",  # year not 4 digits
        "CVE-2026-123",  # sequence number under 4 digits
        "",
        None,
        123,
    ],
)
def test_is_valid_cve_id_rejects_non_cve_shapes(value):
    assert is_valid_cve_id(value) is False
