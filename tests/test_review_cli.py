from datetime import datetime, timezone
from decimal import Decimal

from scripts.review_cli import (
    _apply_approval,
    _apply_manual_flag,
    _apply_rejection,
    _queue_sort_key,
)


class FakeAdvisory:
    def __init__(self, publish_status="blocked_pending_review", verification_status="pending"):
        self.publish_status = publish_status
        self.verification_status = verification_status
        self.reviewed_by = None
        self.published_at = None
        self.rejection_reason = "stale reason from a prior cycle"
        self.precheck_flags = {"source": "precheck", "reasons": ["missing title"]}


def test_apply_approval_sets_published_and_clears_rejection_reason():
    advisory = FakeAdvisory()
    now = datetime(2026, 7, 1, tzinfo=timezone.utc)

    _apply_approval(advisory, "alice", now)

    assert advisory.publish_status == "published"
    assert advisory.verification_status == "approved"
    assert advisory.reviewed_by == "alice"
    assert advisory.published_at == now
    assert advisory.rejection_reason is None
    assert advisory.precheck_flags is None


def test_apply_rejection_never_publishes_and_logs_reason():
    advisory = FakeAdvisory()

    _apply_rejection(advisory, "alice", "fabricated rollback step")

    assert advisory.publish_status == "draft"
    assert advisory.verification_status == "rejected"
    assert advisory.reviewed_by == "alice"
    assert advisory.rejection_reason == "fabricated rollback step"
    assert advisory.precheck_flags is None


def test_apply_manual_flag_pulls_published_item_back_into_queue():
    """The --flag escape hatch must work even on something already live."""
    advisory = FakeAdvisory(publish_status="published", verification_status="approved")

    _apply_manual_flag(advisory, "double-checking the rollback claim")

    assert advisory.publish_status == "blocked_pending_review"
    assert advisory.verification_status == "pending"
    assert advisory.precheck_flags == {
        "source": "manual",
        "reason": "double-checking the rollback claim",
    }


def test_queue_sort_key_kev_ranks_before_non_kev_regardless_of_cvss():
    kev_low_severity = _queue_sort_key(kev_listed=True, max_cvss=Decimal("3.1"))
    non_kev_critical = _queue_sort_key(kev_listed=False, max_cvss=Decimal("9.8"))

    assert kev_low_severity < non_kev_critical


def test_queue_sort_key_orders_by_cvss_descending_within_same_kev_status():
    higher = _queue_sort_key(kev_listed=False, max_cvss=Decimal("9.8"))
    lower = _queue_sort_key(kev_listed=False, max_cvss=Decimal("4.0"))

    assert higher < lower


def test_queue_sort_key_handles_no_cvss_score():
    with_score = _queue_sort_key(kev_listed=False, max_cvss=Decimal("5.0"))
    without_score = _queue_sort_key(kev_listed=False, max_cvss=None)

    assert with_score < without_score
