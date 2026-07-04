#!/usr/bin/env python3
"""Phase 4 Step 3: CLI review tool.

Default mode lists advisories in blocked_pending_review with
verification_status='pending' — i.e. advisories that failed the pre-check
engine (collectors/precheck.py) or were manually pulled in below — and
lets a human approve or reject one at a time via plain terminal prompts.
Everything else auto-publishes via the pre-check engine
(PRECHECK_AUTO_APPROVE in collectors/config.py); this queue is
deliberately just the exceptions, not a queue of everything ingested.

--flag is the escape hatch: pull any advisory into this queue regardless
of its current pre-check outcome, including one that's already published.
"""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select

from common.db import get_session_factory
from common.models import Advisory, AdvisoryCve, Cve, PatchVerdictHistory, WindowsUpdate


def _apply_approval(advisory, reviewer: str, now: datetime) -> None:
    advisory.publish_status = "published"
    advisory.verification_status = "approved"
    advisory.reviewed_by = reviewer
    advisory.published_at = now
    advisory.rejection_reason = None
    advisory.precheck_flags = None  # resolved — don't leave a stale "why was this blocked" note


def _apply_rejection(advisory, reviewer: str, reason: str) -> None:
    advisory.publish_status = "draft"
    advisory.verification_status = "rejected"
    advisory.reviewed_by = reviewer
    advisory.rejection_reason = reason
    advisory.precheck_flags = None  # resolved — the decision is now captured in rejection_reason


def _apply_manual_flag(advisory, reason: str) -> None:
    advisory.publish_status = "blocked_pending_review"
    advisory.verification_status = "pending"
    advisory.precheck_flags = {"source": "manual", "reason": reason}


def _queue_sort_key(kev_listed: bool, max_cvss) -> tuple:
    """KEV-first, then highest CVSS — matches the build brief's Section 8
    review-queue convention (written for advisory_guidance narrative
    review, reused here since the priority order is the same idea)."""
    return (not kev_listed, -(max_cvss if max_cvss is not None else 0))


def _linked_cves(session, advisory_id: int) -> list[Cve]:
    return (
        session.execute(
            select(Cve)
            .join(AdvisoryCve, AdvisoryCve.cve_id == Cve.cve_id)
            .where(AdvisoryCve.advisory_id == advisory_id)
        )
        .scalars()
        .all()
    )


def _latest_verdict(session, advisory_id: int) -> str | None:
    verdict = (
        session.execute(
            select(PatchVerdictHistory)
            .join(WindowsUpdate, WindowsUpdate.id == PatchVerdictHistory.windows_update_id)
            .where(WindowsUpdate.advisory_id == advisory_id)
            .order_by(PatchVerdictHistory.as_of_date.desc(), PatchVerdictHistory.id.desc())
        )
        .scalars()
        .first()
    )
    return verdict.recommendation if verdict else None


def _build_queue(session) -> list[Advisory]:
    candidates = (
        session.execute(
            select(Advisory).where(
                Advisory.publish_status == "blocked_pending_review",
                Advisory.verification_status == "pending",
            )
        )
        .scalars()
        .all()
    )
    facts = {a.id: _linked_cves(session, a.id) for a in candidates}

    def sort_key(advisory):
        cves = facts[advisory.id]
        kev_listed = any(c.kev_listed for c in cves)
        scores = [c.cvss_score for c in cves if c.cvss_score is not None]
        return _queue_sort_key(kev_listed, max(scores) if scores else None)

    return sorted(candidates, key=sort_key)


def _print_advisory(session, advisory: Advisory, index: int, total: int) -> None:
    cves = _linked_cves(session, advisory.id)
    kev_listed = any(c.kev_listed for c in cves)
    scores = [c.cvss_score for c in cves if c.cvss_score is not None]
    max_cvss = max(scores) if scores else None
    verdict = _latest_verdict(session, advisory.id)

    print()
    print(f"[{index}/{total}] {advisory.source_vendor}/{advisory.source_advisory_id}")
    print(f"  Title:      {advisory.title!r}")
    print(f"  Source URL: {advisory.source_url!r}")
    print(f"  Published:  {advisory.published_date}")
    print(f"  KEV listed: {'YES' if kev_listed else 'no'}   Max CVSS: {max_cvss if max_cvss is not None else 'n/a'}")
    print(f"  Verdict:    {verdict or 'n/a'}")
    if cves:
        print(f"  Linked CVEs ({len(cves)}):")
        for cve in cves:
            print(f"    {cve.cve_id}  cvss={cve.cvss_score}  kev={cve.kev_listed}  cwe={cve.cwe_id}")
    else:
        print("  Linked CVEs: none")
    print(f"  precheck_flags: {advisory.precheck_flags}")


def run_review_queue() -> None:
    session_factory = get_session_factory()
    with session_factory() as session:
        queue = _build_queue(session)
        if not queue:
            print("Review queue is empty — nothing blocked_pending_review awaiting a decision.")
            return

        reviewer = input("Reviewer name (for audit log): ").strip() or "unknown_reviewer"
        total = len(queue)

        for index, advisory in enumerate(queue, start=1):
            _print_advisory(session, advisory, index, total)
            while True:
                choice = input("  [a]pprove  [r]eject  [s]kip: ").strip().lower()
                if choice in ("a", "approve"):
                    _apply_approval(advisory, reviewer, datetime.now(timezone.utc))
                    session.commit()
                    print("  -> approved and published.")
                    break
                if choice in ("r", "reject"):
                    reason = input("  Rejection reason: ").strip()
                    _apply_rejection(advisory, reviewer, reason)
                    session.commit()
                    print("  -> rejected.")
                    break
                if choice in ("s", "skip"):
                    print("  -> skipped.")
                    break
                print("  Please enter a, r, or s.")


def run_flag(advisory_id: int, reason: str) -> None:
    session_factory = get_session_factory()
    with session_factory() as session:
        advisory = session.get(Advisory, advisory_id)
        if advisory is None:
            print(f"No advisory with id={advisory_id}.")
            return

        print(
            f"Advisory {advisory_id} ({advisory.source_vendor}/{advisory.source_advisory_id}): "
            f"currently publish_status={advisory.publish_status!r}, "
            f"verification_status={advisory.verification_status!r}."
        )
        if advisory.publish_status == "published":
            confirm = (
                input(
                    "This is currently published — flagging will pull it back into "
                    "manual review and out of the published state. Continue? [y/N]: "
                )
                .strip()
                .lower()
            )
            if confirm != "y":
                print("Cancelled.")
                return

        _apply_manual_flag(advisory, reason)
        session.commit()
        print(f"Advisory {advisory_id} flagged for manual review.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--flag",
        type=int,
        metavar="ADVISORY_ID",
        help="Pull a specific advisory into the manual review queue, regardless of its current pre-check outcome.",
    )
    parser.add_argument("--reason", type=str, help="Reason for --flag (required with --flag).")
    args = parser.parse_args()

    if args.flag is not None:
        if not args.reason:
            parser.error("--flag requires --reason")
        run_flag(args.flag, args.reason)
        return

    run_review_queue()


if __name__ == "__main__":
    main()
