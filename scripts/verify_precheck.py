#!/usr/bin/env python3
"""Phase 4 verification: run the pre-check engine once, confirm advisories
transition to published/approved (auto-approve) or blocked_pending_review
(failed checks), and print a sample of each."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select

from collectors.precheck import run_once
from common.db import get_session_factory
from common.models import Advisory


def main() -> None:
    print("Running pre-check engine once...")
    summary = run_once()
    print(f"  evaluated:              {summary['evaluated']}")
    print(f"  auto_approved:          {summary['auto_approved']}")
    print(f"  blocked_pending_review: {summary['blocked_pending_review']}")
    print(f"  left_pending:           {summary['left_pending']}")

    session_factory = get_session_factory()
    with session_factory() as session:
        counts = session.execute(
            select(Advisory.publish_status, Advisory.verification_status, func.count())
            .group_by(Advisory.publish_status, Advisory.verification_status)
            .order_by(Advisory.publish_status, Advisory.verification_status)
        ).all()
        blocked_sample = (
            session.execute(
                select(Advisory)
                .where(Advisory.publish_status == "blocked_pending_review")
                .order_by(Advisory.id.desc())
                .limit(10)
            )
            .scalars()
            .all()
        )

    print()
    print("publish_status / verification_status breakdown:")
    for publish_status, verification_status, count in counts:
        print(f"  {publish_status:10s} / {verification_status:10s}: {count}")

    print()
    if blocked_sample:
        print(f"sample blocked_pending_review advisories ({len(blocked_sample)}):")
        for row in blocked_sample:
            print(
                f"  id={row.id} {row.source_vendor}/{row.source_advisory_id}: "
                f"{row.precheck_flags}"
            )
    else:
        print("no blocked_pending_review advisories")


if __name__ == "__main__":
    main()
