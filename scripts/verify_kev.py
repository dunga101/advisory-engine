#!/usr/bin/env python3
"""End-to-end Phase 1 verification: run the KEV collector once, confirm rows
landed in cves on db-01, and print any cve_revision_history entries written."""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select

from collectors.sources.kev import run_once
from common.db import get_session_factory
from common.models import Cve, CveRevisionHistory


def main() -> None:
    run_started_at = datetime.now(timezone.utc)

    print("Running KEV collector once...")
    summary = run_once()
    print(f"  feed entries: {summary['feed_entry_count']}")
    print(f"  inserted:     {summary['inserted']}")
    print(f"  updated rows: {summary['updated']}")
    print(f"  field changes:{summary['field_changes']}")

    session_factory = get_session_factory()
    with session_factory() as session:
        total_cves = session.scalar(select(func.count()).select_from(Cve))
        kev_listed_cves = session.scalar(
            select(func.count()).select_from(Cve).where(Cve.kev_listed.is_(True))
        )
        revisions = (
            session.execute(
                select(CveRevisionHistory)
                .where(CveRevisionHistory.captured_at >= run_started_at)
                .order_by(CveRevisionHistory.captured_at)
            )
            .scalars()
            .all()
        )

    print()
    print(f"cves table row count:      {total_cves}")
    print(f"cves with kev_listed=true: {kev_listed_cves}")
    print()

    if revisions:
        print(f"cve_revision_history entries written this run ({len(revisions)}):")
        for rev in revisions:
            print(
                f"  [{rev.captured_at.isoformat()}] {rev.cve_id} "
                f"{rev.field_changed}: {rev.old_value!r} -> {rev.new_value!r}"
            )
    else:
        print("cve_revision_history entries written this run: none "
              "(no diffs detected on existing rows)")


if __name__ == "__main__":
    main()
