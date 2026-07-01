#!/usr/bin/env python3
"""Phase 2 verification: run the verdict engine once, print every
patch_verdict_history row written this run."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select

from collectors.verdict import run_once
from common.db import get_session_factory
from common.models import PatchVerdictHistory, WindowsUpdate


def main() -> None:
    session_factory = get_session_factory()
    with session_factory() as session:
        # id-based watermark, not as_of_date — as_of_date has no time component,
        # so a same-day re-run would otherwise re-list rows from an earlier run.
        max_id_before = session.scalar(select(func.max(PatchVerdictHistory.id))) or 0

    print("Running verdict engine once...")
    summary = run_once()
    print(f"  windows_updates evaluated: {summary['windows_updates_evaluated']}")
    print(f"  verdicts written:          {summary['verdicts_written']}")
    print()

    with session_factory() as session:
        rows = (
            session.execute(
                select(PatchVerdictHistory, WindowsUpdate)
                .join(WindowsUpdate, WindowsUpdate.id == PatchVerdictHistory.windows_update_id)
                .where(PatchVerdictHistory.id > max_id_before)
                .order_by(PatchVerdictHistory.id)
            ).all()
        )

    if rows:
        print(f"patch_verdict_history rows written this run ({len(rows)}):")
        for verdict, update in rows:
            print(
                f"  windows_update_id={verdict.windows_update_id} kb={update.kb_number} "
                f"os_product={update.os_product!r} -> {verdict.recommendation} "
                f"(wait_days_estimate={verdict.wait_days_estimate}, "
                f"field_report_count={verdict.field_report_count_at_time})"
            )
            print(f"    rationale: {verdict.rationale}")
    else:
        print("patch_verdict_history rows written this run: none "
              "(no recommendation changes detected)")


if __name__ == "__main__":
    main()
