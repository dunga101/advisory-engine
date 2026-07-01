#!/usr/bin/env python3
"""Manually record a field report against a windows_update or advisory. There is
no automated collector for field_reports (build brief Section 4 only lists
community field reports as manual entry) — this is that entry point."""
import argparse
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.db import get_session_factory
from common.models import FieldReport

SOURCE_TYPES = ("microsoft_release_health", "community", "vendor_kb")
STATUSES = ("unconfirmed", "confirmed", "workaround_available", "resolved")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows-update-id", type=int)
    parser.add_argument("--advisory-id", type=int)
    parser.add_argument("--source-type", required=True, choices=SOURCE_TYPES)
    parser.add_argument("--issue-description", required=True)
    parser.add_argument("--affected-configuration")
    parser.add_argument("--report-date", type=date.fromisoformat, default=date.today())
    parser.add_argument("--status", choices=STATUSES, default="unconfirmed")
    args = parser.parse_args()

    if args.windows_update_id is None and args.advisory_id is None:
        parser.error("at least one of --windows-update-id or --advisory-id is required")

    return args


def main() -> None:
    args = parse_args()

    session_factory = get_session_factory()
    with session_factory() as session:
        report = FieldReport(
            windows_update_id=args.windows_update_id,
            advisory_id=args.advisory_id,
            source_type=args.source_type,
            issue_description=args.issue_description,
            affected_configuration=args.affected_configuration,
            report_date=args.report_date,
            status=args.status,
        )
        session.add(report)
        session.commit()
        print(f"field_reports row created: id={report.id}")


if __name__ == "__main__":
    main()
