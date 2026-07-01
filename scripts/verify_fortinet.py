#!/usr/bin/env python3
"""Verification: run the Fortinet PSIRT collector once, confirm rows
landed in advisories/advisory_cve/cves/advisory_product_affected on
db-01."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select

from collectors.sources.fortinet import run_once
from common.db import get_session_factory
from common.models import Advisory, AdvisoryCve, AdvisoryProductAffected


def main() -> None:
    print("Running Fortinet PSIRT collector once...")
    summary = run_once()
    print(f"  advisories upserted: {summary['advisories_upserted']}")
    print(f"  cves inserted:       {summary['cves_inserted']}")
    print(f"  cves updated:        {summary['cves_updated']}")
    print(f"  products upserted:   {summary['products_upserted']}")
    print(f"  skipped advisories:  {len(summary['skipped_advisories'])}")
    for skipped in summary["skipped_advisories"]:
        print(f"    - {skipped}")

    session_factory = get_session_factory()
    with session_factory() as session:
        total_fortinet_advisories = session.scalar(
            select(func.count())
            .select_from(Advisory)
            .where(Advisory.source_vendor == "fortinet")
        )
        total_advisory_cve = session.scalar(select(func.count()).select_from(AdvisoryCve))
        total_product_affected = session.scalar(
            select(func.count()).select_from(AdvisoryProductAffected)
        )
        sample = (
            session.execute(
                select(Advisory)
                .where(Advisory.source_vendor == "fortinet")
                .order_by(Advisory.id.desc())
                .limit(10)
            )
            .scalars()
            .all()
        )

    print()
    print(f"fortinet advisories row count:            {total_fortinet_advisories}")
    print(f"advisory_cve table row count:              {total_advisory_cve}")
    print(f"advisory_product_affected table row count: {total_product_affected}")
    print()

    if sample:
        print(f"sample fortinet advisories (most recent {len(sample)}):")
        for row in sample:
            print(
                f"  id={row.id} source_advisory_id={row.source_advisory_id} "
                f"title={row.title!r} published={row.published_date}"
            )
    else:
        print("fortinet advisories: no rows found")


if __name__ == "__main__":
    main()
