#!/usr/bin/env python3
"""Phase 2 verification: run the MSRC collector once, confirm rows landed in
advisories/advisory_cve/cves/windows_updates on db-01."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select

from collectors.sources.msrc import run_once
from common.db import get_session_factory
from common.models import Advisory, AdvisoryCve, WindowsUpdate


def main() -> None:
    print("Running MSRC collector once...")
    summary = run_once()
    print(f"  docs processed:       {summary['docs_processed']}")
    print(f"  cves inserted:        {summary['cves_inserted']}")
    print(f"  cves updated:         {summary['cves_updated']}")
    print(f"  advisories upserted:  {summary['advisories_upserted']}")
    print(f"  windows_updates upserted: {summary['windows_updates_upserted']}")

    session_factory = get_session_factory()
    with session_factory() as session:
        total_advisories = session.scalar(select(func.count()).select_from(Advisory))
        total_advisory_cve = session.scalar(select(func.count()).select_from(AdvisoryCve))
        total_windows_updates = session.scalar(select(func.count()).select_from(WindowsUpdate))
        sample = (
            session.execute(
                select(WindowsUpdate)
                .order_by(WindowsUpdate.id.desc())
                .limit(10)
            )
            .scalars()
            .all()
        )

    print()
    print(f"advisories table row count:      {total_advisories}")
    print(f"advisory_cve table row count:    {total_advisory_cve}")
    print(f"windows_updates table row count: {total_windows_updates}")
    print()

    if sample:
        print(f"sample windows_updates rows (most recent {len(sample)}):")
        for row in sample:
            print(
                f"  id={row.id} kb={row.kb_number} os_product={row.os_product!r} "
                f"os_build={row.os_build} channel={row.update_channel} "
                f"supersedes={row.supersedes_kb}"
            )
    else:
        print("windows_updates: no rows found")


if __name__ == "__main__":
    main()
