#!/usr/bin/env python3
"""Idempotent seed for reference data that has no automated collector:
platform_reliability_notes (operator track record) and the Windows rows in
products (catalog completeness — windows_updates is the operative exposure
model for Windows, not advisory_product_affected). Safe to re-run."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.sources.base import upsert_by_lookup
from common.db import get_session_factory
from common.models import PlatformReliabilityNote, Product

PLATFORM_RELIABILITY_NOTES = [
    {
        "os_product": "Windows Server 2019",
        "notes": "Clean history — no unresolved cumulative update regressions on this fleet.",
    },
    {
        "os_product": "Windows Server 2022",
        "notes": "Clean history — no unresolved cumulative update regressions on this fleet.",
    },
]

WINDOWS_PRODUCTS = [
    {"vendor": "Microsoft", "product_name": "Windows Server 2019", "product_family": "Windows"},
    {"vendor": "Microsoft", "product_name": "Windows Server 2022", "product_family": "Windows"},
    {"vendor": "Microsoft", "product_name": "Windows Server 2025", "product_family": "Windows"},
    {"vendor": "Microsoft", "product_name": "Windows 10", "product_family": "Windows"},
    {"vendor": "Microsoft", "product_name": "Windows 11", "product_family": "Windows"},
]

EXPOSURE_CHECK_METHOD = (
    "Get-HotFix -Id <KB>, or check HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion "
    "UBR against the KB chain (is this KB or a later superseding KB installed?)"
)


def main() -> None:
    session_factory = get_session_factory()
    notes_written = 0
    products_written = 0

    with session_factory() as session:
        for entry in PLATFORM_RELIABILITY_NOTES:
            upsert_by_lookup(
                session,
                model_cls=PlatformReliabilityNote,
                lookup={"os_product": entry["os_product"]},
                fields={"notes": entry["notes"]},
            )
            notes_written += 1

        for entry in WINDOWS_PRODUCTS:
            upsert_by_lookup(
                session,
                model_cls=Product,
                lookup={"vendor": entry["vendor"], "product_name": entry["product_name"]},
                fields={
                    "product_family": entry["product_family"],
                    "exposure_check_method": EXPOSURE_CHECK_METHOD,
                },
            )
            products_written += 1

        session.commit()

    print(f"platform_reliability_notes upserted: {notes_written}")
    print(f"products upserted:                   {products_written}")


if __name__ == "__main__":
    main()
