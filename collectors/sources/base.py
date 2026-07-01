from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import select


@dataclass
class DiffResult:
    inserted: bool
    changed_fields: list[str] = field(default_factory=list)


def _is_empty(value) -> bool:
    """A null/blank incoming value means "this source had nothing to say" —
    never treat it as a real change to an existing non-null value."""
    if value is None:
        return True
    if isinstance(value, str) and value.strip() == "":
        return True
    return False


def _comparable(value):
    """Normalize for equality checks only (the stored/written value is left
    untouched). Postgres Numeric columns come back as Decimal; incoming JSON
    numbers are Python float. Decimal(7.8) == 7.8 is False due to binary
    float imprecision, so floats are normalized via Decimal(str(value)) —
    the DB side is never cast to float, which would introduce the same
    imprecision from the other direction."""
    if isinstance(value, float):
        return Decimal(str(value))
    return value


def upsert_and_diff(
    session,
    model_cls,
    revision_cls,
    pk_column: str,
    revision_fk_column: str,
    pk_value,
    fields: dict,
) -> DiffResult:
    """Insert a new row, or diff owned fields against an existing row and write
    a revision_cls row for every field that changed before applying the update.
    A null/empty incoming value never overwrites an existing non-null value —
    e.g. an MSRC document with no CWE for a CVE must not blank out a CWE the
    KEV feed already populated."""
    existing = session.get(model_cls, pk_value)

    if existing is None:
        row = model_cls(**{pk_column: pk_value}, **fields)
        session.add(row)
        return DiffResult(inserted=True)

    now = datetime.now(timezone.utc)
    changed_fields = []
    for field_name, new_value in fields.items():
        if _is_empty(new_value):
            continue

        old_value = getattr(existing, field_name)
        if _comparable(old_value) == _comparable(new_value):
            continue

        session.add(
            revision_cls(
                **{revision_fk_column: pk_value},
                captured_at=now,
                field_changed=field_name,
                old_value=None if old_value is None else str(old_value),
                new_value=None if new_value is None else str(new_value),
            )
        )
        setattr(existing, field_name, new_value)
        changed_fields.append(field_name)

    return DiffResult(inserted=False, changed_fields=changed_fields)


def upsert_by_lookup(session, model_cls, lookup: dict, fields: dict) -> bool:
    """Insert a new row, or update fields on the row matching `lookup` (an arbitrary
    filter, not necessarily the PK). Returns True if inserted, False otherwise.

    Unlike upsert_and_diff, this writes no revision history — only cves has a
    revision_history table today. Use this for tables deduped on a natural key
    (e.g. advisories on source_vendor+source_advisory_id, windows_updates on
    kb_number+os_product) rather than a single-column PK lookup.

    Same null/empty-never-overwrites rule as upsert_and_diff."""
    existing = session.execute(
        select(model_cls).filter_by(**lookup)
    ).scalar_one_or_none()

    if existing is None:
        row = model_cls(**lookup, **fields)
        session.add(row)
        return True

    for field_name, new_value in fields.items():
        if _is_empty(new_value):
            continue
        if _comparable(getattr(existing, field_name)) != _comparable(new_value):
            setattr(existing, field_name, new_value)

    return False
