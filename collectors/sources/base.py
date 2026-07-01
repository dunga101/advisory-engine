from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select


@dataclass
class DiffResult:
    inserted: bool
    changed_fields: list[str] = field(default_factory=list)


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
    a revision_cls row for every field that changed before applying the update."""
    existing = session.get(model_cls, pk_value)

    if existing is None:
        row = model_cls(**{pk_column: pk_value}, **fields)
        session.add(row)
        return DiffResult(inserted=True)

    now = datetime.now(timezone.utc)
    changed_fields = []
    for field_name, new_value in fields.items():
        old_value = getattr(existing, field_name)
        if old_value == new_value:
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
    kb_number+os_product) rather than a single-column PK lookup."""
    existing = session.execute(
        select(model_cls).filter_by(**lookup)
    ).scalar_one_or_none()

    if existing is None:
        row = model_cls(**lookup, **fields)
        session.add(row)
        return True

    for field_name, new_value in fields.items():
        if getattr(existing, field_name) != new_value:
            setattr(existing, field_name, new_value)

    return False
