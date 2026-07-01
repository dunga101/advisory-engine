from dataclasses import dataclass, field
from datetime import datetime, timezone


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
