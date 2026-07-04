import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import select

from common.models import Advisory, AdvisoryCve

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def is_valid_cve_id(value) -> bool:
    """True only for a real CVE identifier shape (CVE-YYYY-NNNN, 4+ digit
    sequence number). CVE is the atomic unit for this schema (build brief
    Section 5) — vendor feeds routinely mix in things that aren't CVE IDs:
    Cisco's "NA" sentinel for "no CVE assigned yet", Microsoft's pre-CVE
    "ADV------" advisory identifiers, and malformed "-M" suffixed IDs. Any
    collector extracting CVE IDs from a source payload should filter
    through this before writing to cves/advisory_cve."""
    return isinstance(value, str) and bool(CVE_ID_PATTERN.match(value.strip()))


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
    *,
    on_field_changed=None,
) -> DiffResult:
    """Insert a new row, or diff owned fields against an existing row and write
    a revision_cls row for every field that changed before applying the update.
    A null/empty incoming value never overwrites an existing non-null value —
    e.g. an MSRC document with no CWE for a CVE must not blank out a CWE the
    KEV feed already populated.

    on_field_changed, if given, is called as on_field_changed(field_name,
    old_value, new_value) for every field that changed on an *existing* row
    (never on insert). Used by collectors to reopen the review gate on an
    already-published advisory when a significant field changes — see
    reopen_review_gate below. Never called on insert since there's no prior
    published state to protect."""
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
        if on_field_changed is not None:
            on_field_changed(field_name, old_value, new_value)

    return DiffResult(inserted=False, changed_fields=changed_fields)


def upsert_by_lookup(
    session,
    model_cls,
    lookup: dict,
    fields: dict,
    *,
    revision_cls=None,
    revision_fk_column: str | None = None,
    on_field_changed=None,
) -> bool:
    """Insert a new row, or update fields on the row matching `lookup` (an arbitrary
    filter, not necessarily the PK). Returns True if inserted, False otherwise.

    revision_cls/revision_fk_column are optional (default None, preserving
    the original no-history behavior) — pass both to also write a
    revision_cls row for every changed field, same as upsert_and_diff. The
    revision FK value is always the existing row's own `id`, since
    upsert_by_lookup's `lookup` dict is an arbitrary filter rather than a
    single PK. Use this for tables deduped on a natural key (e.g.
    advisories on source_vendor+source_advisory_id, windows_updates on
    kb_number+os_product) rather than a single-column PK lookup.

    on_field_changed, unlike upsert_and_diff's version, is called as
    on_field_changed(field_name, old_value, new_value, existing_id) — the
    row's own id is passed explicitly since (unlike upsert_and_diff) the
    caller here never has a single pk_value in scope up front, only the
    natural-key `lookup` dict. Called on every changed field of an
    existing row, never on insert.

    Same null/empty-never-overwrites rule as upsert_and_diff."""
    existing = session.execute(
        select(model_cls).filter_by(**lookup)
    ).scalar_one_or_none()

    if existing is None:
        row = model_cls(**lookup, **fields)
        session.add(row)
        return True

    now = datetime.now(timezone.utc)
    for field_name, new_value in fields.items():
        if _is_empty(new_value):
            continue
        old_value = getattr(existing, field_name)
        if _comparable(old_value) == _comparable(new_value):
            continue

        if revision_cls is not None:
            session.add(
                revision_cls(
                    **{revision_fk_column: existing.id},
                    captured_at=now,
                    field_changed=field_name,
                    old_value=None if old_value is None else str(old_value),
                    new_value=None if new_value is None else str(new_value),
                )
            )
        setattr(existing, field_name, new_value)
        if on_field_changed is not None:
            on_field_changed(field_name, old_value, new_value, existing.id)

    return False


# --- Review-gate reopening (architecture review item 4) ---
#
# Once an advisory is published+approved, most collector-driven field
# updates (title wording, description text, dates, source URLs) should
# keep applying silently — that's routine churn, not something a human
# needs to re-look at, and the whole point of the pre-check
# auto-approve pipeline is to not need a human for every re-fetch.
# A narrow set of fields are significant enough to warrant a second look
# before the new value stays live on the public site: CVSS score
# (meaningful moves only — see CVSS_GATING_DELTA), kev_listed, and the
# advisory's own severity rating. Kept deliberately narrow so this can't
# turn into an unmanageable review queue.
GATING_CVE_FIELDS = {"cvss_score", "kev_listed"}
GATING_ADVISORY_FIELDS = {"severity_vendor"}
CVSS_GATING_DELTA = Decimal("0.10")

# precheck.py must treat this the same as a human's manual --flag: never
# auto-re-approve it. Otherwise PRECHECK_AUTO_APPROVE would silently
# re-publish the very next run, making this whole mechanism a no-op.
REOPENED_PRECHECK_SOURCE = "auto-reopened"


def is_gating_cve_change(field_name: str, old_value, new_value) -> bool:
    """True if a change to this Cve field is significant enough to reopen
    the review gate on any advisory linked to this CVE. cvss_score only
    gates on a move bigger than CVSS_GATING_DELTA (or a scored<->unscored
    transition) — small revisions (e.g. 7.8 -> 7.9) are exactly the kind
    of routine cross-source disagreement noise this must not flag."""
    if field_name not in GATING_CVE_FIELDS:
        return False
    if field_name == "cvss_score":
        if old_value is None or new_value is None:
            return True
        return abs(_comparable(old_value) - _comparable(new_value)) > CVSS_GATING_DELTA
    return True


def is_gating_advisory_change(field_name: str, old_value, new_value) -> bool:
    """True if a change to this Advisory field is significant enough to
    reopen the review gate. Only severity_vendor today — title/dates/URL
    are routine churn (Fortinet CVRF re-fetches, MSRC CurrentReleaseDate
    bumps) that must never reopen the queue."""
    return field_name in GATING_ADVISORY_FIELDS


def reopen_review_gate(session, advisory_ids, reason: str) -> int:
    """Pull already-published+approved advisories back into
    blocked_pending_review/pending. No-op (returns 0) for any advisory_id
    not currently in that exact state — draft/pending/rejected advisories
    have nothing to "reopen". Uses REOPENED_PRECHECK_SOURCE rather than
    precheck.py's own "precheck" tag so the next precheck run skips
    re-evaluating it entirely (same escape hatch review_cli.py's --flag
    uses for "manual") — it must sit in the queue until a human looks at
    it, not get silently re-approved because the new value happens to
    still pass every structural check."""
    advisory_ids = {aid for aid in advisory_ids if aid is not None}
    if not advisory_ids:
        return 0

    advisories = (
        session.execute(
            select(Advisory).where(
                Advisory.id.in_(advisory_ids),
                Advisory.publish_status == "published",
                Advisory.verification_status == "approved",
            )
        )
        .scalars()
        .all()
    )
    for advisory in advisories:
        advisory.publish_status = "blocked_pending_review"
        advisory.verification_status = "pending"
        advisory.precheck_flags = {"source": REOPENED_PRECHECK_SOURCE, "reason": reason}
    return len(advisories)


def advisory_ids_for_cve(session, cve_id: str) -> list[int]:
    """All advisory_ids a given CVE is linked to, via advisory_cve — used
    to resolve which advisories to reopen when a gating Cve field
    changes."""
    return (
        session.execute(select(AdvisoryCve.advisory_id).where(AdvisoryCve.cve_id == cve_id))
        .scalars()
        .all()
    )


def cve_gate_hook(session, cve_id: str):
    """on_field_changed callback for upsert_and_diff(model_cls=Cve, ...).
    Every collector that upserts CVEs (KEV, Cisco, MSRC, Fortinet) passes
    this so a gating change (CVSS jump, kev_listed flip) reopens review on
    every advisory that CVE is linked to — not just the advisory the
    collector currently happens to be processing, since e.g. KEV never
    touches advisories at all, only cves."""

    def _on_change(field_name, old_value, new_value):
        if not is_gating_cve_change(field_name, old_value, new_value):
            return
        reopen_review_gate(
            session,
            advisory_ids_for_cve(session, cve_id),
            reason=f"{cve_id}.{field_name} changed ({old_value!r} -> {new_value!r})",
        )

    return _on_change


def advisory_gate_hook(session):
    """on_field_changed callback for upsert_by_lookup(model_cls=Advisory,
    ...). Reopens review on the advisory itself when a gating field
    (severity_vendor) changes."""

    def _on_change(field_name, old_value, new_value, existing_id):
        if not is_gating_advisory_change(field_name, old_value, new_value):
            return
        reopen_review_gate(
            session,
            [existing_id],
            reason=f"advisory.{field_name} changed ({old_value!r} -> {new_value!r})",
        )

    return _on_change
