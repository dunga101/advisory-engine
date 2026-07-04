import re
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal

from sqlalchemy import select

from common.db import get_session_factory
from common.models import (
    Advisory,
    AdvisoryCve,
    AdvisoryProductAffected,
    Cve,
    PatchVerdictHistory,
    Product,
    WindowsUpdate,
)


def _slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return re.sub(r"-+", "-", value).strip("-")


@dataclass
class CveFact:
    cve_id: str
    cvss_score: Decimal | None
    cvss_vector: str | None
    cwe_id: str | None
    kev_listed: bool
    kev_date_added: date | None
    kev_ransomware_use: bool | None


@dataclass
class VerdictFact:
    recommendation: str
    wait_days_estimate: int | None
    rationale: str
    as_of_date: date


@dataclass
class KbFact:
    kb_number: str | None
    os_product: str | None
    os_build: str | None
    update_channel: str | None
    cumulative: bool | None
    supersedes_kb: str | None
    superseded_by_kb: str | None
    verdict: VerdictFact | None = None


@dataclass
class ProductFact:
    product_name: str | None
    affected_version_range: str | None
    fixed_version: str | None


@dataclass
class AdvisoryFact:
    id: int
    source_vendor: str
    source_advisory_id: str
    title: str | None
    published_date: date | None
    last_updated_date: date | None
    source_url: str | None
    severity_vendor: str | None
    cves: list[CveFact] = field(default_factory=list)
    kbs: list[KbFact] = field(default_factory=list)
    products: list[ProductFact] = field(default_factory=list)

    @property
    def kev_listed(self) -> bool:
        return any(c.kev_listed for c in self.cves)

    @property
    def max_cvss(self) -> Decimal | None:
        scores = [c.cvss_score for c in self.cves if c.cvss_score is not None]
        return max(scores) if scores else None

    @property
    def slug(self) -> str:
        return _slugify(f"{self.source_vendor}-{self.source_advisory_id}")


def _latest_verdict_for_windows_update(session, windows_update_id: int) -> VerdictFact | None:
    row = session.execute(
        select(PatchVerdictHistory)
        .where(PatchVerdictHistory.windows_update_id == windows_update_id)
        .order_by(PatchVerdictHistory.as_of_date.desc(), PatchVerdictHistory.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None
    return VerdictFact(
        recommendation=row.recommendation,
        wait_days_estimate=row.wait_days_estimate,
        rationale=row.rationale,
        as_of_date=row.as_of_date,
    )


def gather_published_advisories(session=None) -> list[AdvisoryFact]:
    """The one and only publish gate: publish_status='published' AND
    verification_status='approved'. Nothing else is eligible, full stop.

    cves.description_raw is never read here — build brief Section 5:
    "source material, private, never published verbatim." Only structured
    facts (CVSS, CWE, KEV status, KB chain, verdict, affected products) are
    exported; there is no AI narrative in v1."""
    owns_session = session is None
    session = session or get_session_factory()()

    try:
        advisories = (
            session.execute(
                select(Advisory)
                .where(
                    Advisory.publish_status == "published",
                    Advisory.verification_status == "approved",
                )
                .order_by(Advisory.published_date.desc().nullslast(), Advisory.id.desc())
            )
            .scalars()
            .all()
        )

        facts = []
        for advisory in advisories:
            cves = (
                session.execute(
                    select(Cve)
                    .join(AdvisoryCve, AdvisoryCve.cve_id == Cve.cve_id)
                    .where(AdvisoryCve.advisory_id == advisory.id)
                    .order_by(Cve.cve_id)
                )
                .scalars()
                .all()
            )
            cve_facts = [
                CveFact(
                    cve_id=c.cve_id,
                    cvss_score=c.cvss_score,
                    cvss_vector=c.cvss_vector,
                    cwe_id=c.cwe_id,
                    kev_listed=c.kev_listed,
                    kev_date_added=c.kev_date_added,
                    kev_ransomware_use=c.kev_ransomware_use,
                )
                for c in cves
            ]

            windows_updates = (
                session.execute(
                    select(WindowsUpdate)
                    .where(WindowsUpdate.advisory_id == advisory.id)
                    .order_by(WindowsUpdate.os_product, WindowsUpdate.kb_number)
                )
                .scalars()
                .all()
            )
            kb_facts = [
                KbFact(
                    kb_number=wu.kb_number,
                    os_product=wu.os_product,
                    os_build=wu.os_build,
                    update_channel=wu.update_channel,
                    cumulative=wu.cumulative,
                    supersedes_kb=wu.supersedes_kb,
                    superseded_by_kb=wu.superseded_by_kb,
                    verdict=_latest_verdict_for_windows_update(session, wu.id),
                )
                for wu in windows_updates
            ]

            product_rows = session.execute(
                select(AdvisoryProductAffected, Product)
                .join(Product, Product.id == AdvisoryProductAffected.product_id)
                .where(AdvisoryProductAffected.advisory_id == advisory.id)
                .order_by(Product.product_name)
            ).all()
            product_facts = [
                ProductFact(
                    product_name=product.product_name,
                    affected_version_range=apa.affected_version_range,
                    fixed_version=apa.fixed_version,
                )
                for apa, product in product_rows
            ]

            facts.append(
                AdvisoryFact(
                    id=advisory.id,
                    source_vendor=advisory.source_vendor,
                    source_advisory_id=advisory.source_advisory_id,
                    title=advisory.title,
                    published_date=advisory.published_date,
                    last_updated_date=advisory.last_updated_date,
                    source_url=advisory.source_url,
                    severity_vendor=advisory.severity_vendor,
                    cves=cve_facts,
                    kbs=kb_facts,
                    products=product_facts,
                )
            )
        return facts
    finally:
        if owns_session:
            session.close()


def recent_verdicts(
    advisories: list[AdvisoryFact], limit: int
) -> list[tuple[AdvisoryFact, KbFact]]:
    """Every (advisory, KB) pair that has a verdict, most recent first —
    the homepage's "recent verdicts" list."""
    pairs = [(a, kb) for a in advisories for kb in a.kbs if kb.verdict is not None]
    pairs.sort(key=lambda pair: pair[1].verdict.as_of_date, reverse=True)
    return pairs[:limit]


def latest_patch_tuesday_advisories(advisories: list[AdvisoryFact]) -> list[AdvisoryFact]:
    """MSRC advisories carrying a b_release KB, from the most recent
    published_date among them — "the most recent Patch Tuesday.\""""
    msrc_b_release = [
        a
        for a in advisories
        if a.source_vendor == "microsoft" and any(kb.update_channel == "b_release" for kb in a.kbs)
    ]
    if not msrc_b_release:
        return []
    latest_date = max(a.published_date for a in msrc_b_release if a.published_date)
    return [a for a in msrc_b_release if a.published_date == latest_date]


@dataclass
class HomepageStats:
    total_advisories: int
    verdict_counts: dict[str, int]
    most_recent_kev: tuple[str, date] | None  # (cve_id, kev_date_added)


def compute_homepage_stats(advisories: list[AdvisoryFact]) -> HomepageStats:
    """Homepage stats-strip numbers — pure aggregation over the already-
    fetched advisory list, no new queries. verdict_counts is per (advisory,
    KB) pair, same unit recent_verdicts() counts in, not per-advisory."""
    verdict_counts: dict[str, int] = {}
    for advisory in advisories:
        for kb in advisory.kbs:
            if kb.verdict is not None:
                verdict_counts[kb.verdict.recommendation] = (
                    verdict_counts.get(kb.verdict.recommendation, 0) + 1
                )

    most_recent_kev: tuple[str, date] | None = None
    for advisory in advisories:
        for cve in advisory.cves:
            if cve.kev_listed and cve.kev_date_added is not None:
                if most_recent_kev is None or cve.kev_date_added > most_recent_kev[1]:
                    most_recent_kev = (cve.cve_id, cve.kev_date_added)

    return HomepageStats(
        total_advisories=len(advisories),
        verdict_counts=verdict_counts,
        most_recent_kev=most_recent_kev,
    )
