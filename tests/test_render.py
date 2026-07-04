import json
from datetime import datetime, timezone

from publisher.data import HomepageStats
from publisher.render import write_site


def test_write_site_emits_machine_readable_status_json(tmp_path):
    generated_at = datetime(2026, 7, 1, 4, 0, tzinfo=timezone.utc)
    stats = HomepageStats(total_advisories=0, verdict_counts={}, most_recent_kev=None)

    write_site(tmp_path, advisories=[], recent=[], digest=[], stats=stats, generated_at=generated_at)

    status_path = tmp_path / "status.json"
    assert status_path.exists()
    status = json.loads(status_path.read_text())
    assert status["generated_at"] == generated_at.isoformat()
    assert status["advisories_published"] == 0


def test_write_site_status_json_reflects_advisory_count(tmp_path):
    from decimal import Decimal

    from publisher.data import AdvisoryFact, CveFact

    generated_at = datetime(2026, 7, 1, 4, 0, tzinfo=timezone.utc)
    advisory = AdvisoryFact(
        id=1,
        source_vendor="microsoft",
        source_advisory_id="2026-Jun",
        title="June 2026 Security Updates",
        published_date=None,
        last_updated_date=None,
        source_url="https://example.com",
        severity_vendor="Critical",
        cves=[
            CveFact(
                cve_id="CVE-2026-1",
                cvss_score=Decimal("7.8"),
                cvss_vector=None,
                cwe_id=None,
                kev_listed=False,
                kev_date_added=None,
                kev_ransomware_use=None,
            )
        ],
        kbs=[],
        products=[],
    )
    stats = HomepageStats(total_advisories=1, verdict_counts={}, most_recent_kev=None)

    write_site(
        tmp_path, advisories=[advisory], recent=[], digest=[], stats=stats, generated_at=generated_at
    )

    status = json.loads((tmp_path / "status.json").read_text())
    assert status["advisories_published"] == 1
