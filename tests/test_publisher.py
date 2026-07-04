from datetime import date
from decimal import Decimal

from publisher.data import (
    AdvisoryFact,
    CveFact,
    KbFact,
    VerdictFact,
    compute_homepage_stats,
    latest_patch_tuesday_advisories,
    recent_verdicts,
)


def _cve(cve_id="CVE-2026-1", cvss_score=None, kev_listed=False, kev_date_added=None):
    return CveFact(
        cve_id=cve_id,
        cvss_score=cvss_score,
        cvss_vector=None,
        cwe_id=None,
        kev_listed=kev_listed,
        kev_date_added=kev_date_added,
        kev_ransomware_use=None,
    )


def _advisory(
    id_,
    source_vendor="microsoft",
    source_advisory_id="2026-Apr",
    cves=None,
    kbs=None,
    published_date=None,
):
    return AdvisoryFact(
        id=id_,
        source_vendor=source_vendor,
        source_advisory_id=source_advisory_id,
        title=f"Advisory {id_}",
        published_date=published_date,
        last_updated_date=None,
        source_url="https://example.com",
        severity_vendor=None,
        cves=cves or [],
        kbs=kbs or [],
    )


def _kb(kb_number, update_channel="b_release", verdict=None):
    return KbFact(
        kb_number=kb_number,
        os_product="Windows Server 2022",
        os_build=None,
        update_channel=update_channel,
        cumulative=True,
        supersedes_kb=None,
        superseded_by_kb=None,
        verdict=verdict,
    )


def _verdict(as_of_date, recommendation="deploy_now"):
    return VerdictFact(
        recommendation=recommendation, wait_days_estimate=None, rationale="", as_of_date=as_of_date
    )


def test_slug_combines_vendor_and_source_id_and_is_url_safe():
    advisory = _advisory(1, source_vendor="cisco", source_advisory_id="cisco-sa-clamav-88cFYyxR")
    assert advisory.slug == "cisco-cisco-sa-clamav-88cfyyxr"


def test_slug_handles_msrc_style_ids():
    advisory = _advisory(1, source_vendor="microsoft", source_advisory_id="2026-Apr")
    assert advisory.slug == "microsoft-2026-apr"


def test_kev_listed_true_if_any_linked_cve_is_kev():
    advisory = _advisory(1, cves=[_cve("CVE-1", kev_listed=False), _cve("CVE-2", kev_listed=True)])
    assert advisory.kev_listed is True


def test_kev_listed_false_with_no_kev_cves():
    advisory = _advisory(1, cves=[_cve("CVE-1", kev_listed=False)])
    assert advisory.kev_listed is False


def test_max_cvss_ignores_null_scores():
    advisory = _advisory(
        1,
        cves=[
            _cve("CVE-1", cvss_score=None),
            _cve("CVE-2", cvss_score=Decimal("7.5")),
            _cve("CVE-3", cvss_score=Decimal("9.8")),
        ],
    )
    assert advisory.max_cvss == Decimal("9.8")


def test_max_cvss_is_none_with_no_scores():
    advisory = _advisory(1, cves=[_cve("CVE-1", cvss_score=None)])
    assert advisory.max_cvss is None


def test_recent_verdicts_sorted_most_recent_first_across_advisories():
    older = _advisory(1, kbs=[_kb("KB1", verdict=_verdict(date(2026, 1, 1)))])
    newer = _advisory(2, kbs=[_kb("KB2", verdict=_verdict(date(2026, 6, 1)))])

    result = recent_verdicts([older, newer], limit=10)

    assert [kb.kb_number for _, kb in result] == ["KB2", "KB1"]


def test_recent_verdicts_excludes_kbs_with_no_verdict():
    advisory = _advisory(1, kbs=[_kb("KB1", verdict=None), _kb("KB2", verdict=_verdict(date(2026, 1, 1)))])

    result = recent_verdicts([advisory], limit=10)

    assert [kb.kb_number for _, kb in result] == ["KB2"]


def test_recent_verdicts_respects_limit():
    advisory = _advisory(
        1,
        kbs=[_kb(f"KB{i}", verdict=_verdict(date(2026, 1, i))) for i in range(1, 6)],
    )

    result = recent_verdicts([advisory], limit=2)

    assert len(result) == 2


def test_latest_patch_tuesday_picks_most_recent_b_release_month():
    april = _advisory(
        1, source_advisory_id="2026-Apr", published_date=date(2026, 4, 14),
        kbs=[_kb("KB1", update_channel="b_release")],
    )
    june = _advisory(
        2, source_advisory_id="2026-Jun", published_date=date(2026, 6, 9),
        kbs=[_kb("KB2", update_channel="b_release")],
    )

    result = latest_patch_tuesday_advisories([april, june])

    assert result == [june]


def test_latest_patch_tuesday_ignores_non_microsoft_and_preview_only():
    cisco = _advisory(1, source_vendor="cisco", published_date=date(2026, 6, 9))
    preview_only = _advisory(
        2, source_advisory_id="2026-Jun-preview", published_date=date(2026, 6, 23),
        kbs=[_kb("KB3", update_channel="c_d_preview")],
    )

    result = latest_patch_tuesday_advisories([cisco, preview_only])

    assert result == []


def test_latest_patch_tuesday_empty_when_no_msrc_advisories():
    assert latest_patch_tuesday_advisories([]) == []


def test_compute_homepage_stats_counts_advisories_and_verdicts():
    advisory = _advisory(
        1,
        kbs=[
            _kb("KB1", verdict=_verdict(date(2026, 1, 1), "deploy_now")),
            _kb("KB2", verdict=_verdict(date(2026, 1, 2), "deploy_now")),
            _kb("KB3", verdict=_verdict(date(2026, 1, 3), "wait")),
        ],
    )

    stats = compute_homepage_stats([advisory])

    assert stats.total_advisories == 1
    assert stats.verdict_counts == {"deploy_now": 2, "wait": 1}


def test_compute_homepage_stats_ignores_kbs_with_no_verdict():
    advisory = _advisory(1, kbs=[_kb("KB1", verdict=None)])

    stats = compute_homepage_stats([advisory])

    assert stats.verdict_counts == {}


def test_compute_homepage_stats_finds_most_recent_kev_across_advisories():
    older_kev = _advisory(1, cves=[_cve("CVE-2025-1", kev_listed=True, kev_date_added=date(2025, 1, 1))])
    newer_kev = _advisory(2, cves=[_cve("CVE-2026-2", kev_listed=True, kev_date_added=date(2026, 6, 1))])
    non_kev = _advisory(3, cves=[_cve("CVE-2026-3", kev_listed=False)])

    stats = compute_homepage_stats([older_kev, newer_kev, non_kev])

    assert stats.most_recent_kev == ("CVE-2026-2", date(2026, 6, 1))


def test_compute_homepage_stats_most_recent_kev_none_when_no_kev_cves():
    advisory = _advisory(1, cves=[_cve("CVE-2026-1", kev_listed=False)])

    stats = compute_homepage_stats([advisory])

    assert stats.most_recent_kev is None
