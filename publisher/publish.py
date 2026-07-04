import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from publisher.config import (
    GIT_COMMIT_AUTHOR_EMAIL,
    GIT_COMMIT_AUTHOR_NAME,
    PUBLISH_REPO_BRANCH,
    RECENT_VERDICTS_LIMIT,
)
from publisher.data import (
    compute_homepage_stats,
    gather_published_advisories,
    latest_patch_tuesday_advisories,
    recent_verdicts,
)
from publisher.git_publish import clear_tracked_content, commit_and_push, prepare_working_copy
from publisher.remote import resolve_push_token, resolve_remote_url
from publisher.render import write_site

logger = logging.getLogger(__name__)


def run_once(
    *,
    work_dir: Path | None = None,
    remote_url: str | None = None,
    push_token: str | None = None,
    push: bool = True,
) -> dict:
    """Query every publish_status='published'/verification_status='approved'
    advisory, regenerate the entire static site from scratch, and push it to
    the public site repo. work_dir/remote_url/push_token/push are
    overridable for local preview and testing — production calls
    (scheduler, main.py) use the defaults: a scratch temp dir, the real
    public repo, GITHUB_PUSH_TOKEN from the environment, and an actual
    push."""
    owns_work_dir = work_dir is None
    work_dir = work_dir or Path(tempfile.mkdtemp(prefix="advisory-site-"))
    remote_url = remote_url or resolve_remote_url()
    push_token = push_token if push_token is not None else resolve_push_token()

    try:
        advisories = gather_published_advisories()
        generated_at = datetime.now(timezone.utc)
        recent = recent_verdicts(advisories, limit=RECENT_VERDICTS_LIMIT)
        digest = latest_patch_tuesday_advisories(advisories)
        stats = compute_homepage_stats(advisories)

        prepare_working_copy(work_dir, remote_url, PUBLISH_REPO_BRANCH, token=push_token)
        clear_tracked_content(work_dir)
        write_site(work_dir, advisories, recent, digest, stats, generated_at)

        commit_sha = None
        if push:
            commit_sha = commit_and_push(
                work_dir,
                PUBLISH_REPO_BRANCH,
                message=f"Publish {len(advisories)} advisories ({generated_at.isoformat()})",
                author_name=GIT_COMMIT_AUTHOR_NAME,
                author_email=GIT_COMMIT_AUTHOR_EMAIL,
                token=push_token,
            )

        summary = {
            "advisories_published": len(advisories),
            "pushed": commit_sha is not None,
            "commit_sha": commit_sha,
            "work_dir": str(work_dir),
        }
        logger.info("Publisher run complete: %s", summary)
        return summary
    finally:
        if owns_work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)
