import base64
import subprocess

import pytest

from publisher.git_publish import (
    GitPublishError,
    _auth_header,
    _scrub,
    clear_tracked_content,
    commit_and_push,
    prepare_working_copy,
)

FAKE_TOKEN = "ghp_faketokenvalue1234567890abcdef"


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def bare_remote(tmp_path):
    remote_dir = tmp_path / "remote.git"
    _git(["init", "--bare", "-q", str(remote_dir)], cwd=tmp_path)
    return remote_dir


def test_auth_header_is_basic_x_access_token():
    header = _auth_header(FAKE_TOKEN)
    expected_basic = base64.b64encode(f"x-access-token:{FAKE_TOKEN}".encode()).decode()
    assert header == f"Authorization: Basic {expected_basic}"


def test_scrub_redacts_literal_secret():
    text = f"remote rejected: bad credentials for token {FAKE_TOKEN}"
    assert FAKE_TOKEN not in _scrub(text, secrets=[FAKE_TOKEN])


def test_scrub_redacts_ghp_pattern_even_without_secrets_list():
    text = f"fatal: authentication failed for token {FAKE_TOKEN}"
    scrubbed = _scrub(text)
    assert FAKE_TOKEN not in scrubbed


def test_scrub_redacts_github_pat_pattern():
    token = "github_pat_11ABCDEFG0123456789012345678901234567890abcdefghijklmno"
    text = f"push failed: {token}"
    assert token not in _scrub(text)


def test_scrub_redacts_token_embedded_in_url_shape():
    text = f"fatal: unable to access 'https://x-access-token:{FAKE_TOKEN}@github.com/foo/bar.git/'"
    scrubbed = _scrub(text)
    assert FAKE_TOKEN not in scrubbed
    assert "x-access-token:" not in scrubbed


def test_resolve_remote_url_never_embeds_token(monkeypatch):
    monkeypatch.setenv("GITHUB_PUSH_TOKEN", FAKE_TOKEN)
    from publisher.remote import resolve_remote_url

    url = resolve_remote_url()
    assert FAKE_TOKEN not in url
    assert "x-access-token" not in url


def test_full_publish_cycle_never_persists_token_in_git_config(tmp_path, bare_remote):
    """End-to-end: prepare -> write a file -> commit_and_push with a token,
    against a real (local) git remote. The token must never appear in
    .git/config, even transiently, because it's only ever passed via a
    per-invocation -c http.extraheader flag."""
    work_dir = tmp_path / "work"

    prepare_working_copy(work_dir, str(bare_remote), "main", token=FAKE_TOKEN)
    (work_dir / "index.html").write_text("hello")
    sha = commit_and_push(
        work_dir,
        "main",
        message="test publish",
        author_name="tester",
        author_email="tester@example.com",
        token=FAKE_TOKEN,
    )

    assert sha is not None
    config_text = (work_dir / ".git" / "config").read_text()
    assert FAKE_TOKEN not in config_text
    assert "extraheader" not in config_text

    # Re-fetch from a second working copy to prove the push actually landed.
    second_work_dir = tmp_path / "work2"
    prepare_working_copy(second_work_dir, str(bare_remote), "main", token=FAKE_TOKEN)
    assert (second_work_dir / "index.html").read_text() == "hello"
    second_config_text = (second_work_dir / ".git" / "config").read_text()
    assert FAKE_TOKEN not in second_config_text


def test_clear_tracked_content_preserves_git_dir(tmp_path, bare_remote):
    work_dir = tmp_path / "work"
    prepare_working_copy(work_dir, str(bare_remote), "main", token=FAKE_TOKEN)
    (work_dir / "stale.html").write_text("old")
    clear_tracked_content(work_dir)
    assert not (work_dir / "stale.html").exists()
    assert (work_dir / ".git").exists()


def test_commit_and_push_returns_none_when_nothing_changed(tmp_path, bare_remote):
    work_dir = tmp_path / "work"
    prepare_working_copy(work_dir, str(bare_remote), "main", token=FAKE_TOKEN)
    (work_dir / "index.html").write_text("hello")
    commit_and_push(
        work_dir,
        "main",
        message="first",
        author_name="tester",
        author_email="tester@example.com",
        token=FAKE_TOKEN,
    )

    second_sha = commit_and_push(
        work_dir,
        "main",
        message="second (no changes)",
        author_name="tester",
        author_email="tester@example.com",
        token=FAKE_TOKEN,
    )
    assert second_sha is None


def test_push_failure_error_message_never_contains_raw_token(tmp_path):
    """Point origin at a nonexistent path so push fails, then confirm the
    raised GitPublishError's message never contains the raw token — the
    exact failure mode that will happen daily once the PAT expires."""
    work_dir = tmp_path / "work"
    nonexistent_remote = str(tmp_path / "does-not-exist.git")

    work_dir.mkdir()
    _git(["init", "-q"], cwd=work_dir)
    _git(["config", "user.email", "tester@example.com"], cwd=work_dir)
    _git(["config", "user.name", "tester"], cwd=work_dir)
    _git(["remote", "add", "origin", nonexistent_remote], cwd=work_dir)
    (work_dir / "index.html").write_text("hello")

    with pytest.raises(GitPublishError) as exc_info:
        commit_and_push(
            work_dir,
            "main",
            message="test",
            author_name="tester",
            author_email="tester@example.com",
            token=FAKE_TOKEN,
        )
    assert FAKE_TOKEN not in str(exc_info.value)


def test_prepare_working_copy_fresh_repo_no_remote_history(tmp_path, bare_remote):
    """First-ever publish to a brand-new (empty) bare repo falls back to a
    fresh local branch with no parent history, and still never persists
    the token."""
    work_dir = tmp_path / "work"
    prepare_working_copy(work_dir, str(bare_remote), "main", token=FAKE_TOKEN)
    assert (work_dir / ".git").exists()
    config_text = (work_dir / ".git" / "config").read_text()
    assert FAKE_TOKEN not in config_text


def test_prepare_working_copy_without_token_still_works_for_unauthenticated_remote(
    tmp_path, bare_remote
):
    work_dir = tmp_path / "work"
    prepare_working_copy(work_dir, str(bare_remote), "main", token=None)
    assert (work_dir / ".git").exists()
