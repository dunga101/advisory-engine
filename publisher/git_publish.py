import base64
import re
import shutil
import subprocess
from pathlib import Path

REDACTED = "***REDACTED***"

# Belt-and-braces pattern scrub, independent of any specific secret value
# we were handed this call — catches a token leaking via some future
# regression (e.g. a token accidentally reappearing in a URL) even if the
# literal value isn't in the `secrets` list passed to _run.
_TOKEN_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # classic PAT prefixes (ghp_/gho_/ghu_/ghs_/ghr_)
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),  # fine-grained PAT
    re.compile(r"x-access-token:[^@\s]+@"),  # token embedded in a URL
]


class GitPublishError(Exception):
    pass


def _scrub(text: str, secrets: list[str] | None = None) -> str:
    for secret in secrets or ():
        if secret:
            text = text.replace(secret, REDACTED)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def _auth_header(token: str) -> str:
    """HTTP Basic auth header value for GitHub's x-access-token convention.
    Passed only via `-c http.extraheader=...` on the single git invocation
    that needs network auth (fetch/push) — never via a token-embedded
    remote URL, and never written to the repo's persisted .git/config."""
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return f"Authorization: Basic {basic}"


def _run(
    cmd: list[str], cwd: Path, secrets: list[str] | None = None
) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        cmd_str = _scrub(" ".join(cmd), secrets)
        stderr = _scrub(result.stderr.strip(), secrets)
        raise GitPublishError(f"{cmd_str} failed: {stderr}")
    return result


def _authed_run(
    cmd: list[str], cwd: Path, token: str | None
) -> subprocess.CompletedProcess:
    """Run a git command that needs GitHub auth (fetch/push). The
    Authorization header is injected only for this one invocation via -c
    http.extraheader, so it never persists in the working copy's git
    config — even transiently. Both the raw token and the derived header
    (which trivially decodes back to it) are redacted from any error this
    raises."""
    if not token:
        return _run(cmd, cwd)
    header = _auth_header(token)
    authed_cmd = [cmd[0], "-c", f"http.extraheader={header}", *cmd[1:]]
    return _run(authed_cmd, cwd, secrets=[token, header])


def _fetch(repo_dir: Path, branch: str, token: str | None) -> subprocess.CompletedProcess:
    """Fetch without raising on failure — callers decide what a failed
    fetch means (e.g. "remote repo doesn't exist yet" during first-ever
    publish is expected, not an error)."""
    cmd = ["git", "fetch", "origin", branch]
    if not token:
        return subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True)
    header = _auth_header(token)
    authed_cmd = [cmd[0], "-c", f"http.extraheader={header}", *cmd[1:]]
    return subprocess.run(authed_cmd, cwd=repo_dir, capture_output=True, text=True)


def prepare_working_copy(
    repo_dir: Path, remote_url: str, branch: str, token: str | None = None
) -> None:
    """Bring repo_dir to a clean checkout of origin/<branch>. If the remote
    has no commits yet (first-ever publish to a brand-new repo), falls back
    to a fresh local branch with no parent history."""
    if (repo_dir / ".git").exists():
        fetch = _fetch(repo_dir, branch, token)
        if fetch.returncode != 0:
            raise GitPublishError(
                f"git fetch origin {branch} failed: {_scrub(fetch.stderr.strip(), [token] if token else None)}"
            )
        _run(["git", "checkout", branch], cwd=repo_dir)
        _run(["git", "reset", "--hard", f"origin/{branch}"], cwd=repo_dir)
        return

    repo_dir.mkdir(parents=True, exist_ok=True)
    _run(["git", "init"], cwd=repo_dir)
    _run(["git", "remote", "add", "origin", remote_url], cwd=repo_dir)
    fetch = _fetch(repo_dir, branch, token)
    if fetch.returncode == 0:
        _run(["git", "checkout", "-B", branch, f"origin/{branch}"], cwd=repo_dir)
    else:
        _run(["git", "checkout", "-B", branch], cwd=repo_dir)


def clear_tracked_content(repo_dir: Path) -> None:
    """Wipe everything except .git before regenerating — publisher always
    does a full rebuild, never an incremental patch."""
    for item in repo_dir.iterdir():
        if item.name == ".git":
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()


def commit_and_push(
    repo_dir: Path,
    branch: str,
    message: str,
    author_name: str,
    author_email: str,
    token: str | None = None,
) -> str | None:
    """Returns the new commit SHA if there was something to commit and it
    was pushed, None if the working tree was already identical to what's
    already published (nothing new to publish)."""
    _run(["git", "add", "-A"], cwd=repo_dir)
    status = _run(["git", "status", "--porcelain"], cwd=repo_dir)
    if not status.stdout.strip():
        return None

    _run(
        [
            "git",
            "-c",
            f"user.name={author_name}",
            "-c",
            f"user.email={author_email}",
            "commit",
            "-m",
            message,
        ],
        cwd=repo_dir,
    )
    _authed_run(["git", "push", "origin", branch], cwd=repo_dir, token=token)
    return _run(["git", "rev-parse", "HEAD"], cwd=repo_dir).stdout.strip()
