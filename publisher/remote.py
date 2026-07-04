import os

from publisher.config import PUBLISH_REPO_HOST_PATH


def resolve_remote_url() -> str:
    """Build the git remote URL for the public site repo. Always the plain
    clean URL — GITHUB_PUSH_TOKEN is never embedded here. Auth (when
    needed) is injected per-invocation in publisher/git_publish.py via
    `-c http.extraheader`, not via a token-in-URL remote, so the token
    never lands in .git/config or in any URL that could be logged."""
    return f"https://github.com/{PUBLISH_REPO_HOST_PATH}.git"


def resolve_push_token() -> str | None:
    """GITHUB_PUSH_TOKEN is read from the environment only — never
    hardcoded, never logged. None means push operations will fail
    (expected/fine for local/preview runs against a repo that doesn't
    require auth); push=False callers don't need it at all."""
    return os.environ.get("GITHUB_PUSH_TOKEN")
