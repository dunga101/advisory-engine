#!/usr/bin/env python3
"""Phase 5 verification: run the publisher once against the real public
site repo and report what happened. This pushes to a public GitHub repo —
only run this once github.com/dunga101/advisory-site exists and
GITHUB_PUSH_TOKEN is configured."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from publisher.config import PUBLISH_REPO_HOST_PATH
from publisher.publish import run_once


def main() -> None:
    print("Running publisher once against the real public site repo...")
    summary = run_once()
    print(f"  advisories published: {summary['advisories_published']}")
    print(f"  pushed:                {summary['pushed']}")
    print(f"  work_dir:              {summary['work_dir']}")
    if summary["commit_sha"]:
        print(f"  commit:                {summary['commit_sha']}")
        print(
            f"  commit URL:            https://github.com/{PUBLISH_REPO_HOST_PATH}"
            f"/commit/{summary['commit_sha']}"
        )
    else:
        print("  commit:                none — nothing changed since the last publish")


if __name__ == "__main__":
    main()
