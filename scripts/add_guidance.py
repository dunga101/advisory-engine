#!/usr/bin/env python3
"""Manually author an advisory_guidance row. Phase 4's pre-check engine and
Phase 6's AI drafting don't exist yet (build brief Section 10), so guidance is
hand-written for now: verification_status is always human_verified (a human
wrote it directly, nothing was ai_drafted), and publish_status stays draft
unless --publish is passed, keeping an explicit gate before anything goes live."""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.db import get_session_factory
from common.models import AdvisoryGuidance


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--advisory-id", type=int, required=True)
    parser.add_argument("--plain-english-summary")
    parser.add_argument("--what-to-backup")
    parser.add_argument("--deployment-notes")
    parser.add_argument("--known-issues-after-patch")
    parser.add_argument("--rollback-procedure")
    parser.add_argument("--post-patch-verification")
    parser.add_argument("--reviewed-by")
    parser.add_argument("--publish", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    session_factory = get_session_factory()
    with session_factory() as session:
        guidance = AdvisoryGuidance(
            advisory_id=args.advisory_id,
            plain_english_summary=args.plain_english_summary,
            what_to_backup=args.what_to_backup,
            deployment_notes=args.deployment_notes,
            known_issues_after_patch=args.known_issues_after_patch,
            rollback_procedure=args.rollback_procedure,
            post_patch_verification=args.post_patch_verification,
            publish_status="published" if args.publish else "draft",
            verification_status="human_verified",
            reviewed_by=args.reviewed_by,
            published_at=datetime.now(timezone.utc) if args.publish else None,
        )
        session.add(guidance)
        session.commit()
        print(f"advisory_guidance row created: id={guidance.id} publish_status={guidance.publish_status}")


if __name__ == "__main__":
    main()
