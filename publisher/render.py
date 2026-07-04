import json
import shutil
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from publisher.cwe_names import describe_cwe
from publisher.data import AdvisoryFact, HomepageStats, KbFact

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _format_cvss(score) -> str:
    return "Not yet scored" if score is None else str(score)


_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["describe_cwe"] = describe_cwe
_env.filters["format_cvss"] = _format_cvss


def write_site(
    output_dir: Path,
    advisories: list[AdvisoryFact],
    recent: list[tuple[AdvisoryFact, KbFact]],
    digest: list[AdvisoryFact],
    stats: HomepageStats,
    generated_at: datetime,
) -> None:
    """Full rebuild — always regenerates every file from current DB state,
    never an incremental patch. Caller is responsible for having already
    cleared any prior content in output_dir."""
    (output_dir / "advisories").mkdir(parents=True, exist_ok=True)
    (output_dir / "digest").mkdir(parents=True, exist_ok=True)
    (output_dir / "static").mkdir(parents=True, exist_ok=True)

    shutil.copy(STATIC_DIR / "style.css", output_dir / "static" / "style.css")

    index_html = _env.get_template("index.html").render(
        advisories=advisories, recent=recent, digest=digest, stats=stats, generated_at=generated_at
    )
    (output_dir / "index.html").write_text(index_html)

    for advisory in advisories:
        page_html = _env.get_template("advisory.html").render(
            advisory=advisory, generated_at=generated_at
        )
        (output_dir / "advisories" / f"{advisory.slug}.html").write_text(page_html)

    digest_html = _env.get_template("digest.html").render(
        advisories=digest, generated_at=generated_at
    )
    (output_dir / "digest" / "index.html").write_text(digest_html)

    # Machine-readable freshness signal for external monitoring (the
    # publisher's dead-man's-switch freshness check reads this) — the
    # footer's human-readable timestamp isn't a stable parse target.
    status = {
        "generated_at": generated_at.isoformat(),
        "advisories_published": len(advisories),
    }
    (output_dir / "status.json").write_text(json.dumps(status))
