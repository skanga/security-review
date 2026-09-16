"""Safe report rendering and atomic local artifacts."""
import html
import json
from pathlib import Path
import re
import tempfile
import unicodedata


def safe_text(value):
    text = html.escape(str(value), quote=True)
    text = " ".join(text.splitlines())
    text = "".join(char for char in text if not unicodedata.category(char).startswith("C"))
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~:-])", r"\\\1", text)


def render_json(report):
    return json.dumps(report.to_dict(), indent=2, allow_nan=False) + "\n"


def render_markdown(report):
    lines = ["# Security review", "", f"Status: **{safe_text(report.status)}**  ",
             f"Policy: **{safe_text(report.policy_outcome)}**", "",
             f"Assessed {len(report.coverage['assessed'])} of {len(report.coverage['eligible'])} eligible files."]
    for name in ("incomplete", "excluded"):
        if report.coverage.get(name):
            lines += ["", f"{name.title()}: {safe_text(report.coverage[name])}"]
    for finding in report.findings + report.suppressed_findings:
        lines += ["", f"## {safe_text(finding['severity'])}: {safe_text(finding.get('title', finding.get('description', 'Finding')))}",
                  "", f"{safe_text(finding['file'])}:{finding['line']} — {safe_text(finding['validation_status'])}",
                  "", safe_text(finding.get("description", "")), "",
                  f"Policy decision: {safe_text(finding.get('policy_decision', 'retained'))}"]
    if report.errors:
        lines += ["", "## Execution errors", ""]
        lines += [f"- {safe_text(error['stage'])}: {safe_text(error['message'])}" for error in report.errors]
    return "\n".join(lines) + "\n"


def atomic_write(destination, content):
    destination = Path(destination).absolute()
    if any(path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())
           for path in (destination, *destination.parents)):
        raise OSError("Artifact paths must not traverse filesystem links")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False,
                                         dir=destination.parent, prefix=".review-") as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
        temporary.replace(destination)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
