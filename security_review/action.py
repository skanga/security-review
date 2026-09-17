"""Thin GitHub Action input/output boundary over the public engine."""
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import uuid

from . import ReviewReport, resolve_config, review
from .rendering import atomic_write, render_json


def _alias(environment, current, legacy, default=None):
    new, old = environment.get(current), environment.get(legacy)
    if new and old and new != old:
        raise ValueError(f"Conflicting {current}/{legacy} inputs")
    return new or old or default


def action_request(environment):
    model = _alias(environment, "REVIEW_MODEL", "CLAUDE_MODEL")
    timeout = environment.get("REVIEW_TIMEOUT_SECONDS")
    legacy_timeout = environment.get("CLAUDECODE_TIMEOUT")
    if timeout and legacy_timeout and int(timeout) != int(legacy_timeout) * 60:
        raise ValueError("Conflicting timeout inputs")
    timeout = int(timeout) if timeout else int(legacy_timeout) * 60 if legacy_timeout else None
    workspace = Path(environment.get("GITHUB_WORKSPACE", ".")).resolve()
    config = environment.get("REVIEW_CONFIG") or None
    scan_instructions = environment.get("CUSTOM_SECURITY_SCAN_INSTRUCTIONS") or None
    validation_instructions = environment.get("FALSE_POSITIVE_FILTERING_INSTRUCTIONS") or None
    for path in (config, scan_instructions, validation_instructions):
        if path and (workspace / path).resolve().is_relative_to(workspace):
            raise ValueError("PR configuration/instructions must be supplied outside the reviewed workspace from a trusted checkout")
    request = resolve_config(config, {"repository": workspace, "model": model,
        "validation_model": environment.get("REVIEW_VALIDATION_MODEL") or None,
        "backend": environment.get("REVIEW_BACKEND") or None,
        "timeout_seconds": timeout, "instructions_file": scan_instructions,
        "validation_instructions_file": validation_instructions,
        "pr": f"{environment.get('GITHUB_REPOSITORY', '')}#{environment.get('PR_NUMBER', '')}"}, environ=environment)
    excludes = tuple(item.strip().rstrip("/") + "/**" for item in environment.get("EXCLUDE_DIRECTORIES", "").split(",") if item.strip())
    if excludes:
        request = replace(request, policy=replace(request.policy, exclude_paths=request.policy.exclude_paths + excludes,
                                                 source="action-explicit-input"))
    return request


def execute(environment=None, *, scanner=review, publisher=None):
    environment = os.environ if environment is None else environment
    workspace = Path(environment.get("GITHUB_WORKSPACE", ".")).resolve()
    publication_status = "not_requested"
    artifact_failed = False
    report = ReviewReport(str(uuid.uuid4()))
    try:
        mode = environment.get("REVIEW_CI_MODE", "blocking")
        if mode not in {"blocking", "advisory"}:
            raise ValueError("ci-mode must be blocking or advisory")
        if environment.get("GITHUB_EVENT_NAME") != "pull_request":
            raise ValueError("Only pull_request events are supported; use the CLI for local/non-PR scans")
        request = action_request(environment)
        report = scanner(request)
    except Exception as exc:
        report.errors.append({"stage": "action", "code": "ACTION_CONFIGURATION", "retryable": False,
                              "message": f"Action setup/execution failed ({type(exc).__name__}); check trusted inputs, event, and credentials"})
        report.status, report.policy_outcome = "failed", "unknown"
    else:
        if environment.get("REVIEW_COMMENT_PR", "true") == "true":
            from .github import GitHubClient, GitHubPublisher, PublicationResult
            try:
                publisher = publisher or GitHubPublisher(GitHubClient(environment.get("GITHUB_PUBLISH_TOKEN") or environment.get("GITHUB_TOKEN")), actor="github-actions[bot]")
                publication = publisher.publish(report, request.pr)
            except Exception as exc:
                publication = PublicationResult(request.pr, report.run_id, report.snapshot.get("id", ""),
                    errors=[{"code": "PUBLICATION_FAILED", "retryable": isinstance(exc, TimeoutError),
                             "message": f"Publication failed ({type(exc).__name__}); retry the saved report"}])
            publication_status = publication.status
            try:
                atomic_write(workspace / "security-review-publication.json", json.dumps(publication.to_dict(), indent=2))
            except OSError:
                artifact_failed = True
                print("Could not write publication receipt; publication result follows", file=sys.stderr)
                print(json.dumps(publication.to_dict()), file=sys.stderr)
    destination = workspace / "security-review-results.json"
    report_written = False
    try:
        report.artifacts = [str(destination)]
        atomic_write(destination, render_json(report))
        report_written = True
    except OSError:
        artifact_failed = True
        report.artifacts = []
        print("Could not write requested scan report; JSON follows on stdout", file=sys.stderr)
        print(render_json(report), end="")
    try:
        outputs = {"scan-status": report.status, "policy-outcome": report.policy_outcome,
                   "findings-count": str(sum(f.get("reportable", False) for f in report.findings)),
                   "results-file": str(destination) if report_written else "", "publication-status": publication_status}
        if environment.get("GITHUB_OUTPUT"):
            with Path(environment["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
                for key, value in outputs.items():
                    if "\n" in value or "\r" in value:
                        raise ValueError("Invalid workflow output")
                    stream.write(f"{key}={value}\n")
    except (OSError, ValueError):
        artifact_failed = True
        print("Could not write workflow outputs; inspect the scan report", file=sys.stderr)
        if report_written:
            print(render_json(report), end="")
    if artifact_failed:
        return 2
    code = 2 if publication_status in {"failed", "stale"} else report.exit_code
    return 0 if environment.get("REVIEW_CI_MODE", "blocking") == "advisory" else code


if __name__ == "__main__":
    raise SystemExit(execute())
