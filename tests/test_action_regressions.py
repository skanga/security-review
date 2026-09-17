"""Action precedence and independent scan/publication/artifact outcomes."""
import json

import pytest

from security_review import ReviewReport
from security_review.action import action_request, execute
from security_review.config import DEFAULT_MODEL
from security_review.github import PublicationResult


def environment(workspace, **overrides):
    return dict(GITHUB_EVENT_NAME="pull_request", GITHUB_REPOSITORY="owner/repo", PR_NUMBER="7",
                GITHUB_WORKSPACE=str(workspace), GITHUB_OUTPUT=str(workspace / "outputs"), **overrides)


def scan(request):
    return ReviewReport("fixture", status="completed", policy_outcome="pass")


class Publisher:
    def __init__(self, status="published"):
        self.status = status

    def publish(self, report, target):
        return PublicationResult(target, report.run_id, "snapshot", status=self.status)


@pytest.mark.parametrize("mode", ["advisory", "blocking"])
@pytest.mark.parametrize("artifact", ["security-review-publication.json", "security-review-results.json", "outputs"])
def test_artifact_failures_are_errors_and_scan_report_stays_valid(tmp_path, capsys, mode, artifact):
    (tmp_path / artifact).mkdir()
    code = execute(environment(tmp_path, REVIEW_CI_MODE=mode), scanner=scan, publisher=Publisher())
    assert code == 2
    path = tmp_path / "security-review-results.json"
    output = capsys.readouterr()
    report = ReviewReport.from_dict(json.loads(path.read_text() if path.is_file() else output.out))
    assert report.status == "completed" and not report.errors
    assert report.artifacts == ([str(path)] if path.is_file() else [])
    if artifact != "outputs":
        assert "publication-status=published" in (tmp_path / "outputs").read_text()


@pytest.mark.parametrize("mode,expected", [("blocking", 2), ("advisory", 0)])
@pytest.mark.parametrize("raises", [False, True])
def test_publication_failure_preserves_valid_completed_scan(tmp_path, mode, expected, raises):
    class Failure(Publisher):
        def publish(self, report, target):
            if raises:
                raise TimeoutError("synthetic publisher failure")
            return super().publish(report, target)
    code = execute(environment(tmp_path, REVIEW_CI_MODE=mode), scanner=scan, publisher=Failure("failed"))
    assert code == expected
    saved = json.loads((tmp_path / "security-review-results.json").read_text())
    assert ReviewReport.from_dict(saved).status == "completed" and not saved["errors"]
    publication = json.loads((tmp_path / "security-review-publication.json").read_text())
    assert publication["status"] == "failed"


def configured_environment(tmp_path, settings, **overrides):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = tmp_path / "trusted.json"
    config.write_text(json.dumps(settings))
    return environment(workspace, REVIEW_CONFIG=str(config), **overrides)


@pytest.mark.parametrize("inputs,expected", [({}, 45), ({"REVIEW_TIMEOUT_SECONDS": ""}, 45),
    ({"SECURITY_REVIEW_TIMEOUT": "60"}, 60), ({"CLAUDECODE_TIMEOUT": "2"}, 120),
    ({"REVIEW_TIMEOUT_SECONDS": "90", "SECURITY_REVIEW_TIMEOUT": "60"}, 90)])
def test_action_timeout_precedence(tmp_path, inputs, expected):
    req = action_request(configured_environment(tmp_path, {"timeout_seconds": 45}, **inputs))
    assert req.timeout_seconds == expected


@pytest.mark.parametrize("inputs,expected", [({"REVIEW_MODEL": "investigator"}, "configured-validator"),
    ({"REVIEW_VALIDATION_MODEL": "", "CLAUDE_MODEL": "investigator"}, "configured-validator"),
    ({"REVIEW_MODEL": "investigator", "SECURITY_REVIEW_VALIDATION_MODEL": "env-validator"}, "env-validator"),
    ({"REVIEW_VALIDATION_MODEL": "explicit-validator"}, "explicit-validator")])
def test_action_preserves_independent_validation_model(tmp_path, inputs, expected):
    req = action_request(configured_environment(tmp_path, {"validation_model": "configured-validator"}, **inputs))
    assert req.validation_model == expected


def test_action_falls_back_only_after_merging_config(tmp_path):
    env = environment(tmp_path, REVIEW_TIMEOUT_SECONDS="", REVIEW_VALIDATION_MODEL="", REVIEW_BACKEND="")
    req = action_request(env)
    assert req.timeout_seconds == 1200
    assert req.model == req.validation_model == DEFAULT_MODEL and req.backend == "claude-code"
    req = action_request(dict(env, REVIEW_MODEL="explicit"))
    assert req.model == req.validation_model == "explicit"


def test_backend_action_default_does_not_mask_config(tmp_path):
    from pathlib import Path
    action = (Path(__file__).parents[1] / "action.yml").read_text()
    backend_input = action.split("  backend:\n", 1)[1].split("  config:\n", 1)[0]
    assert "default: ''" in backend_input
    req = action_request(configured_environment(tmp_path, {"backend": "custom"}, REVIEW_BACKEND=""))
    assert req.backend == "custom"
