import json
from pathlib import Path
import subprocess
import sys

import pytest
from test_standalone import history, FakeBackend, ConfirmingValidator
from security_review import ReviewReport

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("arguments", [["config", "show", "--redact"], ["backends", "list"]])
def test_introspection_requires_no_sdk(arguments):
    result = subprocess.run([sys.executable, "-S", "-m", "security_review", *arguments], cwd=ROOT,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)


def test_markdown_cli_and_contradictory_modes(history):
    repo, _, head = history
    result = subprocess.run([sys.executable, "-S", "-m", "security_review", "scan", "--repo", str(repo),
                             "--base", head, "--head", head, "--format", "markdown"], cwd=ROOT,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0 and "completed" in result.stdout
    result = subprocess.run([sys.executable, "-S", "-m", "security_review", "scan", "--repo", str(repo),
                             "--base", head, "--staged"], cwd=ROOT, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2


def test_action_outputs_and_blocking_use_engine_report(tmp_path):
    from security_review.action import execute
    def scan(request):
        return ReviewReport("fixture", status="partial", policy_outcome="unknown")
    environment = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": "owner/repo", "PR_NUMBER": "7",
                   "GITHUB_WORKSPACE": str(tmp_path), "GITHUB_OUTPUT": str(tmp_path / "outputs"),
                   "REVIEW_COMMENT_PR": "false", "REVIEW_CI_MODE": "blocking"}
    assert execute(environment, scanner=scan) == 2
    outputs = (tmp_path / "outputs").read_text()
    assert "scan-status=partial" in outputs and "policy-outcome=unknown" in outputs
    path = next(line.split("=", 1)[1] for line in outputs.splitlines() if line.startswith("results-file="))
    assert Path(path).is_file()
    assert json.loads(Path(path).read_text())["status"] == "partial"
    environment["REVIEW_CI_MODE"] = "advisory"
    assert execute(environment, scanner=scan) == 0


def test_action_alias_conflict_is_rejected(tmp_path):
    from security_review.action import action_request
    with pytest.raises(ValueError, match="Conflicting"):
        action_request({"GITHUB_WORKSPACE": str(tmp_path), "REVIEW_MODEL": "one", "CLAUDE_MODEL": "two"})


def test_action_yaml_is_a_thin_pinned_engine_wrapper():
    text = (ROOT / "action.yml").read_text()
    assert "python -I -m security_review.action" in text
    assert "marker.json" not in text
    assert "@anthropic-ai/claude-code@" in text
    for name in ("scan-status", "policy-outcome", "publication-status", "results-file"):
        assert name in text
