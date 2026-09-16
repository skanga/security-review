"""The first standalone path uses real disposable Git histories and fake analysis."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def git(repo, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "-c", "commit.gpgsign=false", "-C", str(repo), *args],
        check=True, capture_output=True, text=True, timeout=20,
    ).stdout.strip()


@pytest.fixture
def history(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "app.py").write_text("safe = True\n", encoding="utf-8")
    git(repo, "add", "app.py")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("safe = False\n", encoding="utf-8")
    git(repo, "add", "app.py")
    git(repo, "commit", "-qm", "change")
    return repo, base, git(repo, "rev-parse", "HEAD")


def test_cli_help_does_not_require_provider_sdks():
    result = subprocess.run([sys.executable, "-S", "-m", "security_review", "--help"],
                            cwd=ROOT, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "scan" in result.stdout


def test_snapshot_uses_commits_and_survives_checkout_changes(history):
    from security_review.repository import capture
    from security_review import ReviewRequest
    repo, base, head = history
    snapshot = capture(ReviewRequest(repo, base, head))
    (repo / "app.py").write_text("uncommitted change\n", encoding="utf-8")
    assert snapshot.read("app.py", "head") == "safe = False\n"
    assert snapshot.read("app.py", "base") == "safe = True\n"
    assert snapshot.head == head
    assert snapshot.changed_files == ("app.py",)
    with pytest.raises(ValueError):
        snapshot.read("../outside.txt")
    with pytest.raises(TypeError):
        snapshot.head_files["app.py"] = b"changed"


def test_snapshot_rejects_option_like_revision(history):
    from security_review.repository import capture
    from security_review import ReviewRequest
    repo, _, head = history
    with pytest.raises(ValueError):
        capture(ReviewRequest(repo, "--help", head))


class FakeBackend:
    def __init__(self, severity=None, completed=True, invalid_line=False):
        self.severity = severity
        self.completed = completed
        self.invalid_line = invalid_line

    def investigate(self, snapshot, request):
        from security_review import InvestigationResult
        findings = [] if self.severity is None else [{
            "file": "app.py", "line": 200 if self.invalid_line else 1,
            "severity": self.severity, "description": "Fixture vulnerability",
            "category": "test", "exploit_scenario": "Fixture attack path",
            "recommendation": "Restore guard", "confidence": 0.9,
        }]
        return InvestigationResult(findings, list(snapshot.changed_files) if self.completed else [])


class ConfirmingValidator:
    def validate(self, finding, snapshot, request):
        from security_review import ValidationResult
        return ValidationResult("confirmed", 0.9, "Verified against fixture")


@pytest.mark.parametrize("severity,code,outcome", [
    ("HIGH", 1, "fail"), ("MEDIUM", 0, "pass"), ("LOW", 0, "pass"),
    ("CRITICAL", 0, "pass"), (None, 0, "pass"),
])
def test_high_is_the_only_default_blocking_severity(history, severity, code, outcome):
    from security_review import ReviewRequest, review
    report = review(ReviewRequest(*history), FakeBackend(severity), ConfirmingValidator())
    assert report.status == "completed"
    assert report.policy_outcome == outcome
    assert report.exit_code == code
    json.dumps(report.to_dict(), allow_nan=False)


def test_missing_coverage_cannot_pass(history):
    from security_review import ReviewRequest, review
    report = review(ReviewRequest(*history), FakeBackend(completed=False), ConfirmingValidator())
    assert report.status in {"partial", "failed"}
    assert report.policy_outcome == "unknown"
    assert report.exit_code == 2
    assert report.coverage["incomplete"] == ["app.py"]


def test_bad_finding_location_is_an_operational_gap(history):
    from security_review import ReviewRequest, review
    report = review(ReviewRequest(*history), FakeBackend("HIGH", invalid_line=True), ConfirmingValidator())
    assert report.status == "partial"
    assert report.exit_code == 2
    assert report.errors


def test_validator_failure_preserves_candidate_without_fake_confidence(history):
    from security_review import ReviewRequest, review

    class BrokenValidator:
        def validate(self, *args):
            raise TimeoutError("fixture timeout")

    report = review(ReviewRequest(*history), FakeBackend("HIGH"), BrokenValidator())
    assert report.status == "partial"
    assert report.exit_code == 2
    assert report.findings[0]["validation_status"] == "unvalidated"
    assert report.findings[0]["confidence"] is None


def test_backend_failure_cannot_be_a_clean_scan(history):
    from security_review import ReviewRequest, review

    class BrokenBackend:
        def investigate(self, *args):
            raise RuntimeError("fixture failure")

    report = review(ReviewRequest(*history), BrokenBackend(), ConfirmingValidator())
    assert report.status == "failed"
    assert report.policy_outcome == "unknown"
    assert report.exit_code == 2


def test_empty_changes_do_not_call_backend(history):
    from security_review import ReviewRequest, review
    repo, _, head = history

    class NeverBackend:
        def investigate(self, *args):
            pytest.fail("No analysis needed for no changed files")

    report = review(ReviewRequest(repo, head, head), NeverBackend(), ConfirmingValidator())
    assert report.exit_code == 0
    assert report.coverage["eligible"] == []


def test_cli_empty_scan_is_json_without_cloud_credentials(history):
    repo, _, head = history
    env = {k: v for k, v in os.environ.items() if k not in {
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN"}}
    result = subprocess.run([
        sys.executable, "-S", "-m", "security_review", "scan", "--repo", str(repo),
        "--base", head, "--head", head], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "completed"
    assert report["policy_outcome"] == "pass"


def test_cli_invalid_source_returns_machine_readable_failure(tmp_path):
    result = subprocess.run([
        sys.executable, "-m", "security_review", "scan", "--repo", str(tmp_path),
        "--base", "main", "--head", "HEAD"], cwd=ROOT,
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "failed"


def test_invalid_deadline_rejected_before_backend(history):
    from security_review import ReviewRequest
    with pytest.raises(ValueError):
        ReviewRequest(*history, timeout_seconds=0)


def test_low_confidence_confirmation_does_not_block(history):
    from security_review import ReviewRequest, ValidationResult, review

    class LowConfidence:
        def validate(self, *args):
            return ValidationResult("confirmed", 0.3, "Insufficient confidence")

    report = review(ReviewRequest(*history), FakeBackend("HIGH"), LowConfidence())
    assert report.exit_code == 0
    assert report.findings[0]["validation_status"] == "uncertain"


def test_unknown_coverage_is_rejected(history):
    from security_review import InvestigationResult, ReviewRequest, review

    class WrongCoverage:
        def investigate(self, *args):
            return InvestigationResult([], ["does-not-exist.py"])

    assert review(ReviewRequest(*history), WrongCoverage()).exit_code == 2


def test_deleted_file_evidence_uses_base_side(history):
    from security_review import InvestigationResult, ReviewRequest, review
    repo, _, base = history
    git(repo, "rm", "app.py")
    git(repo, "commit", "-qm", "remove guard")

    class DeletedFinding:
        def investigate(self, *args):
            return InvestigationResult([{"file": "app.py", "line": 1, "side": "base",
                                         "severity": "HIGH", "description": "Guard removed", "category": "authorization",
                                         "exploit_scenario": "Access without guard", "recommendation": "Restore guard"}], ["app.py"])

    report = review(ReviewRequest(repo, base, "HEAD"), DeletedFinding(), ConfirmingValidator())
    assert report.exit_code == 1
    assert report.findings[0]["side"] == "base"


def test_cli_failed_export_preserves_json_on_stdout(history, tmp_path):
    repo, _, head = history
    result = subprocess.run([
        sys.executable, "-m", "security_review", "scan", "--repo", str(repo),
        "--base", head, "--head", head, "--output", str(tmp_path / "missing" / "report.json")],
        cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "completed"


def test_validator_interrupt_preserves_current_candidate(history):
    from security_review import ReviewRequest, review

    class Interrupted:
        def validate(self, *args):
            raise KeyboardInterrupt()

    report = review(ReviewRequest(*history), FakeBackend("HIGH"), Interrupted())
    assert report.status == "cancelled"
    assert report.exit_code == 3
    assert len(report.findings) == 1
    assert report.findings[0]["validation_status"] == "unvalidated"


def test_compatibility_adapter_uses_snapshot_and_restricted_environment(history, monkeypatch):
    from security_review import ReviewRequest
    from security_review.repository import capture
    from security_review.claude_backend import ClaudeCodeBackend
    request = ReviewRequest(*history, model="fixture-model")
    snapshot = capture(request)
    (history[0] / "app.py").write_text("later edit")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-inherit")
    def run(command, **kwargs):
        assert (kwargs["cwd"] / "app.py").read_text() == "safe = False\n"
        assert "GITHUB_TOKEN" not in kwargs["env"]
        assert command[command.index("--model") + 1] == "fixture-model"
        assert command[command.index("--tools") + 1] == "Read,Glob,Grep"
        inner = {"findings": [], "assessed_files": ["app.py"], "analysis_summary": {"review_completed": True}}
        return subprocess.CompletedProcess(command, 0, json.dumps({"result": json.dumps(inner)}).encode(), b"")
    monkeypatch.setattr("security_review.claude_backend.run_process", run)
    assert ClaudeCodeBackend().investigate(snapshot, request).assessed_files == ["app.py"]


def test_read_only_runner_restricts_tools_and_does_not_retry(tmp_path, monkeypatch):
    from claudecode.github_action_audit import SimpleClaudeRunner
    calls = []

    def failed_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, "", "fixture failure")

    monkeypatch.setattr(subprocess, "run", failed_run)
    monkeypatch.setattr("claudecode.github_action_audit.time.sleep", lambda _: None)
    runner = SimpleClaudeRunner()
    runner.read_only = True
    assert runner.run_security_audit(tmp_path, "review")[0] is False
    assert len(calls) == 1
    command = calls[0]
    assert command[command.index("--tools") + 1] == "Read,Glob,Grep"
    assert "--restricted" in command
    assert "--bare" in command
    assert "-p" in command
    assert command[command.index("--mcp-config") + 1] == '{"mcpServers":{}}'


def test_validator_reads_immutable_evidence(history, monkeypatch):
    from security_review import ReviewRequest
    from security_review.repository import capture
    from security_review.claude_backend import ClaudeFindingValidator
    request = ReviewRequest(*history, model="fixture-model")
    snapshot = capture(request)
    (history[0] / "app.py").write_text("later edit")
    def run(command, **kwargs):
        payload = json.loads(kwargs["input"])
        assert payload["evidence"]["base"] == "safe = True\n"
        return subprocess.CompletedProcess(command, 0, b'{"status":"confirmed","confidence":0.9,"justification":"verified"}', b'')
    monkeypatch.setattr("security_review.claude_backend.run_process", run)
    result = ClaudeFindingValidator().validate({"file": "app.py", "side": "base"}, snapshot, request)
    assert result.status == "confirmed"
    assert result.confidence == 0.9
