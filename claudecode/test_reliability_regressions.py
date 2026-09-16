"""Regression cases reproduced during the generic-tool assessment (offline)."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from claudecode.claude_api_client import ClaudeAPIClient
from claudecode.evals.eval_engine import EvalCase, EvaluationEngine
from claudecode.findings_filter import FindingsFilter, HardExclusionRules
from claudecode.github_action_audit import SimpleClaudeRunner, initialize_clients


@pytest.mark.parametrize("inner", [
    "not a report", "{}", "[]",
    '{"findings": [], "analysis_summary": {"review_completed": false}}',
    '{"findings": {}, "analysis_summary": {"review_completed": true}}',
    '{"findings": [null], "analysis_summary": {"review_completed": true}}',
])
def test_invalid_inner_report_is_not_success(tmp_path, monkeypatch, inner):
    monkeypatch.setattr("claudecode.github_action_audit.subprocess.run", Mock(
        return_value=Mock(returncode=0, stdout=json.dumps({"result": inner}), stderr="")))
    success, error, _ = SimpleClaudeRunner().run_security_audit(tmp_path, "review")
    assert not success
    assert error


def test_error_envelope_cannot_hide_behind_valid_findings(tmp_path, monkeypatch):
    report = {"findings": [], "analysis_summary": {"review_completed": True}}
    envelope = {"is_error": True, "result": json.dumps(report)}
    monkeypatch.setattr("claudecode.github_action_audit.subprocess.run", Mock(
        return_value=Mock(returncode=0, stdout=json.dumps(envelope), stderr="")))
    assert SimpleClaudeRunner().run_security_audit(tmp_path, "review")[0] is False


@pytest.mark.parametrize("report", [
    {"error": "Security audit failed: timeout"},
    {"findings": [], "analysis_summary": {"review_completed": False}},
    [],
])
def test_evaluation_rejects_error_and_incomplete_reports(tmp_path, monkeypatch, report):
    engine = object.__new__(EvaluationEngine)
    engine.claude_api_key = "synthetic"
    engine.github_token = "synthetic"
    engine.verbose = False
    monkeypatch.setattr("claudecode.evals.eval_engine.subprocess.run", Mock(
        return_value=Mock(returncode=1, stdout=json.dumps(report), stderr="")))
    success, _, _, error = engine._run_sast_audit(EvalCase("example/repo", 1), str(tmp_path))
    assert not success
    assert error


@pytest.mark.parametrize("path_kind", ["parent", "absolute", "backslash_parent"])
def test_evidence_read_cannot_escape_repository(tmp_path, monkeypatch, path_kind):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("synthetic secret", encoding="utf-8")
    monkeypatch.setenv("REPO_PATH", str(repo))
    paths = {"parent": "../outside.txt", "absolute": str(outside),
             "backslash_parent": "..\\outside.txt"}
    success, content, error = object.__new__(ClaudeAPIClient)._read_file(paths[path_kind])
    assert not success
    assert content == ""
    assert error


def test_evidence_read_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("REPO_PATH", str(tmp_path))
    (tmp_path / "large.txt").write_bytes(b"x" * (1024 * 1024 + 1))
    success, content, _ = object.__new__(ClaudeAPIClient)._read_file("large.txt")
    assert not success
    assert content == ""


def test_evidence_read_allows_regular_repository_file(tmp_path, monkeypatch):
    monkeypatch.setenv("REPO_PATH", str(tmp_path))
    (tmp_path / "source.py").write_text("print('hello')", encoding="utf-8")
    assert object.__new__(ClaudeAPIClient)._read_file("source.py") == (
        True, "print('hello')", "")


@pytest.mark.parametrize("extension", ["cxx", "hpp", "rs", "py"])
def test_memory_safety_requires_evidence_not_extension_exclusion(extension):
    finding = {"file": f"native/parser.{extension}",
               "description": "User input triggers buffer overflow across an unsafe FFI boundary"}
    assert HardExclusionRules.get_exclusion_reason(finding) is None


@pytest.mark.parametrize("failed", [False, True])
def test_unvalidated_finding_does_not_get_maximum_confidence(failed):
    filter_ = FindingsFilter(use_hard_exclusions=False, use_claude_filtering=False)
    if failed:
        filter_.use_claude_filtering = True
        filter_.claude_client = Mock()
        filter_.claude_client.analyze_single_finding.return_value = (False, {}, "timeout")
    _, report, _ = filter_.filter_findings([{"file": "app.py", "description": "issue"}])
    metadata = report["filtered_findings"][0]["_filter_metadata"]
    assert metadata["confidence_score"] is None
    assert metadata["validation_status"] == "unvalidated"


def test_configured_timeout_reaches_runner(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic")
    monkeypatch.setenv("CLAUDE_TIMEOUT", "7")
    assert initialize_clients()[1].timeout_seconds == 420


@pytest.mark.parametrize("analysis", [
    {"confidence_score": "certain", "keep_finding": True},
    {"confidence_score": 8, "keep_finding": "false"},
    {"justification": "missing decision fields"},
])
def test_malformed_validation_is_unvalidated(analysis):
    filter_ = FindingsFilter(use_hard_exclusions=False, use_claude_filtering=False)
    filter_.use_claude_filtering = True
    filter_.claude_client = Mock()
    filter_.claude_client.analyze_single_finding.return_value = (True, analysis, "")
    _, report, _ = filter_.filter_findings([{"file": "app.py", "description": "issue"}])
    metadata = report["filtered_findings"][0]["_filter_metadata"]
    assert metadata["confidence_score"] is None
    assert metadata["validation_status"] == "unvalidated"


def test_api_probe_uses_selected_model_and_zero_retry_is_respected(monkeypatch):
    client_sdk = Mock()
    monkeypatch.setattr("claudecode.claude_api_client.Anthropic", Mock(return_value=client_sdk))
    client = ClaudeAPIClient(model="configured-model", api_key="synthetic", max_retries=0)
    assert client.max_retries == 0
    assert client.validate_api_access()[0]
    assert client_sdk.messages.create.call_args.kwargs["model"] == "configured-model"
