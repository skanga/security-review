import json
from unittest.mock import Mock

from claudecode.evals.eval_engine import EvaluationEngine, EvalCase
from claudecode.findings_filter import HardExclusionRules
from claudecode.json_parser import parse_json_with_fallbacks


def test_html_is_not_a_security_boundary():
    assert HardExclusionRules.get_exclusion_reason({"file": "server.html", "description": "SSRF in server-side template", "category": "ssrf"}) is None


def test_mixed_impact_cannot_be_suppressed_by_description():
    assert HardExclusionRules.get_exclusion_reason({"file": "app.py", "category": "command_injection",
                                                   "description": "Denial of service and arbitrary command execution"}) is None


def test_invalid_provider_output_is_not_logged(caplog):
    success, result = parse_json_with_fallbacks("synthetic-secret no JSON")
    assert not success
    assert "synthetic-secret" not in caplog.text + json.dumps(result)


def test_foreign_locked_worktree_is_never_removed(tmp_path, monkeypatch):
    engine = object.__new__(EvaluationEngine)
    engine.work_dir = str(tmp_path)
    engine.verbose = False
    engine._owned_worktrees = {}
    runner = Mock(return_value=Mock(stdout=f"worktree {tmp_path}/foreign\nlocked\n\n", returncode=0))
    monkeypatch.setattr("claudecode.evals.eval_engine.subprocess.run", runner)
    engine._clean_worktrees(str(tmp_path), "eval-pr")
    assert not any("remove" in call.args[0] or "-D" in call.args[0] for call in runner.call_args_list)


def test_api_exception_text_is_not_logged_or_returned(caplog):
    from claudecode.claude_api_client import ClaudeAPIClient
    client = object.__new__(ClaudeAPIClient)
    client.model = "fixture"
    client.client = Mock()
    client.client.messages.create.side_effect = RuntimeError("synthetic-secret")
    success, error = client.validate_api_access()
    assert not success
    assert "synthetic-secret" not in error + caplog.text
