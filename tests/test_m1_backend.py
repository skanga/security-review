import json
import subprocess
from unittest.mock import Mock

import pytest
from test_standalone import history
from security_review import ReviewRequest
from security_review.repository import capture


def test_preflight_rejects_cloud_forbidden_and_missing_key(history, monkeypatch):
    from security_review.claude_backend import ClaudeCodeBackend
    backend = ClaudeCodeBackend()
    with pytest.raises(ValueError, match="cloud"):
        backend.preflight(ReviewRequest(*history, cloud_allowed=False))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        backend.preflight(ReviewRequest(*history))


def test_validator_receives_both_immutable_sides_and_change(history, monkeypatch):
    from security_review.claude_backend import ClaudeFindingValidator
    request = ReviewRequest(*history, model="investigator", validation_model="validator")
    snapshot = capture(request)
    seen = {}
    def run(command, **kwargs):
        seen.update(json.loads(kwargs["input"]))
        return subprocess.CompletedProcess(command, 0, b'{"status":"confirmed","confidence":0.9,"justification":"New missing guard"}', b'')
    monkeypatch.setattr("security_review.claude_backend.run_process", run)
    result = ClaudeFindingValidator().validate({"file": "app.py", "line": 1, "description": "Missing guard"}, snapshot, request)
    assert seen["model"] == "validator"
    assert seen["evidence"]["base"] == "safe = True\n"
    assert seen["evidence"]["head"] == "safe = False\n"
    assert "safe = False" in seen["evidence"]["diff"]
    assert result.status == "confirmed"


def test_backend_accepts_only_complete_envelope(history, monkeypatch):
    from security_review.claude_backend import ClaudeCodeBackend
    request = ReviewRequest(*history)
    snapshot = capture(request)
    inner = {"findings": [], "assessed_files": ["app.py"], "analysis_summary": {"review_completed": True}}
    monkeypatch.setattr("security_review.claude_backend.run_process", lambda *a, **kw:
                        subprocess.CompletedProcess(a[0], 0, json.dumps({"is_error": True, "result": json.dumps(inner)}).encode(), b''))
    with pytest.raises(ValueError):
        ClaudeCodeBackend().investigate(snapshot, request)
