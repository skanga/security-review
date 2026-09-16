import json
from pathlib import Path

from evaluation_fixture import build
from security_review import ReviewRequest, review, InvestigationResult, ValidationResult


def test_pinned_evaluation_case_replays_contract_and_locations(tmp_path):
    manifest = json.loads((Path(__file__).parent / "fixtures/evaluation-manifest.json").read_text())
    repository = tmp_path / "repository"
    base, head = build(repository)
    assert [base, head] == [manifest["source"]["base_commit"], manifest["source"]["head_commit"]]
    class RecordedBackend:
        def investigate(self, snapshot, request):
            return InvestigationResult([{"file": "app.py", "line": 2, "severity": "HIGH", "category": "authorization_bypass",
                "description": "Permission guard removed", "exploit_scenario": "Read another user's record",
                "recommendation": "Restore the permission check"}], ["app.py"])
    class RecordedValidator:
        def validate(self, candidate, snapshot, request):
            assert "can_read" in snapshot.read("app.py", "base")
            assert "can_read" not in snapshot.read("app.py")
            return ValidationResult("confirmed", 0.9, "Guard removal matches pinned fixture")
    report = review(ReviewRequest(repository, base, head, comparison="direct"), RecordedBackend(), RecordedValidator())
    assert report.exit_code == 1
    assert report.findings[0]["line"] in manifest["expected_findings"][0]["acceptable_lines"]
    assert review(ReviewRequest(repository, base, base), RecordedBackend()).exit_code == 0
