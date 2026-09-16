from dataclasses import replace
import json
from pathlib import Path

import pytest
from test_standalone import history, FakeBackend, ConfirmingValidator
from security_review import ReviewRequest, ReviewReport, review


def test_frozen_legacy_transport_baseline():
    from claudecode.json_parser import is_completed_report
    fixture = json.loads((Path(__file__).parent / "fixtures/compatibility-v1.json").read_text())
    for case in fixture["cases"]:
        assert is_completed_report(case["report"]) is case["completed"], case["name"]
    assert not fixture["slash_command"]["machine_report_contract"]


def test_published_schemas_are_current():
    from security_review.schema import schemas
    from importlib.resources import files
    for name, expected in schemas().items():
        assert json.loads(files("security_review").joinpath("schemas", name).read_text()) == expected


@pytest.mark.parametrize("severity,expected", [(None, 0), ("HIGH", 1), ("MEDIUM", 0)])
def test_api_cli_action_share_policy_outcomes(history, tmp_path, monkeypatch, capsys, severity, expected):
    import security_review.__main__ as cli
    from security_review.action import execute
    request = ReviewRequest(*history)
    def scan(_):
        return review(request, FakeBackend(severity), ConfirmingValidator())
    api_report = scan(request)
    monkeypatch.setattr(cli, "review", scan)
    assert cli.main(["scan", "--repo", str(history[0]), "--base", history[1], "--head", history[2]]) == expected
    cli_report = json.loads(capsys.readouterr().out)
    environment = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": "owner/repo", "PR_NUMBER": "7",
                   "GITHUB_WORKSPACE": str(tmp_path), "REVIEW_COMMENT_PR": "false"}
    assert execute(environment, scanner=scan) == expected
    action_report = json.loads((tmp_path / "security-review-results.json").read_text())
    for result in (cli_report, action_report):
        assert result["status"] == api_report.status
        assert result["policy_outcome"] == api_report.policy_outcome
        assert result["findings"] == api_report.findings
        ReviewReport.from_dict(result)
