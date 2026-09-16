from test_standalone import history, FakeBackend, ConfirmingValidator
from security_review import ReviewRequest, review
import pytest


@pytest.mark.parametrize("field", ["category", "exploit_scenario", "recommendation"])
def test_missing_required_candidate_fields_cannot_be_confirmed(history, field):
    class Missing(FakeBackend):
        def investigate(self, *args):
            result = super().investigate(*args)
            del result.findings[0][field]
            return result
    report = review(ReviewRequest(*history), Missing("HIGH"), ConfirmingValidator())
    assert report.exit_code == 2 and not report.findings


def test_non_usage_fields_are_not_copied_to_report(history):
    from security_review import InvestigationResult
    class Usage(FakeBackend):
        def investigate(self, *args):
            result = super().investigate(*args)
            return InvestigationResult(result.findings, result.assessed_files,
                                       usage={"input_tokens": 3, "transcript": "synthetic-secret"})
    report = review(ReviewRequest(*history), Usage())
    assert report.usage == {"investigation": {"input_tokens": 3}, "validation": None}
