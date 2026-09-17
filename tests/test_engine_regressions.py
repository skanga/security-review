"""Location identity, cached policy, and explicit adapter regressions."""
from dataclasses import replace
from datetime import date

import pytest

from security_review import InvestigationResult, Policy, ReviewReport, ReviewRequest, Suppression, ValidationResult, review
from security_review.policy import digest
from security_review.repository import Snapshot
from security_review.store import RunStore


class Backend:
    def __init__(self, sites=((2, "head"), (5, "head"))):
        self.sites = sites
        self.calls = 0

    def investigate(self, snapshot, request):
        self.calls += 1
        return InvestigationResult([dict(file="app.py", line=line, side=side, severity="HIGH",
            description="Missing authorization", category="authorization",
            exploit_scenario="Untrusted user accesses another user's record",
            recommendation="Restore the owner check") for line, side in self.sites], ["app.py"])


class Validator:
    def __init__(self):
        self.calls = []

    def validate(self, finding, *args):
        self.calls.append((finding["line"], finding["side"]))
        return ValidationResult("rejected" if finding["line"] == 2 else "confirmed", 0.95,
                                "Owner check present" if finding["line"] == 2 else "Owner check absent")


def source(*args):
    text = b"check_owner()\nread_record()\n\n# Other route\nread_record()\n"
    return Snapshot("a" * 40, "b" * 40, "immutable", ("app.py",),
                    {"app.py": text}, {"app.py": text}, (), "diff")


@pytest.mark.parametrize("sites", [((2, "head"), (5, "head")), ((5, "head"), (2, "head"))])
def test_distinct_locations_validate_independently(tmp_path, sites):
    validator = Validator()
    report = review(ReviewRequest(tmp_path), Backend(sites), validator, source=source)
    assert report.exit_code == 1
    assert set(validator.calls) == set(sites)
    assert len(report.findings) == len(report.rejected_findings) == 1
    assert not report.duplicates
    assert len({f["fingerprint"] for f in report.candidates}) == 2
    assert all(f["fingerprint"].startswith("v2:") for f in report.candidates)


def test_only_exact_location_duplicates_collapse(tmp_path):
    sites = ((5, "head"), (5, "base"), (5, "head"))
    validator = Validator()
    report = review(ReviewRequest(tmp_path), Backend(sites), validator, source=source)
    assert report.exit_code == 1
    assert validator.calls == [(5, "head"), (5, "base")]
    assert len(report.findings) == 2 and len(report.duplicates) == 1


@pytest.mark.parametrize("fingerprint", ["v1:" + "a" * 64, "v3:" + "a" * 64, "v2:invalid"])
def test_old_or_invalid_suppression_identity_requires_migration(fingerprint):
    with pytest.raises(ValueError, match="fingerprint|rescan"):
        Suppression("accepted", fingerprint, "Temporary exception")


def test_legacy_reports_remain_readable(tmp_path):
    report = review(ReviewRequest(tmp_path), Backend(), Validator(), source=source).to_dict()
    for collection in ("findings", "rejected_findings", "candidates"):
        for finding in report[collection]:
            finding["fingerprint"] = "v1:" + "a" * 64
    assert ReviewReport.from_dict(report).exit_code == 1


def test_pre_fix_cache_is_not_reused(tmp_path):
    request = ReviewRequest(tmp_path, cache_dir=tmp_path / "state")
    backend = Backend()
    original = review(request, backend, Validator(), source=source)
    config = {k: v for k, v in original.effective_config.items() if k not in {"no_cache", "cache_dir"}}
    # Frozen pre-fix cache-key format. Such a report may have already lost candidates.
    old_key = digest({"snapshot": "immutable", "request": config, "versions": {"engine": "0.1.0"},
        "backend": __name__ + ".Backend", "validator": __name__ + ".Validator"})
    store = RunStore(request.cache_dir)
    with store.connect() as connection:
        connection.execute("DELETE FROM runs")
    original.findings = original.rejected_findings = original.candidates = []
    original.policy_outcome = "pass"
    store.save(original, old_key)
    second = review(request, backend, Validator(), source=source)
    assert not second.cache["hit"] and second.exit_code == 1
    assert backend.calls == 2


def set_date(monkeypatch, day):
    import security_review.engine as engine
    import security_review.policy as policy
    class Today(date):
        @classmethod
        def today(cls):
            return cls(2026, 9, day)
    monkeypatch.setattr(policy, "date", Today)
    # Engine captures a single date for all findings, including cache reuse.
    monkeypatch.setattr(engine, "date", Today, raising=False)


def test_cached_policy_repartitions_suppressed_findings(tmp_path, monkeypatch):
    request = ReviewRequest(tmp_path)
    original = review(request, Backend(), Validator(), source=source)
    rule = Suppression("accepted", original.findings[0]["fingerprint"], "Temporary exception", expires="2026-09-15")
    request = replace(request, policy=Policy(suppressions=(rule,)), cache_dir=tmp_path / "state")
    backend, validator = Backend(), Validator()
    set_date(monkeypatch, 15)
    first = review(request, backend, validator, source=source)
    assert first.exit_code == 0 and len(first.suppressed_findings) == 1
    set_date(monkeypatch, 16)
    for _ in range(2):
        cached = review(request, backend, validator, source=source)
        assert cached.cache["hit"] and cached.exit_code == 1
        assert len(cached.findings) == len(cached.rejected_findings) == 1
        assert len(cached.candidates) == 2 and not cached.suppressed_findings
        assert RunStore(request.cache_dir).load(cached.run_id).exit_code == 1
    assert backend.calls == 1 and len(validator.calls) == 2
    fresh = review(replace(request, no_cache=True), Backend(), Validator(), source=source)
    assert cached.policy_outcome == fresh.policy_outcome


def test_permanent_suppression_survives_repeated_cache_hits(tmp_path):
    request = ReviewRequest(tmp_path)
    original = review(request, Backend(), Validator(), source=source)
    rule = Suppression("accepted", original.findings[0]["fingerprint"], "Accepted risk")
    request = replace(request, policy=Policy(suppressions=(rule,)), cache_dir=tmp_path / "state")
    for _ in range(3):
        report = review(request, Backend(), Validator(), source=source)
        assert report.exit_code == 0 and len(report.suppressed_findings) == 1
        assert len(report.candidates) == 2


def test_explicit_validator_is_preserved_with_default_backend(tmp_path):
    validator = Validator()
    preflight_calls = []
    validator.preflight = lambda req: preflight_calls.append(req) or {"version": "fixture"}
    class Registry:
        def create(self, kind, name):
            assert kind == "backend", "Explicit validator must not be replaced"
            return Backend()
    report = review(ReviewRequest(tmp_path), validator=validator, source=source, registry=Registry())
    assert report.exit_code == 1 and preflight_calls and len(validator.calls) == 2


def test_disabled_validation_does_not_preflight_injected_validator(tmp_path):
    class Unused:
        def preflight(self, request):
            pytest.fail("Disabled validator must not require provider access")
    report = review(ReviewRequest(tmp_path, policy=Policy(validation_required=False)),
                    Backend(), Unused(), source=source)
    assert report.exit_code == 0


def test_distinct_locations_publish_independently(tmp_path):
    from test_m1_github import FakeGitHub
    from security_review.github import GitHubPublisher
    report = review(ReviewRequest(tmp_path), Backend(((5, "head"), (5, "base"))), Validator(), source=source)
    report.snapshot["source"] = {"type": "github", "repository": "owner/repo", "number": 7}
    client = FakeGitHub()
    publisher = GitHubPublisher(client)
    assert publisher.publish(report, "owner/repo#7").status == "published"
    assert len(client.posted) == 3  # Two findings plus execution summary.
    assert len(publisher.publish(report, "owner/repo#7").skipped) == 2
    assert len(client.posted) == 3
