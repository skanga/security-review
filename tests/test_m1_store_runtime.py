import json
import sys
import time

import pytest
from test_standalone import history, FakeBackend, ConfirmingValidator
from security_review import ReviewRequest, review


def test_cache_hit_provenance_and_policy_identity(history, tmp_path):
    from dataclasses import replace
    from security_review.policy import Policy
    request = ReviewRequest(*history, cache_dir=tmp_path / "state")
    class Count(FakeBackend):
        calls = 0
        def investigate(self, *args):
            self.calls += 1
            return super().investigate(*args)
    backend = Count("HIGH")
    first = review(request, backend, ConfirmingValidator())
    second = review(request, backend, ConfirmingValidator())
    assert first.exit_code == second.exit_code == 1
    assert backend.calls == 1
    assert second.cache["source_run_id"] == first.run_id
    assert second.run_id != first.run_id
    review(replace(request, policy=Policy(minimum_confidence=0.95)), backend, ConfirmingValidator())
    assert backend.calls == 2


def test_failed_report_is_not_reused(history, tmp_path):
    request = ReviewRequest(*history, cache_dir=tmp_path / "state")
    first = review(request, FakeBackend("HIGH"))
    second = review(request, FakeBackend("HIGH"), ConfirmingValidator())
    assert first.exit_code == 2 and second.exit_code == 1
    assert second.cache["hit"] is False


def test_store_lease_ownership_and_expiry(tmp_path):
    from security_review.store import RunStore
    store = RunStore(tmp_path)
    owner = store.acquire("key", "run", time.time() + 60)
    with pytest.raises(ValueError, match="reserved"):
        store.acquire("key", "another", time.time() + 60)
    assert not store.release("key", "wrong-owner")
    assert store.release("key", owner)
    store.acquire("key", "old", time.time() - 1)
    new = store.acquire("key", "new", time.time() + 60)
    assert store.release("key", new)


def test_subprocess_limits_and_cancellation_are_enforced(tmp_path):
    from security_review.runtime import run_process, execution, Execution, CancellationToken, Cancelled
    with pytest.raises(ValueError, match="limit"):
        run_process([sys.executable, "-c", "print('x' * 100000)"], limit=100)
    with pytest.raises(TimeoutError):
        run_process([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)
    token = CancellationToken()
    token.cancel()
    handle = execution.set(Execution(time.monotonic() + 10, token))
    try:
        with pytest.raises(Cancelled):
            run_process([sys.executable, "-c", "raise AssertionError('must not launch')"])
    finally:
        execution.reset(handle)


def test_report_schema_rejects_forged_cache_state():
    from security_review import ReviewReport
    report = ReviewReport("id").to_dict()
    report.update(status="completed", policy_outcome="pass")
    report["coverage"]["incomplete"] = ["app.py"]
    with pytest.raises(ValueError):
        ReviewReport.from_dict(report)


def test_invalid_state_directory_is_reported_and_context_restored(history, tmp_path):
    from security_review.runtime import execution
    directory = tmp_path / "not-a-directory"
    directory.write_text("sentinel")
    before = execution.get()
    report = review(ReviewRequest(*history, cache_dir=directory), FakeBackend())
    assert report.exit_code == 2
    assert execution.get() is before


def test_cached_report_must_reconcile_all_eligible_files():
    from security_review import ReviewReport
    report = ReviewReport("forged", status="completed", policy_outcome="pass").to_dict()
    report["coverage"]["eligible"] = ["unreviewed.py"]
    with pytest.raises(ValueError):
        ReviewReport.from_dict(report)
