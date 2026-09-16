"""Milestone acceptance checks; provider calls remain synthetic."""
import json
from pathlib import Path

import pytest

from test_standalone import history, git, FakeBackend, ConfirmingValidator
from security_review import ReviewRequest, review


@pytest.mark.parametrize("mode", ["revisions", "staged", "unstaged", "working_tree"])
def test_source_directory_cannot_silently_select_parent_repository(history, mode):
    from security_review.repository import capture
    repo, _, head = history
    nested = repo / "not-a-repository"
    nested.mkdir()
    with pytest.raises(ValueError, match="repository root"):
        capture(ReviewRequest(nested, head, head, mode=mode))


def test_trusted_config_rejects_unknown_and_resolves_paths(tmp_path):
    from security_review.config import resolve_config
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"repository": ".", "model": "configured", "mode": "staged"}))
    request = resolve_config(path, {"model": "explicit"}, environ={})
    assert request.repository == tmp_path
    assert request.model == "explicit"
    path.write_text('{"typo": true}')
    with pytest.raises(ValueError, match="Unknown"):
        resolve_config(path, {}, environ={})


def test_config_credentials_are_references_and_not_effective_values(tmp_path):
    from security_review.config import resolve_config, effective_config
    request = resolve_config(None, {"repository": str(tmp_path)},
                             environ={"ANTHROPIC_API_KEY": "synthetic-secret"})
    assert "synthetic-secret" not in json.dumps(effective_config(request))
    assert request.model == request.validation_model


@pytest.mark.parametrize("mode,base_text,head_text", [
    ("staged", "safe = False\n", "staged = True\n"),
    ("unstaged", "staged = True\n", "working = True\n"),
    ("working_tree", "safe = False\n", "working = True\n"),
])
def test_working_modes_freeze_distinct_states(history, mode, base_text, head_text):
    from security_review.repository import capture
    repo, _, head = history
    (repo / "app.py").write_bytes(b"staged = True\n")
    git(repo, "add", "app.py")
    (repo / "app.py").write_bytes(b"working = True\n")
    before = git(repo, "status", "--porcelain=v1")
    snapshot = capture(ReviewRequest(repo, head, head, mode=mode))
    assert snapshot.read("app.py", "base") == base_text
    assert snapshot.read("app.py") == head_text
    assert git(repo, "status", "--porcelain=v1") == before
    (repo / "app.py").write_text("later edit\n")
    assert snapshot.read("app.py") == head_text


def test_untracked_and_ignored_inventory(history):
    from security_review.repository import capture
    repo, _, head = history
    (repo / ".gitignore").write_text("secret.txt\n")
    (repo / "secret.txt").write_text("synthetic secret")
    (repo / "new.txt").write_text("visible")
    request = ReviewRequest(repo, head, head, mode="working_tree", include_untracked=True)
    snapshot = capture(request)
    assert "new.txt" in snapshot.changed_files
    assert "secret.txt" not in snapshot.head_files
    assert "new.txt" not in capture(ReviewRequest(repo, head, head, mode="working_tree")).changed_files


def test_reader_paging_and_unavailable_reasons(history):
    from security_review.repository import capture
    repo, _, base = history
    (repo / "data.bin").write_bytes(b"\0\xff")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "binary")
    snapshot = capture(ReviewRequest(repo, base, "HEAD"))
    assert snapshot.unavailable_reasons["data.bin"] == "binary"
    page = snapshot.list_files(limit=1)
    assert len(page["items"]) == 1 and page["next_cursor"] is not None
    assert snapshot.read_lines("app.py", start=1, limit=1)["text"] == "safe = False\n"


def test_staged_mode_only_change_is_eligible(history):
    from security_review.repository import capture
    repo, _, head = history
    git(repo, "update-index", "--chmod=+x", "app.py")
    snapshot = capture(ReviewRequest(repo, head, head, mode="staged"))
    assert snapshot.changed_files == ("app.py",)
    assert snapshot.changes[0]["base_mode"] == "100644"
    assert snapshot.changes[0]["head_mode"] == "100755"


def test_literal_git_pathspec_cannot_include_denied_content(history):
    from security_review.repository import capture
    repo, _, base = history
    (repo / "[a].txt").write_bytes(b"allowed\n")
    (repo / "a.txt").write_bytes(b"synthetic-secret\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "pathspec fixture")
    snapshot = capture(ReviewRequest(repo, base, "HEAD", denied_paths=("a.txt",)))
    assert "synthetic-secret" not in snapshot.diff
    assert "a.txt" not in snapshot.head_files


def test_working_snapshot_identity_includes_unchanged_context(history):
    from security_review.repository import capture
    repo, _, head = history
    (repo / "app.py").write_bytes(b"unstaged\n")
    (repo / "context.py").write_bytes(b"guard = True\n")
    git(repo, "add", "context.py")
    request = ReviewRequest(repo, head, head, mode="unstaged")
    first = capture(request)
    (repo / "context.py").write_bytes(b"guard = False\n")
    git(repo, "add", "context.py")
    second = capture(request)
    assert first.changed_files == second.changed_files == ("app.py",)
    assert first.snapshot_id != second.snapshot_id


def test_git_detected_rename_retains_old_path_after_small_edit(history):
    from security_review.repository import capture
    repo, _, _ = history
    (repo / "app.py").write_bytes(b"one\ntwo\nthree\nfour\nfive\nsix\n")
    git(repo, "add", "app.py")
    git(repo, "commit", "-qm", "rename base")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "mv", "app.py", "renamed.py")
    (repo / "renamed.py").write_bytes(b"one\ntwo\nthree\nfour\nfive\nchanged\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "rename with edit")
    snapshot = capture(ReviewRequest(repo, base, "HEAD"))
    renamed = next(change for change in snapshot.changes if change["path"] == "renamed.py")
    assert renamed["status"] == "renamed" and renamed["old_path"] == "app.py"


def test_policy_suppressions_and_exclusions_are_auditable(history):
    from security_review.policy import Policy
    request = ReviewRequest(*history, policy=Policy(exclude_paths=("app.py",)))
    report = review(request, FakeBackend("HIGH"), ConfirmingValidator())
    assert report.status == "completed"
    assert report.coverage["excluded"][0]["file"] == "app.py"
    assert report.policy["hash"]


def test_disabled_validation_retains_unvalidated_advisory(history):
    from security_review.policy import Policy
    request = ReviewRequest(*history, policy=Policy(validation_required=False))
    report = review(request, FakeBackend("HIGH"))
    assert report.status == "completed"
    assert report.exit_code == 0
    assert report.findings[0]["validation_reason"] == "Validation explicitly disabled"


def test_events_and_cancellation_include_source_phase(history):
    from security_review.runtime import CancellationToken
    token = CancellationToken()
    token.cancel()
    events = []
    report = review(ReviewRequest(*history), FakeBackend(), cancellation=token, on_event=events.append)
    assert report.status == "cancelled"
    assert report.events[-1]["state"] == "cancelled"
    assert events == report.events


def test_cancelled_backend_result_keeps_returned_candidates(history):
    from security_review.runtime import CancellationToken
    token = CancellationToken()
    class CancelAtReturn(FakeBackend):
        def investigate(self, *args):
            result = super().investigate(*args)
            token.cancel()
            return result
    report = review(ReviewRequest(*history), CancelAtReturn("HIGH"), ConfirmingValidator(), cancellation=token)
    assert report.status == "cancelled"
    assert len(report.findings) == 1
    assert report.findings[0]["validation_status"] == "unvalidated"


def test_canonical_finding_deduplicates_and_drops_arbitrary_fields(history):
    from security_review import InvestigationResult
    class Duplicate(FakeBackend):
        def investigate(self, snapshot, request):
            result = super().investigate(snapshot, request)
            result.findings[0]["provider_transcript"] = "must not persist"
            return InvestigationResult(result.findings * 2, result.assessed_files)
    report = review(ReviewRequest(*history), Duplicate("HIGH"), ConfirmingValidator())
    assert report.exit_code == 1
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding["fingerprint"] and finding["locations"][0]["revision"]
    assert "provider_transcript" not in finding
    assert report.duplicates


def test_registry_does_not_discover_repo_plugins():
    from security_review.registry import Registry
    registry = Registry()
    assert "claude-code" in registry.list("backend")
    with pytest.raises(ValueError):
        registry.create("backend", "repository-plugin")


def test_markdown_escapes_source_and_preserves_partial_status():
    from security_review import ReviewReport
    from security_review.rendering import render_markdown
    report = ReviewReport("fixture", status="partial", findings=[{
        "file": "[click](https://evil.invalid)", "line": 1, "severity": "HIGH",
        "description": "<script>bad</script>\n::error::forged", "validation_status": "unvalidated"}])
    rendered = render_markdown(report)
    assert "partial" in rendered and "unvalidated" in rendered
    assert "<script>" not in rendered and "\n::error::" not in rendered
    assert "[click](https://evil.invalid)" not in rendered
