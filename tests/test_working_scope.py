"""Working-copy scope must describe actual changes, including unavailable entries."""
from pathlib import Path
import os

import pytest

from test_standalone import history, git, FakeBackend
from security_review import ReviewRequest, review
from security_review.repository import capture


@pytest.mark.parametrize("mode", ["staged", "unstaged", "working_tree"])
@pytest.mark.parametrize("kind", ["denied", "oversized"])
def test_unchanged_unavailable_files_do_not_expand_scope(history, mode, kind):
    from security_review.repository import FILE_LIMIT
    repo, _, _ = history
    (repo / "private.txt").write_bytes(b"x" * (FILE_LIMIT + 1) if kind == "oversized" else b"private fixture\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "unavailable context")
    assert not git(repo, "status", "--porcelain")
    request = ReviewRequest(repo, mode=mode, denied_paths=("private.txt",) if kind == "denied" else ())
    class NoProvider:
        def preflight(self, request):
            pytest.fail("Clean snapshot must not need a provider")
    report = review(request, NoProvider())
    assert report.exit_code == 0 and report.coverage["eligible"] == []
    (repo / "app.py").write_bytes(b"new change\n")
    if mode == "staged":
        git(repo, "add", "app.py")
    assert capture(request).changed_files == ("app.py",)


@pytest.mark.parametrize("mode", ["staged", "unstaged", "working_tree"])
@pytest.mark.parametrize("change", ["modified", "deleted"])
def test_changed_denied_file_remains_incomplete_without_reading(history, monkeypatch, mode, change):
    import security_review.repository as repository
    repo, _, _ = history
    private = repo / "private.txt"
    private.write_bytes(b"synthetic private fixture\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "private context")
    if change == "deleted":
        private.unlink()
    else:
        private.write_bytes(b"changed private fixture is longer\n")
    if mode == "staged":
        git(repo, "add", "private.txt")
    original_open = os.open
    def guarded_open(path, *args, **kwargs):
        assert Path(path) != private, "Denied content must not be opened"
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(repository.os, "open", guarded_open)
    request = ReviewRequest(repo, mode=mode, denied_paths=("private.txt",))
    snapshot = capture(request)
    assert snapshot.changed_files == ("private.txt",)
    assert snapshot.changes[0]["status"] == change
    assert "private.txt" not in snapshot.base_files and "private.txt" not in snapshot.head_files
    assert "fixture" not in snapshot.diff
    report = review(request, FakeBackend())
    assert report.exit_code == 2 and report.coverage["incomplete"] == ["private.txt"]


@pytest.mark.parametrize("mode", ["staged", "unstaged", "working_tree"])
def test_unchanged_link_is_not_selected(history, mode):
    repo, _, _ = history
    git(repo, "config", "core.symlinks", "true")
    link = repo / "link"
    try:
        link.symlink_to("app.py")
    except OSError:
        pytest.skip("Host cannot create symbolic links")
    git(repo, "add", "link")
    git(repo, "commit", "-qm", "link context")
    assert not git(repo, "status", "--porcelain")
    assert capture(ReviewRequest(repo, mode=mode)).changed_files == ()
    if mode != "staged":
        link.unlink()
        link.symlink_to("other.py")
        changed = capture(ReviewRequest(repo, mode=mode))
        assert changed.changed_files == ("link",) and "link" in changed.unavailable


def test_unchanged_staged_gitlink_is_not_selected(history):
    repo, _, head = history
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},submodule")
    git(repo, "commit", "-qm", "gitlink context")
    assert capture(ReviewRequest(repo, mode="staged")).changed_files == ()


def test_denied_file_edit_during_capture_is_detected(history, monkeypatch):
    import security_review.repository as repository
    repo, _, _ = history
    private = repo / "private.txt"
    private.write_bytes(b"before\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "private context")
    original = repository._working_files
    calls = 0
    def changing(*args):
        nonlocal calls
        result = original(*args)
        calls += 1
        if calls == 1:
            private.write_bytes(b"changed between captures\n")
        return result
    monkeypatch.setattr(repository, "_working_files", changing)
    with pytest.raises(ValueError, match="changed during capture"):
        capture(ReviewRequest(repo, mode="unstaged", denied_paths=("private.txt",)))


@pytest.mark.parametrize("mode", ["unstaged", "working_tree"])
@pytest.mark.parametrize("setting", ["autocrlf", "attributes", "working_attributes"])
def test_crlf_comparison_preserves_raw_evidence(history, mode, setting):
    repo, _, _ = history
    git(repo, "config", "core.autocrlf", "false")
    (repo / "app.py").write_bytes(b"safe\nsecond\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "LF baseline")
    if setting == "autocrlf":
        git(repo, "config", "core.autocrlf", "true")
    else:
        (repo / ".gitattributes").write_bytes(b"app.py text eol=crlf\n")
        if setting == "attributes":
            git(repo, "add", ".gitattributes")
            git(repo, "commit", "-qm", "text attributes")
    (repo / "app.py").write_bytes(b"safe\r\nsecond\r\n")
    assert not git(repo, "diff", "--name-only", "--", "app.py")
    snapshot = capture(ReviewRequest(repo, mode=mode))
    assert "app.py" not in snapshot.changed_files
    assert snapshot.head_files["app.py"] == b"safe\r\nsecond\r\n"
    (repo / "app.py").write_bytes(b"unsafe\r\nsecond\r\n")
    snapshot = capture(ReviewRequest(repo, mode=mode))
    assert "app.py" in snapshot.changed_files
    assert "+unsafe" in snapshot.diff
    assert "+second" not in snapshot.diff  # EOL conversion must not invent added lines.
    assert snapshot.read_lines("app.py", start=2)["text"] == "second\r\n"


@pytest.mark.parametrize("setting", ["disabled", "binary", "auto_existing_crlf"])
def test_eol_normalization_does_not_hide_byte_changes(history, setting):
    repo, _, _ = history
    git(repo, "config", "core.autocrlf", "false")
    if setting == "binary":
        (repo / ".gitattributes").write_bytes(b"app.py -text\n")
    original = b"safe\r\n" if setting == "auto_existing_crlf" else b"safe\n"
    (repo / "app.py").write_bytes(original)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "EOL baseline")
    if setting != "disabled":
        git(repo, "config", "core.autocrlf", "true")
    (repo / "app.py").write_bytes(b"safe\n" if setting == "auto_existing_crlf" else b"safe\r\n")
    assert git(repo, "diff", "--name-only", "--", "app.py") == "app.py"
    assert "app.py" in capture(ReviewRequest(repo, mode="unstaged")).changed_files


def test_working_comparison_does_not_execute_filters(history):
    repo, _, _ = history
    (repo / ".gitattributes").write_bytes(b"app.py text filter=forbidden\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "filter attribute")
    git(repo, "config", "filter.forbidden.clean", "echo executed > filter-marker; cat")
    git(repo, "config", "filter.forbidden.required", "true")
    (repo / "app.py").write_bytes(b"real change\r\n")
    assert "app.py" in capture(ReviewRequest(repo, mode="unstaged")).changed_files
    assert not (repo / "filter-marker").exists()


@pytest.mark.parametrize("mode", ["unstaged", "working_tree"])
def test_regular_symlink_checkout_is_not_a_mode_change(history, mode):
    repo, _, _ = history
    git(repo, "config", "core.symlinks", "false")
    (repo / "link").write_bytes(b"app.py")
    oid = git(repo, "hash-object", "--no-filters", "link")
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{oid},link")
    # Ensure the blob is stored without invoking a checkout helper.
    git(repo, "hash-object", "-w", "--no-filters", "link")
    git(repo, "commit", "-qm", "link placeholder")
    assert not git(repo, "status", "--porcelain")
    assert capture(ReviewRequest(repo, mode=mode)).changed_files == ()
    (repo / "link").write_bytes(b"other.py")
    assert capture(ReviewRequest(repo, mode=mode)).changed_files == ("link",)


@pytest.mark.parametrize("mode", ["unstaged", "working_tree"])
def test_initialized_gitlink_checks_head_and_tracked_metadata(history, mode):
    repo, _, _ = history
    submodule = repo / "submodule"
    submodule.mkdir()
    git(submodule, "init", "-q")
    (submodule / "code.py").write_bytes(b"original\n")
    git(submodule, "add", ".")
    git(submodule, "commit", "-qm", "nested baseline")
    oid = git(submodule, "rev-parse", "HEAD")
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{oid},submodule")
    git(repo, "commit", "-qm", "gitlink baseline")
    assert not git(repo, "status", "--porcelain")
    request = ReviewRequest(repo, mode=mode)
    assert capture(request).changed_files == ()
    (submodule / "code.py").write_bytes(b"dirty tracked content\n")
    snapshot = capture(request)
    assert snapshot.changed_files == ("submodule",) and "submodule" in snapshot.unavailable
    git(submodule, "add", ".")
    git(submodule, "commit", "-qm", "new nested head")
    assert capture(request).changed_files == ("submodule",)


@pytest.mark.parametrize("attribute_source", ["configured", "configured_dotdot", "configured_outside", "info", "ancestor"])
def test_attribute_lookup_never_consults_denied_source(history, monkeypatch, attribute_source):
    import security_review.repository as repository
    repo, _, _ = history
    git(repo, "config", "core.autocrlf", "false")
    (repo / "app.py").write_bytes(b"original\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "LF baseline")
    path = {"info": ".git/info/attributes", "ancestor": ".gitattributes"}.get(attribute_source, "private.attr")
    (repo / path).write_bytes(b"app.py text\n")
    if attribute_source.startswith("configured"):
        source = repo / path
        if attribute_source == "configured_dotdot":
            (repo / "sub").mkdir()
            source = repo / "sub" / ".." / path
        elif attribute_source == "configured_outside":
            (repo.parent / "outside").mkdir()
            source = repo.parent / "outside" / ".." / repo.name / path
        git(repo, "config", "core.attributesFile", str(source))
    (repo / "app.py").write_bytes(b"original\r\n")
    original = repository.GitReader.run
    def guarded(self, *args, **kwargs):
        assert args[0] != "check-attr", "Git must not read denied attribute sources"
        return original(self, *args, **kwargs)
    monkeypatch.setattr(repository.GitReader, "run", guarded)
    snapshot = capture(ReviewRequest(repo, mode="unstaged", denied_paths=(path,)))
    assert snapshot.changed_files == ("app.py",)  # No unsafe EOL inference.


def test_attribute_source_denial_normalizes_parent_traversal(tmp_path):
    from security_review.repository import _attribute_source_states
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    (repo / "private.attr").write_bytes(b"*.py text\n")
    request = ReviewRequest(repo, mode="unstaged", denied_paths=("private.attr",))
    for source in (repo / "sub" / ".." / "private.attr",
                   tmp_path / "outside" / ".." / "repo" / "private.attr"):
        assert _attribute_source_states(request, [source]) is None
