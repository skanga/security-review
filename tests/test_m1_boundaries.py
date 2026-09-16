from pathlib import Path
import os
import subprocess
import sys
import time

import pytest
from test_standalone import history, git
from security_review import ReviewRequest


def test_atomic_artifacts_do_not_follow_links(tmp_path):
    from security_review.rendering import atomic_write
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep")
    link = tmp_path / "report.json"
    try:
        link.symlink_to(sentinel)
    except OSError:
        pytest.skip("Creating Windows symlinks requires host capability")
    with pytest.raises(OSError):
        atomic_write(link, "overwrite")
    assert sentinel.read_text() == "keep"


def test_working_capture_detects_edit_between_passes(history, monkeypatch):
    import security_review.repository as repository
    original = repository._working_files
    calls = 0
    def changing(request, *args):
        nonlocal calls
        result = original(request, *args)
        calls += 1
        if calls == 1:
            (request.repository / "app.py").write_bytes(b"changed during capture\n")
        return result
    monkeypatch.setattr(repository, "_working_files", changing)
    repo, _, head = history
    with pytest.raises(ValueError, match="changed during capture"):
        repository.capture(ReviewRequest(repo, head, head, mode="working_tree"))


def test_inventory_larger_than_one_hundred(history):
    from security_review.repository import capture
    repo, _, base = history
    for index in range(105):
        (repo / f"file{index}.py").write_bytes(b"same content\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "large inventory")
    snapshot = capture(ReviewRequest(repo, base, "HEAD"))
    assert len(snapshot.changed_files) == 105


def test_owned_descendant_is_terminated_when_parent_exits(tmp_path):
    from security_review.runtime import run_process
    marker = tmp_path / "orphan-marker"
    child = "import time,pathlib;time.sleep(3);pathlib.Path(" + repr(str(marker)) + ").write_text('orphan')"
    parent = "import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(child) + "])"
    try:
        run_process([sys.executable, "-c", parent], timeout=1)
    except (ValueError, TimeoutError):
        pass
    deadline = time.monotonic() + 3.2
    while time.monotonic() < deadline and not marker.exists():
        time.sleep(0.05)
    assert not marker.exists()
