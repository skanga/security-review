import base64
import json
import time
from dataclasses import replace

import pytest
from security_review import ReviewRequest, ReviewReport


def report_for_pr():
    report = ReviewReport("fixture", status="completed", policy_outcome="fail")
    report.snapshot = {"head": "b" * 40, "base": "a" * 40, "id": "snapshot",
                       "source": {"type": "github", "repository": "owner/repo", "number": 7}}
    report.findings = [{"id": "one", "fingerprint": "v1:fixture", "file": "app.py", "line": 1,
                        "severity": "HIGH", "description": "Fixture issue", "validation_status": "confirmed",
                        "confidence": 0.9, "reportable": True, "side": "head"}]
    return report


class FakeGitHub:
    def __init__(self):
        self.comments = []
        self.posted = []
        self.head = "b" * 40
    def request(self, method, path, body=None):
        if path == "/user":
            return {"id": 99}
        if method == "POST":
            self.posted.append((path, body))
            comment = {"id": len(self.comments) + 1, "body": body["body"], "user": {"id": 99}}
            self.comments.append(comment)
            return comment
        return {"head": {"sha": self.head}, "base": {"sha": "a" * 40}}
    def pages(self, path):
        if path.endswith("/files"):
            return [{"filename": "app.py", "patch": "@@ -1 +1 @@\n-old\n+new"}]
        return self.comments


def test_stale_publication_never_posts():
    from security_review.github import GitHubPublisher
    client = FakeGitHub()
    client.head = "c" * 40
    result = GitHubPublisher(client).publish(report_for_pr(), "owner/repo#7")
    assert result.status == "stale"
    assert client.posted == []


def test_publication_deduplicates_per_revision_and_owner():
    from security_review.github import GitHubPublisher
    client = FakeGitHub()
    publisher = GitHubPublisher(client)
    first = publisher.publish(report_for_pr(), "owner/repo#7")
    count = len(client.posted)
    second = publisher.publish(report_for_pr(), "owner/repo#7")
    assert first.status == second.status == "published"
    assert len(client.posted) == count
    client.comments[0]["user"]["id"] = 123
    publisher.publish(report_for_pr(), "owner/repo#7")
    assert len(client.posted) > count


def test_github_pagination_does_not_stop_at_one_hundred():
    from security_review.github import GitHubClient
    client = GitHubClient("synthetic", transport=lambda method, path, body, timeout:
                          [{"id": i} for i in range(100)] if path.endswith("&page=1") else [{"id": 100}])
    assert len(client.pages("/repos/owner/repo/pulls/7/files")) == 101


def test_github_source_resolves_snapshot_without_checkout(tmp_path):
    from security_review.github import GitHubSource
    class SourceClient:
        def request(self, method, path, body=None):
            if "/pulls/7" in path:
                return {"head": {"sha": "b" * 40}, "base": {"sha": "a" * 40}, "changed_files": 1}
            if "/compare/" in path:
                return {"merge_base_commit": {"sha": "a" * 40}}
            if "/trees/" in path:
                return {"truncated": False, "tree": [{"path": "app.py", "type": "blob", "mode": "100644",
                        "sha": "1" * 40 if "a" * 40 in path else "2" * 40, "size": 5}]}
            data = b"old\n" if "1" * 40 in path else b"new\n"
            return {"encoding": "base64", "content": base64.b64encode(data).decode()}
        def pages(self, path):
            return [{"filename": "app.py", "status": "modified", "patch": "@@ -1 +1 @@\n-old\n+new"}]
    request = ReviewRequest(tmp_path, pr="owner/repo#7")
    snapshot = GitHubSource(SourceClient()).resolve(request, time.monotonic() + 30)
    assert snapshot.read("app.py", "base") == "old\n"
    assert snapshot.read("app.py") == "new\n"
    assert snapshot.source["repository"] == "owner/repo"


def test_publisher_failure_does_not_rewrite_scan_status():
    from security_review.github import GitHubPublisher
    client = FakeGitHub()
    client.request = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError())
    report = report_for_pr()
    result = GitHubPublisher(client).publish(report, "owner/repo#7")
    assert result.status == "failed" and report.status == "completed"


def test_pr_locator_rejects_credentials_and_non_github_paths():
    from security_review.github import parse_pr
    for locator in ("https://secret@evil.invalid/a#7", "../repo#7", "owner/repo#0"):
        with pytest.raises(ValueError):
            parse_pr(locator)


def test_action_publisher_uses_explicit_bot_actor_for_installation_tokens():
    from security_review.github import GitHubPublisher
    client = FakeGitHub()
    original = client.request
    def request(method, path, body=None):
        if path == "/user":
            raise AssertionError("Installation tokens cannot use /user")
        if path == "/users/github-actions%5Bbot%5D":
            return {"id": 99}
        return original(method, path, body)
    client.request = request
    assert GitHubPublisher(client, actor="github-actions[bot]").publish(report_for_pr(), "owner/repo#7").status == "published"


def test_direct_pr_comparison_includes_base_only_changes(tmp_path):
    from security_review.github import GitHubSource
    class Diverged:
        def request(self, method, path, body=None):
            if "/pulls/" in path:
                return {"base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}, "changed_files": 0}
            if "/trees/" in path:
                entries = [{"path": "base-only.py", "type": "blob", "mode": "100644", "sha": "1" * 40, "size": 4}]
                return {"tree": entries if "a" * 40 in path else [], "truncated": False}
            return {"encoding": "base64", "content": base64.b64encode(b"old\n").decode()}
        def pages(self, path):
            return []
    snapshot = GitHubSource(Diverged()).resolve(ReviewRequest(tmp_path, comparison="direct", pr="owner/repo#7"), time.monotonic() + 30)
    assert snapshot.changed_files == ("base-only.py",)
    assert "-old" in snapshot.diff
