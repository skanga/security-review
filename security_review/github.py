"""GitHub REST source and publisher, independent of investigation credentials."""
import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import difflib
from fnmatch import fnmatchcase
import json
import re
import time
from types import MappingProxyType
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .policy import digest
from .repository import Snapshot, validate_path, FILE_LIMIT, SNAPSHOT_LIMIT, COMMAND_LIMIT
from .rendering import safe_text
from .runtime import checkpoint


def parse_pr(locator):
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)#([1-9][0-9]*)", locator or "")
    if not match or any(value in {".", ".."} for value in match.groups()[:2]):
        raise ValueError("PR must be owner/repository#positive-number")
    return f"{match[1]}/{match[2]}", int(match[3])


class GitHubError(Exception):
    def __init__(self, status):
        self.status = status
        self.retryable = status == 429 or status >= 500
        self.code = "RATE_LIMIT" if status == 429 else "AUTHENTICATION" if status == 401 else "PERMISSION" if status == 403 else "SOURCE_RESOLUTION"
        super().__init__(f"GitHub request failed (HTTP {status})")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHubClient:
    def __init__(self, token=None, *, transport=None, timeout=180):
        self.token = token
        self.transport = transport
        self.deadline = time.monotonic() + timeout

    def request(self, method, path, body=None):
        if not path.startswith("/") or path.startswith("//") or "\n" in path:
            raise ValueError("Invalid GitHub API path")
        for attempt in range(3):
            checkpoint()
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("GitHub operation deadline exhausted")
            try:
                if self.transport:
                    return self.transport(method, path, body, min(30, remaining))
                headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10",
                           "User-Agent": "security-review-engine/0.1.0"}
                if self.token:
                    headers["Authorization"] = "Bearer " + self.token
                data = json.dumps(body).encode() if body is not None else None
                request = Request("https://api.github.com" + path, data=data, headers=headers, method=method)
                with build_opener(NoRedirect()).open(request, timeout=min(30, remaining)) as response:
                    content = response.read(COMMAND_LIMIT + 1)
                if len(content) > COMMAND_LIMIT:
                    raise ValueError("GitHub response exceeds 8 MiB")
                return json.loads(content)
            except HTTPError as exc:
                error = GitHubError(exc.code)
                # Writes can have succeeded despite a lost response; caller retries via dedup.
                if method != "GET" or not error.retryable or attempt == 2:
                    raise error from None
                wait = min(2 ** attempt, max(0, self.deadline - time.monotonic()))
                until = time.monotonic() + wait
                while time.monotonic() < until:
                    checkpoint()
                    time.sleep(min(0.05, max(0, until - time.monotonic())))

    def pages(self, path):
        result = []
        for page in range(1, 101):
            values = self.request("GET", f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
            if not isinstance(values, list):
                raise ValueError("GitHub pagination returned an invalid page")
            result.extend(values)
            if len(values) < 100:
                return result
        raise ValueError("GitHub result exceeds 10000 items")


class GitHubSource:
    def __init__(self, client):
        self.client = client

    def resolve(self, request, deadline):
        repository, number = parse_pr(request.pr)
        prefix = f"/repos/{repository}"
        pr = self.client.request("GET", f"{prefix}/pulls/{number}")
        original_base, head = pr["base"]["sha"], pr["head"]["sha"]
        if any(not re.fullmatch(r"[a-f0-9]{40,64}", value) for value in (original_base, head)):
            raise ValueError("GitHub returned invalid commit IDs")
        base = original_base
        if request.comparison == "merge_base":
            base = self.client.request("GET", f"{prefix}/compare/{original_base}...{head}")["merge_base_commit"]["sha"]
        changed = self.client.pages(f"{prefix}/pulls/{number}/files")
        if len(changed) != pr["changed_files"]:
            raise ValueError("GitHub changed-file inventory is incomplete")
        reasons, cache, total, metadata = {}, {}, 0, {}

        def tree(revision, side):
            nonlocal total
            response = self.client.request("GET", f"{prefix}/git/trees/{revision}?recursive=1")
            if response.get("truncated") or len(response["tree"]) > 10000:
                raise ValueError("GitHub tree is truncated or exceeds inventory limit")
            files = {}
            for entry in response["tree"]:
                checkpoint()
                if time.monotonic() >= deadline:
                    raise TimeoutError("Source acquisition deadline exhausted")
                if entry["type"] == "tree":
                    continue
                path = validate_path(entry["path"])
                metadata.setdefault(path, {})[side] = entry["mode"]
                metadata[path][side + "_oid"] = entry["sha"]
                if any(fnmatchcase(path, pattern) for pattern in request.denied_paths):
                    reasons[path] = "access_denied"
                    continue
                if entry["type"] != "blob" or entry["mode"] not in {"100644", "100755"}:
                    reasons[path] = "submodule" if entry["type"] == "commit" else "link"
                    continue
                if entry.get("size", FILE_LIMIT + 1) > FILE_LIMIT:
                    reasons[path] = "oversized"
                    continue
                oid = entry["sha"]
                if not re.fullmatch(r"[a-f0-9]{40,64}", oid):
                    raise ValueError("Invalid blob ID")
                if oid not in cache:
                    blob = self.client.request("GET", f"{prefix}/git/blobs/{oid}")
                    if blob.get("encoding") != "base64":
                        raise ValueError("Unsupported blob encoding")
                    content = base64.b64decode(blob["content"])
                    total += len(content)
                    if len(content) > FILE_LIMIT or total > SNAPSHOT_LIMIT:
                        raise ValueError("GitHub snapshot content limit exceeded")
                    cache[oid] = content
                files[path] = cache[oid]
                if b"\0" in files[path]:
                    reasons[path] = "binary"
                elif files[path].startswith(b"version https://git-lfs.github.com/spec/v1"):
                    reasons[path] = "lfs_pointer"
                else:
                    try:
                        files[path].decode("utf-8")
                    except UnicodeDecodeError:
                        reasons[path] = "unsupported_encoding"
            return files

        base_files, head_files = tree(base, "base"), tree(head, "head")
        if request.comparison == "direct":
            changed = [{"filename": path, "status": "added" if "base_oid" not in entry else "removed" if "head_oid" not in entry else "modified"}
                       for path, entry in metadata.items()
                       if (entry.get("base_oid"), entry.get("base")) != (entry.get("head_oid"), entry.get("head"))]
        inventory, changes, patches = set(), [], []
        for item in changed:
            path = validate_path(item["filename"])
            old_path = validate_path(item.get("previous_filename", path))
            inventory.add(path)
            if old_path != path:
                inventory.add(old_path)
            before, after = base_files.get(old_path), head_files.get(path)
            changes.append({"path": path, "old_path": old_path if before is not None else None,
                            "new_path": path if after is not None else None, "status": item["status"],
                            "base_content_id": __import__("hashlib").sha256(before).hexdigest() if before is not None else None,
                            "head_content_id": __import__("hashlib").sha256(after).hexdigest() if after is not None else None,
                            "base_mode": metadata.get(old_path, {}).get("base"), "head_mode": metadata.get(path, {}).get("head")})
            if path not in reasons and old_path not in reasons:
                patches.append("".join(difflib.unified_diff((before or b"").decode().splitlines(True),
                              (after or b"").decode().splitlines(True), fromfile="a/" + old_path, tofile="b/" + path)))
        latest = self.client.request("GET", f"{prefix}/pulls/{number}")
        if latest["head"]["sha"] != head or latest["base"]["sha"] != original_base:
            raise ValueError("PR changed during source capture; retry")
        diff = "".join(patches)
        if len(diff.encode()) > COMMAND_LIMIT:
            raise ValueError("PR diff exceeds 8 MiB")
        identity = digest({"repository": repository, "base": base, "head": head, "denied": request.denied_paths})
        return Snapshot(base, head, identity, tuple(sorted(inventory)), MappingProxyType(base_files), MappingProxyType(head_files),
                        tuple(sorted(reasons)), diff, MappingProxyType(reasons), tuple(changes), "revisions",
                        datetime.now(timezone.utc).isoformat(), MappingProxyType({"type": "github", "repository": repository, "number": number}))


@dataclass
class PublicationResult:
    target: str
    run_id: str
    snapshot_id: str
    status: str = "failed"
    created: list = field(default_factory=list)
    updated: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _inline_lines(patch):
    lines = {"head": set(), "base": set()}
    old = new = None
    for text in (patch or "").splitlines():
        match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", text)
        if match:
            old, new = int(match[1]), int(match[2])
        elif old is not None:
            if text.startswith("-"):
                lines["base"].add(old); old += 1
            elif text.startswith("+"):
                lines["head"].add(new); new += 1
            elif text.startswith(" "):
                lines["base"].add(old); lines["head"].add(new); old += 1; new += 1
    return lines


class GitHubPublisher:
    def __init__(self, client, *, actor=None):
        self.client = client
        self.actor = actor

    def publish(self, report, target):
        result = PublicationResult(target, report.run_id, report.snapshot.get("id", ""))
        try:
            repository, number = parse_pr(target)
            source = report.snapshot.get("source", {})
            if source.get("repository") != repository or source.get("number") != number:
                raise ValueError("Report is not bound to the publication target")
            prefix, head = f"/repos/{repository}", report.snapshot["head"]
            pr_path = f"{prefix}/pulls/{number}"

            def fresh():
                return self.client.request("GET", pr_path)["head"]["sha"] == head

            if not fresh():
                result.status = "stale"
                return result
            user = self.client.request("GET", "/users/" + quote(self.actor, safe="") if self.actor else "/user")["id"]
            existing = self.client.pages(f"{prefix}/issues/{number}/comments") + self.client.pages(f"{pr_path}/comments")
            owned_bodies = [c.get("body", "") for c in existing if c.get("user", {}).get("id") == user]
            changed = self.client.pages(f"{pr_path}/files")
            mapping = {}
            for item in changed:
                mapping[item["filename"]] = (item["filename"], _inline_lines(item.get("patch")))
                if item.get("previous_filename"):
                    mapping[item["previous_filename"]] = mapping[item["filename"]]
            for finding in report.findings:
                if not finding.get("reportable", True) or finding["validation_status"] != "confirmed":
                    continue
                marker = f"<!-- security-review:v1:{head}:{digest(finding['fingerprint'])} -->"
                if any(marker in body for body in owned_bodies):
                    result.skipped.append(finding["id"])
                    continue
                if not fresh():
                    result.status = "stale"
                    return result
                body = f"{marker}\n**{safe_text(finding['severity'])}** {safe_text(finding['description'])}\n\nReviewed commit `{head}`."
                mapped_path, lines = mapping.get(finding["file"], (finding["file"], {"base": set(), "head": set()}))
                side = finding.get("side", "head")
                if finding["line"] in lines[side]:
                    payload = {"body": body, "commit_id": head, "path": mapped_path, "line": finding["line"],
                               "side": "LEFT" if side == "base" else "RIGHT"}
                    created = self.client.request("POST", f"{pr_path}/comments", payload)
                else:
                    body += f"\n\nLocation: {safe_text(finding['file'])}:{finding['line']} ({side}); outside inline diff."
                    created = self.client.request("POST", f"{prefix}/issues/{number}/comments", {"body": body})
                result.created.append(created["id"])
            summary_marker = f"<!-- security-review:summary:v1:{head}:{report.config_hash}:{report.status} -->"
            if not any(summary_marker in body for body in owned_bodies):
                if not fresh():
                    result.status = "stale"
                    return result
                body = (f"{summary_marker}\nSecurity review of `{head}`: **{safe_text(report.status)}**, "
                        f"policy **{safe_text(report.policy_outcome)}**. "
                        f"{len(report.coverage['assessed'])}/{len(report.coverage['eligible'])} eligible files assessed. "
                        f"{len(report.coverage['incomplete'])} incomplete; {len(report.errors)} execution errors. "
                        f"{sum(f['validation_status'] != 'confirmed' for f in report.findings)} unconfirmed candidates retained in the report.")
                result.created.append(self.client.request("POST", f"{prefix}/issues/{number}/comments", {"body": body})["id"])
            result.status = "published"
        except Exception as exc:
            result.errors.append({"code": "PUBLICATION_FAILED", "message": f"Publication failed ({type(exc).__name__}); retry this saved report",
                                  "retryable": isinstance(exc, TimeoutError) or getattr(exc, "retryable", False)})
        return result
