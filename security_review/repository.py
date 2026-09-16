"""Read immutable Git objects for trusted local repositories; never checkout code."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import difflib
from fnmatch import fnmatchcase
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess
import tempfile
import time
import stat
import re
from types import MappingProxyType
from typing import Mapping

from .models import ReviewRequest
from .runtime import checkpoint, run_process

FILE_LIMIT = 1024 * 1024
SNAPSHOT_LIMIT = 32 * 1024 * 1024
COMMAND_LIMIT = 8 * 1024 * 1024


def validate_path(path: str) -> str:
    if (not isinstance(path, str) or not path or "\0" in path or "\\" in path
            or ":" in path or PureWindowsPath(path).drive
            or PurePosixPath(path).is_absolute()
            or any(part in {"", ".", ".."} for part in path.split("/"))):
        raise ValueError("Expected an unambiguous repository-relative path")
    return path


@dataclass(frozen=True)
class Snapshot:
    base: str
    head: str
    snapshot_id: str
    changed_files: tuple[str, ...]
    base_files: Mapping[str, bytes]
    head_files: Mapping[str, bytes]
    unavailable: tuple[str, ...]
    diff: str
    unavailable_reasons: Mapping[str, str] = field(default_factory=dict)
    changes: tuple[dict, ...] = ()
    mode: str = "revisions"
    captured_at: str = ""
    source: Mapping = field(default_factory=dict)

    def read(self, path: str, side: str = "head") -> str:
        validate_path(path)
        if side not in {"base", "head"}:
            raise ValueError("side must be base or head")
        files = self.head_files if side == "head" else self.base_files
        if path not in files:
            raise ValueError("File is unavailable in the selected snapshot side")
        content = files[path]
        if b"\0" in content:
            raise ValueError("Binary content is not supported in this review slice")
        return content.decode("utf-8")

    def list_files(self, cursor=0, limit=100):
        if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Invalid inventory cursor/limit")
        paths = sorted(set(self.head_files) | set(self.unavailable))
        end = min(cursor + limit, len(paths))
        return {"items": paths[cursor:end], "next_cursor": end if end < len(paths) else None}

    def read_lines(self, path, side="head", start=1, limit=200):
        if type(start) is not int or start < 1 or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Invalid line range")
        lines = self.read(path, side).splitlines(keepends=True)
        text = "".join(lines[start - 1:start - 1 + limit])
        if len(text.encode()) > 65536:
            raise ValueError("Selected lines exceed 64 KiB; request smaller range")
        end = min(start - 1 + limit, len(lines))
        return {"text": text, "next_line": end + 1 if end < len(lines) else None}

    def search(self, query, cursor=0, limit=100):
        if not isinstance(query, str) or not query or len(query) > 1024 or not 1 <= limit <= 100 or cursor < 0:
            raise ValueError("Invalid literal search")
        matches = []
        for path in sorted(self.head_files):
            if path in self.unavailable:
                continue
            for line, text in enumerate(self.read(path).splitlines(), 1):
                if query in text:
                    matches.append({"file": path, "line": line, "text": text[:256]})
                    if len(matches) > cursor + limit:
                        return {"items": matches[cursor:cursor + limit], "next_cursor": cursor + limit}
        return {"items": matches[cursor:], "next_cursor": None}

    def diff_page(self, cursor=0, limit=16000):
        if type(cursor) is not int or cursor < 0 or not 1 <= limit <= 16000:
            raise ValueError("Invalid diff cursor/limit")
        end = min(cursor + limit, len(self.diff))
        return {"text": self.diff[cursor:end], "next_cursor": end if end < len(self.diff) else None}


class GitReader:
    def __init__(self, repository, deadline):
        self.repository = repository
        self.deadline = deadline

    def run(self, *args, limit=COMMAND_LIMIT):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Review deadline exhausted during source acquisition")
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_LITERAL_PATHSPECS="1")
        # Only read-only Git commands run in the caller's trusted repository.
        command = ["git", "--no-replace-objects", "-c", "core.fsmonitor=false",
                   "-c", "core.quotePath=false", "-C", str(self.repository), *args]
        result = run_process(command, env=env, timeout=min(30, remaining), limit=limit)
        if result.returncode:
            raise ValueError(f"Git {args[0]} failed; check ownership and local history/object availability")
        return result.stdout


def _capture_revisions(request: ReviewRequest, deadline: float | None = None) -> Snapshot:
    reader = GitReader(request.repository, deadline or time.monotonic() + request.timeout_seconds)
    base = reader.run("rev-parse", "--verify", "--end-of-options", request.base + "^{commit}").decode().strip()
    head = reader.run("rev-parse", "--verify", "--end-of-options", request.head + "^{commit}").decode().strip()
    if request.comparison == "merge_base":
        base = reader.run("merge-base", base, head).decode().strip()
    changed = tuple(filter(None, reader.run(
        "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z",
        base, head, "--").decode("utf-8").split("\0")))
    cache = {}
    unavailable = set()
    total = 0

    def tree(revision):
        nonlocal total
        entries = reader.run("ls-tree", "-r", "-z", revision).split(b"\0")
        if len(entries) > 10001:
            raise ValueError("Snapshot exceeds 10000 files")
        files = {}
        for entry in filter(None, entries):
            checkpoint()
            meta, raw_path = entry.split(b"\t", 1)
            mode, kind, oid = meta.decode("ascii").split()
            path = raw_path.decode("utf-8")
            validate_path(path)
            if any(fnmatchcase(path, pattern) for pattern in request.denied_paths):
                unavailable.add(path)
                continue
            if kind != "blob" or mode not in {"100644", "100755"}:
                unavailable.add(path)
                continue
            if oid not in cache:
                size = int(reader.run("cat-file", "-s", oid, limit=100))
                if size > FILE_LIMIT:
                    unavailable.add(path)
                    continue
                total += size
                if total > SNAPSHOT_LIMIT:
                    raise ValueError("Snapshot exceeds the 32 MiB content limit")
                cache[oid] = reader.run("cat-file", "blob", oid, limit=FILE_LIMIT)
            files[path] = cache[oid]
            try:
                if b"\0" in files[path]:
                    raise ValueError("binary")
                files[path].decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                unavailable.add(path)
        return MappingProxyType(files)

    base_files, head_files = tree(base), tree(head)
    allowed = [p for p in changed if not any(fnmatchcase(p, pattern) for pattern in request.denied_paths)]
    diff = reader.run("diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                      "--diff-algorithm=myers", "--unified=3", base, head, "--", *allowed).decode("utf-8", "replace") if allowed else ""
    identity = json.dumps({"base": base, "head": head, "comparison": request.comparison}, sort_keys=True)
    return Snapshot(base, head, hashlib.sha256(identity.encode()).hexdigest(), changed,
                    base_files, head_files, tuple(sorted(unavailable)), diff)


def _content_id(data):
    return hashlib.sha256(data).hexdigest()


def _working_files(request, reader, index_files):
    paths = set(index_files)
    if request.include_untracked:
        paths.update(filter(None, reader.run("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")))
    if len(paths) > 10000:
        raise ValueError("Snapshot exceeds 10000 files")
    files, reasons, total = {}, {}, 0
    for path in sorted(paths):
        checkpoint()
        validate_path(path)
        target = request.repository / path
        if any(fnmatchcase(path, pattern) for pattern in request.denied_paths):
            reasons[path] = "access_denied"
            continue
        if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
               for p in (target, *target.parents) if p != request.repository and request.repository in p.parents):
            reasons[path] = "link"
            continue
        try:
            before = target.stat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(before.st_mode) or before.st_size > FILE_LIMIT:
            reasons[path] = "nonregular" if not stat.S_ISREG(before.st_mode) else "oversized"
            continue
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(target, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            data = stream.read(FILE_LIMIT + 1)
            after = os.fstat(stream.fileno())
        # Windows stat/fstat disagree on ctime (creation versus change time).
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if signature(before) != signature(opened) or signature(opened) != signature(after) or signature(after) != signature(target.stat()):
            raise ValueError("Working file changed during capture")
        total += len(data)
        if len(data) > FILE_LIMIT or total > SNAPSHOT_LIMIT:
            raise ValueError("Working-copy content limit exceeded")
        files[path] = data
    return files, reasons


def capture(request: ReviewRequest, deadline: float | None = None) -> Snapshot:
    deadline = deadline or time.monotonic() + request.timeout_seconds
    reader = GitReader(request.repository, deadline)
    root = Path(os.fsdecode(reader.run("rev-parse", "--show-toplevel")).strip()).resolve()
    if root != request.repository:
        raise ValueError("Source directory must be the repository root")
    if request.mode == "revisions":
        snapshot = _capture_revisions(request, deadline)
        base_files, head_files = dict(snapshot.base_files), dict(snapshot.head_files)
        unavailable = dict.fromkeys(snapshot.unavailable, "unavailable")
        changed, base, head, diff = snapshot.changed_files, snapshot.base, snapshot.head, snapshot.diff
        # Name/status/modes are read from the same immutable revisions.
        modes = {}
        for side, revision in (("base", base), ("head", head)):
            for entry in filter(None, reader.run("ls-tree", "-r", "-z", revision).split(b"\0")):
                meta, path = entry.split(b"\t", 1)
                modes.setdefault(path.decode(), {})[side] = meta.decode().split()[0]
    else:
        head = reader.run("rev-parse", "HEAD").decode().strip()
        if request.head != "HEAD" and reader.run("rev-parse", "--verify", request.head + "^{commit}").decode().strip() != head:
            raise ValueError("Working modes require current HEAD")
        initial = _capture_revisions(replace(request, base=head, head=head, comparison="direct"), deadline)
        commit_modes = {}
        for entry in filter(None, reader.run("ls-tree", "-r", "-z", head).split(b"\0")):
            meta, raw_path = entry.split(b"\t", 1)
            commit_modes[raw_path.decode()] = meta.decode().split()[0]
        index_raw = reader.run("ls-files", "--stage", "-z")
        index_files, index_modes, unavailable, total = {}, {}, {}, 0
        for entry in filter(None, index_raw.split(b"\0")):
            meta, raw_path = entry.split(b"\t", 1)
            mode, oid, stage = meta.decode().split()
            path = validate_path(raw_path.decode())
            if stage != "0":
                raise ValueError("Unmerged index cannot be reviewed")
            index_modes[path] = mode
            if mode not in {"100644", "100755"} or any(fnmatchcase(path, p) for p in request.denied_paths):
                unavailable[path] = "link_or_access_denied"
                index_files[path] = None
                continue
            size = int(reader.run("cat-file", "-s", oid, limit=100))
            if size > FILE_LIMIT:
                unavailable[path] = "oversized"
                index_files[path] = None
                continue
            total += size
            if total > SNAPSHOT_LIMIT:
                raise ValueError("Index exceeds snapshot content limit")
            index_files[path] = reader.run("cat-file", "blob", oid, limit=FILE_LIMIT)
        base_files = dict(initial.head_files) if request.mode != "unstaged" else dict(index_files)
        base_files = {p: data for p, data in base_files.items() if data is not None}
        if request.mode == "staged":
            head_files = {p: data for p, data in index_files.items() if data is not None}
        else:
            head_files, working_reasons = _working_files(request, reader, index_files)
            repeated = _working_files(request, reader, index_files)
            if repeated != (head_files, working_reasons):
                raise ValueError("Working copy changed during capture; retry")
            unavailable.update(working_reasons)
        if index_raw != reader.run("ls-files", "--stage", "-z") or head != reader.run("rev-parse", "HEAD").decode().strip():
            raise ValueError("Index or HEAD changed during capture; retry")
        base = head
        base_modes = index_modes if request.mode == "unstaged" else commit_modes
        head_modes = dict(index_modes)
        if request.mode != "staged":
            try:
                filemode = reader.run("config", "--bool", "core.filemode").strip() == b"true"
            except ValueError:
                filemode = False
            for path in head_files:
                head_modes[path] = ("100755" if (request.repository / path).stat().st_mode & 0o111 else "100644") if filemode else index_modes.get(path, "100644")
        changed = tuple(sorted(p for p in set(base_files) | set(head_files) | set(unavailable)
                               if base_files.get(p) != head_files.get(p) or p in unavailable or base_modes.get(p) != head_modes.get(p)))
        diff = "".join("".join(difflib.unified_diff(base_files.get(p, b"").decode("utf-8", "replace").splitlines(True),
                       head_files.get(p, b"").decode("utf-8", "replace").splitlines(True), fromfile="a/" + p, tofile="b/" + p))
                       for p in changed if p not in unavailable)
        modes = {p: {"base": base_modes.get(p), "head": head_modes.get(p)} for p in changed}
    if len(diff.encode()) > COMMAND_LIMIT:
        raise ValueError("Diff exceeds 8 MiB; narrow the review")
    for path, data in list(base_files.items()) + list(head_files.items()):
        if b"\0" in data:
            unavailable[path] = "binary"
        elif data.startswith(b"version https://git-lfs.github.com/spec/v1"):
            unavailable[path] = "lfs_pointer"
        else:
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                unavailable[path] = "unsupported_encoding"
    for path in unavailable:
        if any(fnmatchcase(path, p) for p in request.denied_paths):
            unavailable[path] = "access_denied"
        elif modes.get(path, {}).get("head") == "160000":
            unavailable[path] = "submodule"
        elif modes.get(path, {}).get("head") == "120000":
            unavailable[path] = "link"
        elif unavailable[path] == "unavailable":
            unavailable[path] = "oversized_or_unsupported_mode"
    changes = []
    for path in changed:
        old, new = base_files.get(path), head_files.get(path)
        changes.append({"path": path, "old_path": path if old is not None else None,
                        "new_path": path if new is not None else None,
                        "status": "added" if old is None else "deleted" if new is None else "modified",
                        "base_content_id": _content_id(old) if old is not None else None,
                        "head_content_id": _content_id(new) if new is not None else None,
                        "base_mode": modes.get(path, {}).get("base"), "head_mode": modes.get(path, {}).get("head")})
    removed = {v["base_content_id"]: v for v in changes if v["status"] == "deleted" and v["base_content_id"]}
    for item in changes:
        previous = removed.get(item["head_content_id"]) if item["status"] == "added" else None
        if previous:
            item.update(status="renamed", old_path=previous["path"])
            previous["renamed_to"] = item["path"]
    if request.mode == "revisions":
        records = iter(filter(None, reader.run("diff", "--no-ext-diff", "--no-textconv", "--name-status", "-z", "-M", base, head, "--").decode().split("\0")))
        by_path = {change["path"]: change for change in changes}
        for status in records:
            path = next(records)
            if status.startswith("R"):
                new_path = next(records)
                if new_path in by_path:
                    by_path[new_path].update(status="renamed", old_path=path)
                if path in by_path:
                    by_path[path]["renamed_to"] = new_path
    identity = {"base": base, "head": head, "mode": request.mode, "comparison": request.comparison,
                "changes": changes, "denied_paths": request.denied_paths,
                "base_manifest": {p: _content_id(data) for p, data in base_files.items()},
                "head_manifest": {p: _content_id(data) for p, data in head_files.items()}, "unavailable": unavailable}
    return Snapshot(base, head, _content_id(json.dumps(identity, sort_keys=True).encode()), tuple(changed),
                    MappingProxyType(base_files), MappingProxyType(head_files), tuple(sorted(unavailable)), diff,
                    MappingProxyType(unavailable), tuple(changes), request.mode, datetime.now(timezone.utc).isoformat(),
                    MappingProxyType({"type": "local", "repository": str(request.repository)}))
