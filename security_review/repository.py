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

    def run(self, *args, limit=COMMAND_LIMIT, input=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Review deadline exhausted during source acquisition")
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_LITERAL_PATHSPECS="1")
        # Only read-only Git commands run in the caller's trusted repository.
        command = ["git", "--no-replace-objects", "-c", "core.fsmonitor=false",
                   "-c", "core.quotePath=false", "-C", str(self.repository), *args]
        result = run_process(command, env=env, input=input, timeout=min(30, remaining), limit=limit)
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


def _index_stats(reader):
    """Read cached stat metadata only; ls-files --modified can open content/run filters."""
    raw = reader.run("ls-files", "--debug", "-z")
    pattern = re.compile(rb"  ctime: (\d+):(\d+)\n  mtime: (\d+):(\d+)\n"
                         rb"  dev: (\d+)\tino: (\d+)\n  uid: (\d+)\tgid: (\d+)\n"
                         rb"  size: (\d+)\tflags: ([0-9a-f]+)\n")
    entries, offset = {}, 0
    while offset < len(raw):
        end = raw.index(b"\0", offset)
        path = validate_path(raw[offset:end].decode())
        match = pattern.match(raw, end + 1)
        if not match:
            raise ValueError("Unsupported Git index stat metadata")
        entries[path] = tuple(int(v) for v in match.groups()[:-1]) + (int(match[10], 16),)
        offset = match.end()
    return entries


def _file_state(info):
    return (info.st_mode, info.st_size, info.st_mtime_ns,
            getattr(info, "st_birthtime_ns", info.st_ctime_ns) if os.name == "nt" else info.st_ctime_ns,
            info.st_dev, info.st_ino, info.st_uid, info.st_gid)


def _matches_index_stat(state, cached):
    if state is None or cached is None:
        return False
    mode, size, mtime, ctime, dev, ino, uid, gid = state
    csec, cnsec, msec, mnsec, cdev, cino, cuid, cgid, csize, flags = cached
    if not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)) or flags & 0x20000000:
        return False  # Nonregular/intent-to-add entries need an explicit change result.
    # Windows Python reports zero for link size; Git records the target-string
    # length. Retargeting/replacing the link still changes its cached timestamps.
    same_size = size == csize or os.name == "nt" and stat.S_ISLNK(mode) and size == 0
    return (same_size and divmod(mtime, 10**9) == (msec, mnsec)
            and divmod(ctime, 10**9) == (csec, cnsec)
            and (not cdev or dev & 0xFFFFFFFF == cdev)
            and (not cino or ino & 0xFFFFFFFF == cino) and (uid, gid) == (cuid, cgid))


def _working_files(request, reader, index_files):
    paths = set(index_files)
    if request.include_untracked:
        paths.update(filter(None, reader.run("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")))
    if len(paths) > 10000:
        raise ValueError("Snapshot exceeds 10000 files")
    files, reasons, states, total = {}, {}, {}, 0
    for path in sorted(paths):
        checkpoint()
        validate_path(path)
        target = request.repository / path
        denied = any(fnmatchcase(path, pattern) for pattern in request.denied_paths)
        if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
               for p in target.parents if p != request.repository and request.repository in p.parents):
            reasons[path] = "access_denied" if denied else "link"
            states[path] = None  # Do not even stat a child through a directory link.
            continue
        try:
            before = target.lstat()
        except FileNotFoundError:
            if denied:
                reasons[path] = "access_denied"
            continue
        states[path] = _file_state(before)
        if denied:
            reasons[path] = "access_denied"
            continue
        if stat.S_ISLNK(before.st_mode) or (hasattr(target, "is_junction") and target.is_junction()):
            reasons[path] = "link"
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
    return files, reasons, states


def _eol_binary(data):
    """Git's automatic text heuristic, applied only to already captured bytes."""
    text = data.replace(b"\r\n", b"\n")
    if b"\0" in text or b"\r" in text:
        return True
    controls = sum(byte == 127 or byte < 32 and byte not in (8, 9, 10, 12, 27) for byte in text)
    printable = len(text) - text.count(b"\n") - controls
    return controls - int(text.endswith(b"\x1a")) > printable // 128


def _attribute_source_states(request, paths):
    states = {}
    for path in paths:
        path = Path(path)
        if not path.is_absolute():
            path = request.repository / path
        normalized = Path(os.path.abspath(path))
        if normalized.is_relative_to(request.repository) and any(
                fnmatchcase(normalized.relative_to(request.repository).as_posix(), rule) for rule in request.denied_paths):
            return None
        # Keep the original traversal for link checks: collapsing '..' must not
        # hide a symlink/junction that Git would traverse when opening the path.
        if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (path, *path.parents)):
            return None
        try:
            info = path.lstat()
        except FileNotFoundError:
            states[str(path)] = None
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_size > FILE_LIMIT:
            return None
        states[str(path)] = _file_state(info)
    return states


def _working_eol(request, reader, files, index_files):
    paths = [path for path, data in files.items() if b"\r\n" in data]
    if not paths:
        return dict(files), {}
    try:
        extra_sources = [reader.run("var", name).decode().strip() for name in ("GIT_ATTR_GLOBAL", "GIT_ATTR_SYSTEM")]
        extra_sources.append(reader.run("rev-parse", "--git-path", "info/attributes").decode().strip())
    except ValueError:
        # Older Git versions may not expose all attribute sources. Do not guess.
        return dict(files), {}
    extra_states = _attribute_source_states(request, [p for p in extra_sources if p])
    if extra_states is None:
        return dict(files), {}
    # check-attr reads only attributes, never file contents or clean filters. Check
    # every applicable repository attribute file before allowing that lookup.
    ancestors = {path: [(parent / ".gitattributes").as_posix()
                        for parent in PurePosixPath(path).parents] for path in paths}
    attribute_paths = dict.fromkeys({p for values in ancestors.values() for p in values})
    attribute_request = replace(request, include_untracked=False)
    captured = _working_files(attribute_request, reader, attribute_paths)
    attr_files, attr_reasons, _ = captured
    unsafe = set(attr_reasons) | {p for p in attribute_paths if p in index_files and index_files[p] is None}
    safe_paths = [path for path in paths if not unsafe.intersection(ancestors[path])]
    attributes = {}
    if safe_paths:
        raw = reader.run("check-attr", "-z", "--stdin", "text", "eol", "crlf",
                         input="\0".join(safe_paths) + "\0").decode().split("\0")[:-1]
        if len(raw) != len(safe_paths) * 9:
            raise ValueError("Invalid Git attribute result")
        for path, name, value in zip(raw[::3], raw[1::3], raw[2::3]):
            attributes.setdefault(path, {})[name] = value
    if captured != _working_files(attribute_request, reader, attribute_paths):
        raise ValueError("Attributes changed during capture; retry")
    if extra_states != _attribute_source_states(request, extra_states):
        raise ValueError("Attributes changed during capture; retry")
    for path, data in attr_files.items():
        if path in files and data != files[path]:
            raise ValueError("Attributes changed during capture; retry")
    try:
        autocrlf = reader.run("config", "--get", "core.autocrlf").decode().strip().lower()
    except ValueError:
        autocrlf = "false"
    normalized = dict(files)
    for path, attrs in attributes.items():
        action = attrs["text"]
        if action not in {"set", "unset", "auto", "input"}:
            action = attrs["crlf"]
        if action == "unset":
            continue
        if attrs["eol"] in {"lf", "crlf"} and action != "auto":
            action = "set"
        if action not in {"set", "input", "auto"}:
            action = "auto" if autocrlf in {"true", "input", "yes", "on", "1"} else "unset"
        data, indexed = files[path], index_files.get(path)
        if action == "auto" and (_eol_binary(data) or indexed is None
                                 or b"\r\n" in indexed and not _eol_binary(indexed)):
            continue
        if action in {"set", "input", "auto"}:
            normalized[path] = data.replace(b"\r\n", b"\n")
    return normalized, {"autocrlf": autocrlf, "attributes": attributes}


def _working_gitlinks(request, reader, index_modes, index_oids, states):
    """Inspect existing submodule HEAD/index/stat metadata; never read its source."""
    result = {}
    for path, mode in index_modes.items():
        if mode != "160000" or path not in states:
            continue
        result[path] = None
        state = states[path]
        if state is None or not stat.S_ISDIR(state[0]):
            continue
        if any(fnmatchcase(path, p) or fnmatchcase(path + "/.git", p) for p in request.denied_paths):
            continue
        root = request.repository / path
        gitdir = root / ".git"
        if gitdir.is_symlink() or (hasattr(gitdir, "is_junction") and gitdir.is_junction()):
            continue
        if not gitdir.exists():
            # An uninitialized directory has no checked-out revision to compare.
            continue
        nested = GitReader(root, reader.deadline)
        if Path(nested.run("rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
            continue
        head = nested.run("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        tree = {}
        for entry in filter(None, nested.run("ls-tree", "-r", "-z", head).split(b"\0")):
            meta, name = entry.split(b"\t", 1)
            entry_mode, _, oid = meta.decode().split()
            tree[validate_path(name.decode())] = (entry_mode, oid)
        index = {}
        for entry in filter(None, nested.run("ls-files", "--stage", "-z").split(b"\0")):
            meta, name = entry.split(b"\t", 1)
            entry_mode, oid, stage = meta.decode().split()
            index[validate_path(name.decode())] = (entry_mode, oid, stage)
        stats = _index_stats(nested)
        # Treat every nested file as opaque. Cached stat mismatches, including
        # dirty files at an unchanged HEAD, remain incomplete submodule changes.
        opaque = replace(request, repository=root, include_untracked=False, denied_paths=("*",))
        _, _, nested_states = _working_files(opaque, nested, index)
        clean = (head == index_oids[path] and set(tree) == set(index)
                 and all(stage == "0" and tree[name] == (entry_mode, oid)
                         and _matches_index_stat(nested_states.get(name), stats.get(name))
                         for name, (entry_mode, oid, stage) in index.items()))
        result[path] = (clean, _content_id(json.dumps((head, index, stats, nested_states), sort_keys=True).encode()))
    return result


def capture(request: ReviewRequest, deadline: float | None = None) -> Snapshot:
    deadline = deadline or time.monotonic() + request.timeout_seconds
    reader = GitReader(request.repository, deadline)
    root = Path(os.fsdecode(reader.run("rev-parse", "--show-toplevel")).strip()).resolve()
    if root != request.repository:
        raise ValueError("Source directory must be the repository root")
    comparison_settings = {}
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
        commit_modes, commit_oids = {}, {}
        for entry in filter(None, reader.run("ls-tree", "-r", "-z", head).split(b"\0")):
            meta, raw_path = entry.split(b"\t", 1)
            mode, _, oid = meta.decode().split()
            commit_modes[raw_path.decode()] = mode
            commit_oids[raw_path.decode()] = oid
        index_raw = reader.run("ls-files", "--stage", "-z")
        index_files, index_modes, index_oids, total = {}, {}, {}, 0
        unavailable = dict(initial.unavailable_reasons) or dict.fromkeys(initial.unavailable, "unavailable")
        for entry in filter(None, index_raw.split(b"\0")):
            meta, raw_path = entry.split(b"\t", 1)
            mode, oid, stage = meta.decode().split()
            path = validate_path(raw_path.decode())
            if stage != "0":
                raise ValueError("Unmerged index cannot be reviewed")
            index_modes[path] = mode
            index_oids[path] = oid
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
            comparison_files = head_files
        else:
            index_stats = _index_stats(reader)
            head_files, working_reasons, working_states = _working_files(request, reader, index_files)
            comparison_files, comparison_settings = _working_eol(request, reader, head_files, index_files)
            gitlinks = _working_gitlinks(request, reader, index_modes, index_oids, working_states)
            repeated = _working_files(request, reader, index_files)
            if repeated != (head_files, working_reasons, working_states):
                raise ValueError("Working copy changed during capture; retry")
            if index_stats != _index_stats(reader):
                raise ValueError("Index changed during capture; retry")
            if gitlinks != _working_gitlinks(request, reader, index_modes, index_oids, working_states):
                raise ValueError("Submodule changed during capture; retry")
            unavailable.update(working_reasons)
        if index_raw != reader.run("ls-files", "--stage", "-z") or head != reader.run("rev-parse", "HEAD").decode().strip():
            raise ValueError("Index or HEAD changed during capture; retry")
        base = head
        base_modes = index_modes if request.mode == "unstaged" else commit_modes
        base_oids = index_oids if request.mode == "unstaged" else commit_oids
        head_modes = dict(index_modes)
        if request.mode != "staged":
            try:
                filemode = reader.run("config", "--bool", "core.filemode").strip() == b"true"
            except ValueError:
                filemode = False
            try:
                symlinks = reader.run("config", "--bool", "core.symlinks").strip() != b"false"
            except ValueError:
                symlinks = True
            head_modes = {}
            for path, state in working_states.items():
                mode = state[0] if state else 0
                if stat.S_ISREG(mode) and index_modes.get(path) == "120000" and not symlinks:
                    head_modes[path] = "120000"
                elif stat.S_ISREG(mode):
                    head_modes[path] = ("100755" if mode & 0o100 else "100644") if filemode else (
                        "100755" if index_modes.get(path) == "100755" else "100644")
                elif stat.S_ISLNK(mode):
                    head_modes[path] = "120000"
                else:
                    head_modes[path] = index_modes.get(path, "040000")

        def changed_path(path):
            if base_modes.get(path) != head_modes.get(path):
                return True
            if request.mode == "staged":
                return base_oids.get(path) != index_oids.get(path)
            if path in gitlinks:
                return (base_oids.get(path) != index_oids.get(path)
                        or gitlinks[path] is None or not gitlinks[path][0])
            if path in base_files and path in head_files:
                return base_files[path] != comparison_files[path]
            if path in working_states and path in unavailable:
                return (base_oids.get(path) != index_oids.get(path)
                        or not _matches_index_stat(working_states[path], index_stats.get(path)))
            return base_files.get(path) != head_files.get(path)

        changed = tuple(sorted(p for p in set(base_modes) | set(head_modes) if changed_path(p)))
        diff = "".join("".join(difflib.unified_diff(base_files.get(p, b"").decode("utf-8", "replace").splitlines(True),
                       comparison_files.get(p, b"").decode("utf-8", "replace").splitlines(True), fromfile="a/" + p, tofile="b/" + p))
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
        old_mode, new_mode = modes.get(path, {}).get("base"), modes.get(path, {}).get("head")
        changes.append({"path": path, "old_path": path if old_mode else None,
                        "new_path": path if new_mode else None,
                        "status": "added" if not old_mode else "deleted" if not new_mode else "modified",
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
                "comparison_settings": comparison_settings,
                "changes": changes, "denied_paths": request.denied_paths,
                "base_manifest": {p: _content_id(data) for p, data in base_files.items()},
                "head_manifest": {p: _content_id(data) for p, data in head_files.items()}, "unavailable": unavailable}
    return Snapshot(base, head, _content_id(json.dumps(identity, sort_keys=True).encode()), tuple(changed),
                    MappingProxyType(base_files), MappingProxyType(head_files), tuple(sorted(unavailable)), diff,
                    MappingProxyType(unavailable), tuple(changes), request.mode, datetime.now(timezone.utc).isoformat(),
                    MappingProxyType({"type": "local", "repository": str(request.repository)}))
