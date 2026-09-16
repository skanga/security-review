"""Shared review lifecycle: immutable inputs, candidate validation, policy and storage."""
from dataclasses import replace
from datetime import datetime, timezone
import math
import time
from typing import Protocol
import uuid

from .config import effective_config, DEFAULT_MODEL
from .models import InvestigationResult, ReviewReport, ReviewRequest, ValidationResult
from .policy import digest
from .repository import Snapshot, capture, validate_path
from .runtime import CancellationToken, Cancelled, Execution, execution, checkpoint


class InvestigationBackend(Protocol):
    def investigate(self, snapshot: Snapshot, request: ReviewRequest) -> InvestigationResult: ...


class FindingValidator(Protocol):
    def validate(self, finding: dict, snapshot: Snapshot, request: ReviewRequest) -> ValidationResult: ...


def _candidate(value, snapshot, index=0):
    if not isinstance(value, dict):
        raise ValueError("Finding must be an object")
    path = validate_path(value.get("file"))
    line, end = value.get("line"), value.get("end_line", value.get("line"))
    if type(line) is not int or type(end) is not int or line < 1 or end < line:
        raise ValueError("Finding lines must be a positive integer range")
    side = value.get("side", "head")
    content = snapshot.read(path, side)
    if end > len(content.splitlines()) or path not in snapshot.changed_files:
        raise ValueError("Finding must refer to a selected change and an existing snapshot location")
    severity = value.get("severity")
    if not isinstance(severity, str) or severity.upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        raise ValueError("Finding severity is invalid")
    for name in ("category", "exploit_scenario", "recommendation"):
        if not isinstance(value.get(name), str) or not value[name].strip():
            raise ValueError(f"Finding {name} is required")
    description = value.get("description")
    if not isinstance(description, str) or not description.strip() or len(description) > 16384:
        raise ValueError("Finding description is required and bounded")
    confidence = value.get("confidence")
    if confidence is not None and (type(confidence) not in {int, float} or not math.isfinite(confidence) or not 0 <= confidence <= 1):
        raise ValueError("Finding confidence is invalid")
    finding = {name: value.get(name, default) for name, default in {
        "title": description.splitlines()[0][:160], "description": description,
        "category": "unspecified", "exploit_scenario": "Not supplied by compatibility backend",
        "preconditions": "Not supplied by compatibility backend", "recommendation": "Review the referenced code",
        "introduced_by": "Candidate attributed to the selected change; validator must verify the relationship",
    }.items()}
    if any(not isinstance(text, str) or not text.strip() or len(text) > 16384 for text in finding.values()):
        raise ValueError("Finding text fields must be nonempty bounded strings")
    revision = snapshot.base if side == "base" else snapshot.head
    if snapshot.mode != "revisions" and (side == "head" or snapshot.mode == "unstaged"):
        revision = f"snapshot:{snapshot.snapshot_id}:{side}"
    data = (snapshot.base_files if side == "base" else snapshot.head_files)[path]
    evidence_hash = digest(" ".join(content.splitlines()[line - 1:end]))
    fingerprint = "v1:" + digest({"path": path, "category": finding["category"], "evidence": evidence_hash})
    finding.update(id=f"finding-{index + 1}", fingerprint=fingerprint, file=path, line=line, end_line=end,
                   severity=severity.upper(), side=side, discovery_confidence=confidence, confidence=None,
                   validation_status="unvalidated", validation_reason="Validation not yet performed",
                   locations=[{"path": path, "side": side, "revision": revision, "start_line": line,
                               "end_line": end, "content_id": __import__("hashlib").sha256(data).hexdigest()}],
                   evidence=[{"snapshot_id": snapshot.snapshot_id, "path": path, "side": side,
                              "start_line": line, "end_line": end}], provenance={})
    return finding


def review(request: ReviewRequest, backend: InvestigationBackend | None = None,
           validator: FindingValidator | None = None, *, source=None, cancellation=None,
           on_event=None, clock=time.monotonic, registry=None) -> ReviewReport:
    started = clock()
    request = replace(request, model=request.model or DEFAULT_MODEL,
                      validation_model=request.validation_model or request.model or DEFAULT_MODEL)
    if backend is None:
        from .registry import Registry
        registry = registry or Registry()
        backend = registry.create("backend", request.backend)
        validator = registry.create("validator", request.validator) if request.policy.validation_required else None
    context = Execution(started + request.timeout_seconds, cancellation or CancellationToken(), clock)
    context_handle = execution.set(context)
    report = ReviewReport(str(uuid.uuid4()), status="queued", backend=type(backend).__name__, model=request.model,
                          policy=request.policy.describe(request.blocking_severities),
                          started_at=datetime.now(timezone.utc).isoformat(), effective_config=effective_config(request))
    report.config_hash = digest(report.effective_config)
    report.coverage.update(excluded=[], reasons={})
    store, lease, cache_key = None, None, ""

    def emit(stage, state="running"):
        report.stage = stage
        event = {"stage": stage, "state": state, "elapsed_seconds": round(clock() - started, 3)}
        report.events.append(event)
        if on_event:
            on_event(dict(event))
        if store:
            store.save(report, cache_key, lease)

    def remaining_request():
        checkpoint()
        return replace(request, timeout_seconds=max(1, math.ceil(context.deadline - clock())))

    def error(stage, exc):
        code = "TIMEOUT" if isinstance(exc, TimeoutError) else "PERMISSION" if isinstance(exc, PermissionError) else "INVALID_OUTPUT" if stage in {"investigation", "validation", "finding_structure"} else "SOURCE_RESOLUTION" if stage == "source" else "CONFIGURATION"
        report.errors.append({"stage": stage, "code": getattr(exc, "code", code), "retryable": getattr(exc, "retryable", isinstance(exc, TimeoutError)),
                              "message": f"{stage} failed ({type(exc).__name__}); check input, capability, and budget"})

    try:
        if request.cache_dir:
            from .store import RunStore
            store = RunStore(request.cache_dir)
        emit("queued", "queued")
        checkpoint()
        report.status = "running"
        emit("source")
        if request.pr and source is None:
            from .github import GitHubClient, GitHubSource
            import os
            client = GitHubClient(os.environ.get("GITHUB_SOURCE_TOKEN") or os.environ.get("GITHUB_TOKEN"), timeout=request.timeout_seconds)
            source = GitHubSource(client).resolve
        snapshot = (source or capture)(request, context.deadline)
        report.snapshot = {"id": snapshot.snapshot_id, "base": snapshot.base, "head": snapshot.head,
                           "repository": str(request.repository), "comparison": request.comparison,
                           "mode": snapshot.mode, "captured_at": snapshot.captured_at,
                           "changes": list(snapshot.changes), "source": dict(snapshot.source)}
        excluded = [{"file": path, "reason": "Scope excluded", "rule": request.policy.excluded(path),
                     "source": request.policy.source} for path in snapshot.changed_files if request.policy.excluded(path)]
        eligible = tuple(path for path in snapshot.changed_files if not request.policy.excluded(path))
        snapshot = replace(snapshot, changed_files=eligible)
        report.coverage.update(eligible=list(eligible), incomplete=list(eligible), excluded=excluded,
                               reasons={path: reason for path, reason in snapshot.unavailable_reasons.items() if path in eligible})
        emit("preflight")
        if eligible:
            for adapter in (backend, validator):
                if adapter is not None and hasattr(adapter, "preflight"):
                    capabilities = adapter.preflight(remaining_request())
                    report.versions[type(adapter).__name__] = capabilities
        cache_config = {key: value for key, value in report.effective_config.items() if key not in {"no_cache", "cache_dir"}}
        cache_key = digest({"snapshot": snapshot.snapshot_id, "request": cache_config,
                            "versions": report.versions, "backend": type(backend).__module__ + "." + type(backend).__qualname__,
                            "validator": type(validator).__module__ + "." + type(validator).__qualname__})
        if store:
            lease = store.acquire(cache_key, report.run_id, time.time() + request.timeout_seconds + 30)
            cached = None if request.no_cache else store.cached(cache_key)
            if cached:
                cached_id = cached.run_id
                cached.run_id, cached.started_at = report.run_id, report.started_at
                cached.attempt_of = cached_id
                cached.cache = {"hit": True, "source_run_id": cached_id,
                                "original_finished_at": cached.finished_at, "key": cache_key}
                cached.events = report.events
                report = cached
                emit("cache_reuse", "completed")
                return report
        emit("investigation")
        result = backend.investigate(snapshot, remaining_request()) if eligible else InvestigationResult([], [])
        if (not isinstance(result, InvestigationResult) or not isinstance(result.findings, list)
                or not isinstance(result.assessed_files, list) or any(not isinstance(p, str) for p in result.assessed_files)):
            raise ValueError("Invalid investigation result")
        if len(result.findings) > 1000:
            raise ValueError("Candidate output exceeds structural limit")
        if result.usage is not None:
            keys = {"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"}
            if not isinstance(result.usage, dict) or any(type(value) is not int or value < 0 for key, value in result.usage.items() if key in keys):
                raise ValueError("Invalid backend usage accounting")
            report.usage = {"investigation": {key: value for key, value in result.usage.items() if key in keys}, "validation": None}
        assessed = set(result.assessed_files)
        if not assessed <= set(eligible):
            raise ValueError("Backend claimed assessment outside assigned scope")
        assessed -= set(snapshot.unavailable)
        report.coverage.update(assessed=sorted(assessed), incomplete=sorted(set(eligible) - assessed))
        for path in report.coverage["incomplete"]:
            report.coverage["reasons"].setdefault(path, "No completed investigation result")
        seen = set()
        # Normalize all candidates before validation so cancellation retains remaining work.
        for index, value in enumerate(result.findings):
            try:
                finding = _candidate(value, snapshot, index)
                finding["provenance"] = {"investigation": report.backend, "model": request.model,
                                         "validator": type(validator).__name__, "validation_model": request.validation_model}
                if finding["fingerprint"] in seen:
                    report.duplicates.append({"id": finding["id"], "fingerprint": finding["fingerprint"]})
                    continue
                seen.add(finding["fingerprint"])
                report.findings.append(finding)
            except Exception as exc:
                error("finding_structure", exc)
        emit("validation")
        for finding in list(report.findings):
            checkpoint()
            try:
                if not request.policy.validation_required:
                    finding["validation_reason"] = "Validation explicitly disabled"
                    continue
                if validator is None:
                    raise ValueError("Required validator missing")
                validated = validator.validate(dict(finding), snapshot, remaining_request())
                if not isinstance(validated, ValidationResult) or validated.status == "unvalidated":
                    raise ValueError("Required validation did not complete")
                finding.update(validation_status=validated.status, confidence=validated.confidence,
                               validation_reason=validated.justification)
                if validated.status == "confirmed" and (validated.confidence is None or validated.confidence < request.policy.minimum_confidence):
                    finding["validation_status"] = "uncertain"
                if finding["validation_status"] == "rejected":
                    report.findings.remove(finding)
                    report.rejected_findings.append(finding)
            except (Cancelled, KeyboardInterrupt):
                raise
            except Exception as exc:
                finding.update(validation_status="unvalidated", confidence=None, validation_reason="Validation failed")
                error("validation", exc)
        checkpoint()
        report.status = "partial" if report.errors or report.coverage["incomplete"] else "completed"
        if report.status == "partial" and not assessed and not report.findings:
            report.status = "failed"
    except (Cancelled, KeyboardInterrupt):
        report.status = "cancelled"
    except Exception as exc:
        error(report.stage, exc)
        report.status = "partial" if report.findings or report.coverage["assessed"] else "failed"
    finally:
        for finding in list(report.findings):
            request.policy.evaluate(finding)
            if finding["policy_decision"] == "suppressed":
                report.findings.remove(finding)
                report.suppressed_findings.append(finding)
        report.candidates = report.findings + report.rejected_findings + report.suppressed_findings
        blocks = any(f["severity"] in request.blocking_severities and f["validation_status"] == "confirmed"
                     and f["confidence"] >= request.policy.minimum_confidence for f in report.findings)
        report.policy_outcome = "fail" if blocks else "pass" if report.status == "completed" else "unknown"
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.runtime_seconds = round(clock() - started, 3)
        report.coverage["counts"] = {key: len(report.coverage.get(key, [])) for key in ("eligible", "assessed", "incomplete", "excluded")}
        try:
            emit("finalize", report.status)
        except Exception as exc:
            error("artifact", exc)
            report.status = "partial" if report.findings else "failed"
            if report.policy_outcome == "pass":
                report.policy_outcome = "unknown"
        finally:
            if store and lease:
                store.release(cache_key, lease)
            execution.reset(context_handle)
    return report
