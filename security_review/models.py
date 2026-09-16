"""Small draft contracts for the first M1 local-revision path."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from .policy import Policy


@dataclass(frozen=True)
class ReviewRequest:
    repository: Path
    base: str = "HEAD"
    head: str = "HEAD"
    comparison: str = "merge_base"
    model: str | None = None
    timeout_seconds: int = 1200
    blocking_severities: tuple[str, ...] = ("HIGH",)
    mode: str = "revisions"
    include_untracked: bool = False
    policy: Policy = field(default_factory=Policy)
    backend: str = "claude-code"
    validator: str = "claude-api"
    validation_model: str | None = None
    cloud_allowed: bool = True
    denied_paths: tuple[str, ...] = ()
    instructions: str = ""
    validation_instructions: str = ""
    instructions_mode: str = "extend"
    config_source: str = "api"
    schema_version: str = "1.0"
    cache_dir: Path | None = None
    no_cache: bool = False
    pr: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "repository", Path(self.repository).resolve())
        if self.cache_dir:
            object.__setattr__(self, "cache_dir", Path(self.cache_dir).resolve())
        if self.mode not in {"revisions", "staged", "unstaged", "working_tree"}:
            raise ValueError("Invalid source mode")
        if self.instructions_mode not in {"replace", "extend"}:
            raise ValueError("instructions_mode must be replace or extend")
        if self.schema_version != "1.0" or not isinstance(self.policy, Policy):
            raise ValueError("Unsupported request schema or policy")
        for name in ("include_untracked", "cloud_allowed", "no_cache"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be boolean")
        if self.include_untracked and self.mode not in {"working_tree", "unstaged"}:
            raise ValueError("Untracked files require a working-copy mode")
        for name in ("blocking_severities", "denied_paths"):
            if not isinstance(getattr(self, name), (tuple, list)) or any(not isinstance(v, str) or not v for v in getattr(self, name)):
                raise ValueError(f"{name} must be an array of nonempty strings")
            object.__setattr__(self, name, tuple(getattr(self, name)))
        for name in ("model", "validation_model"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be a nonempty model ID")
        for name in ("backend", "validator", "instructions", "validation_instructions", "config_source"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"{name} must be text")
        if len(self.instructions.encode()) > 65536 or len(self.validation_instructions.encode()) > 65536:
            raise ValueError("Instructions exceed 64 KiB")
        if self.pr:
            from .github import parse_pr
            parse_pr(self.pr)
            if self.mode != "revisions":
                raise ValueError("PR reviews cannot use a working-copy mode")
        if self.comparison not in {"merge_base", "direct"}:
            raise ValueError("comparison must be merge_base or direct")
        if type(self.timeout_seconds) is not int or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive integer")
        for ref in (self.base, self.head):
            if not isinstance(ref, str) or not ref or ref.startswith("-") or "\0" in ref:
                raise ValueError("base/head must be explicit Git references, not options")
        if any(value not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
               for value in self.blocking_severities):
            raise ValueError("Invalid blocking severity")


@dataclass(frozen=True)
class InvestigationResult:
    findings: list[dict[str, Any]]
    assessed_files: list[str]
    usage: dict | None = None
    backend_version: str = "unknown"


@dataclass(frozen=True)
class ValidationResult:
    status: str
    confidence: float | None
    justification: str

    def __post_init__(self):
        if not isinstance(self.justification, str):
            raise ValueError("Validation justification must be text")
        if self.status not in {"confirmed", "rejected", "uncertain", "unvalidated"}:
            raise ValueError("Invalid validation status")
        if self.confidence is not None and (
            type(self.confidence) not in {int, float} or not 0 <= self.confidence <= 1
        ):
            raise ValueError("confidence must be finite and between zero and one")
        if self.status == "unvalidated" and self.confidence is not None:
            raise ValueError("Unvalidated findings cannot have confidence")


@dataclass
class ReviewReport:
    run_id: str
    status: str = "failed"
    policy_outcome: str = "unknown"
    snapshot: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    rejected_findings: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, list[str]] = field(default_factory=lambda: {
        "eligible": [], "assessed": [], "incomplete": []})
    errors: list[dict[str, str]] = field(default_factory=list)
    runtime_seconds: float = 0
    schema_version: str = "1.0"
    backend: str = ""
    model: str | None = None
    policy: dict[str, Any] = field(default_factory=dict)
    candidates: list[dict] = field(default_factory=list)
    duplicates: list[dict] = field(default_factory=list)
    suppressed_findings: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    stage: str = "queued"
    started_at: str = ""
    finished_at: str = ""
    attempt_of: str | None = None
    effective_config: dict = field(default_factory=dict)
    config_hash: str = ""
    versions: dict = field(default_factory=lambda: {"engine": "0.1.0"})
    usage: dict | None = None
    cache: dict = field(default_factory=lambda: {"hit": False, "source_run_id": None})
    artifacts: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value):
        from .contracts import validate_report
        validate_report(value)
        return cls(**value)

    @property
    def exit_code(self):
        if self.status == "cancelled":
            return 3
        if self.status != "completed":
            return 2
        return 1 if self.policy_outcome == "fail" else 0

    def to_dict(self):
        return asdict(self)
