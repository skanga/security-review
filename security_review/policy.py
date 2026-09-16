"""Versioned structured policy; text in a finding never acts as an exclusion rule."""
from dataclasses import asdict, dataclass
from datetime import date
from fnmatch import fnmatchcase
import hashlib
import json

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
LEGACY_CATEGORIES = ("denial_of_service", "rate_limiting", "resource_leak", "open_redirect", "regex_injection")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class Suppression:
    id: str
    fingerprint: str
    reason: str
    source: str = "explicit"
    owner: str = ""
    expires: str | None = None

    def __post_init__(self):
        if not all(isinstance(v, str) and v for v in (self.id, self.fingerprint, self.reason, self.source)):
            raise ValueError("Suppression requires id, fingerprint, reason and source")
        if self.expires:
            date.fromisoformat(self.expires)


@dataclass(frozen=True)
class Policy:
    profile: str = "generic"
    version: str = "1"
    minimum_severity: str = "MEDIUM"
    minimum_confidence: float = 0.8
    validation_required: bool = True
    exclude_paths: tuple[str, ...] = ()
    exclude_categories: tuple[str, ...] = ()
    suppressions: tuple[Suppression, ...] = ()
    source: str = "packaged-defaults"

    def __post_init__(self):
        if self.profile not in {"generic", "legacy"} or self.version != "1":
            raise ValueError("Unsupported policy profile/version")
        if self.minimum_severity not in SEVERITIES:
            raise ValueError("Invalid minimum severity")
        if type(self.minimum_confidence) not in {int, float} or not 0 <= self.minimum_confidence <= 1:
            raise ValueError("Invalid confidence threshold")
        if type(self.validation_required) is not bool:
            raise ValueError("validation_required must be boolean")
        for name in ("exclude_paths", "exclude_categories"):
            if not isinstance(getattr(self, name), (tuple, list)):
                raise ValueError(f"{name} must be an array")
            values = tuple(getattr(self, name))
            if any(not isinstance(v, str) or not v for v in values):
                raise ValueError(f"{name} must contain nonempty strings")
            object.__setattr__(self, name, values)
        if not isinstance(self.suppressions, (tuple, list)):
            raise ValueError("suppressions must be an array")
        object.__setattr__(self, "suppressions", tuple(self.suppressions))
        if any(not isinstance(v, Suppression) for v in self.suppressions):
            raise ValueError("Invalid suppression")

    def describe(self, blocking):
        result = asdict(self)
        result["blocking_severities"] = list(blocking)
        return {**result, "hash": digest(result)}

    def excluded(self, path):
        return next((pattern for pattern in self.exclude_paths if fnmatchcase(path, pattern)), None)

    def evaluate(self, finding):
        categories = self.exclude_categories + (LEGACY_CATEGORIES if self.profile == "legacy" else ())
        reason = None
        if finding.get("category") in categories:
            reason = {"rule": "category:" + finding["category"], "reason": "Category outside configured scope",
                      "source": self.source}
        for rule in self.suppressions:
            if rule.fingerprint == finding["fingerprint"] and (
                rule.expires is None or date.fromisoformat(rule.expires) >= date.today()
            ):
                reason = {"rule": rule.id, "reason": rule.reason, "source": rule.source,
                          "owner": rule.owner, "expires": rule.expires}
        finding["policy_decision"] = "suppressed" if reason else "retained"
        finding["policy_reason"] = reason
        finding["reportable"] = bool(not reason and finding["validation_status"] == "confirmed"
                                    and finding["confidence"] is not None
                                    and finding["confidence"] >= self.minimum_confidence
                                    and SEVERITIES.index(finding["severity"]) >= SEVERITIES.index(self.minimum_severity))
        return finding
