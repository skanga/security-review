"""Only explicitly selected configuration is read. No repository auto-discovery."""
from dataclasses import asdict, fields
import json
import os
from pathlib import Path
import tomllib

from .models import ReviewRequest
from .policy import Policy, Suppression

DEFAULT_MODEL = "claude-opus-4-1-20250805"
ENVIRONMENT = {"SECURITY_REVIEW_MODEL": "model", "SECURITY_REVIEW_VALIDATION_MODEL": "validation_model",
               "SECURITY_REVIEW_TIMEOUT": "timeout_seconds"}


def effective_config(request):
    result = asdict(request)
    for name in ("repository", "cache_dir"):
        result[name] = str(result[name]) if result[name] is not None else None
    # Instruction contents may be sensitive. Hash contents but expose only their identity.
    from .policy import digest
    for name in ("instructions", "validation_instructions"):
        result[name] = {"sha256": digest(result[name]), "length": len(result[name])}
    return result


def resolve_config(path=None, overrides=None, *, environ=None):
    environ = os.environ if environ is None else environ
    values = {}
    root = Path.cwd()
    source = "packaged-defaults"
    if path:
        path = Path(path).resolve()
        source, root = str(path), path.parent
        raw = path.read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError("Configuration exceeds 1 MiB")
        values = tomllib.loads(raw.decode("utf-8")) if path.suffix == ".toml" else json.loads(raw)
        if not isinstance(values, dict):
            raise ValueError("Configuration must be an object")
    allowed = {field.name for field in fields(ReviewRequest)} | {"instructions_file", "validation_instructions_file"}
    if set(values) - allowed:
        raise ValueError("Unknown configuration keys: " + ", ".join(sorted(set(values) - allowed)))
    for name in ("repository", "cache_dir", "instructions_file", "validation_instructions_file"):
        if values.get(name):
            values[name] = str((root / values[name]).resolve())
    for variable, name in ENVIRONMENT.items():
        if variable in environ:
            values[name] = int(environ[variable]) if name == "timeout_seconds" else environ[variable]
    values.update({key: value for key, value in (overrides or {}).items() if value is not None})
    if set(values) - allowed:
        raise ValueError("Unknown configuration keys")
    for name in ("instructions", "validation_instructions"):
        filename = values.pop(name + "_file", None)
        if filename:
            if name in values:
                raise ValueError(f"Use either {name} or {name}_file")
            content = Path(filename).read_bytes()
            if len(content) > 64 * 1024:
                raise ValueError("Instructions exceed 64 KiB")
            values[name] = content.decode("utf-8")
    policy = values.get("policy", {})
    if isinstance(policy, dict):
        policy = dict(policy)
        policy.setdefault("source", source)
        policy["suppressions"] = tuple(Suppression(**rule) for rule in policy.get("suppressions", []))
        try:
            values["policy"] = Policy(**policy)
        except TypeError as exc:
            raise ValueError("Unknown policy setting") from exc
    values.setdefault("repository", Path.cwd())
    values.setdefault("model", DEFAULT_MODEL)
    values.setdefault("validation_model", values["model"])
    values.setdefault("config_source", source)
    return ReviewRequest(**values)
