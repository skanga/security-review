"""Published JSON Schemas for wire version 1.0 (no optional SDK imports)."""
from dataclasses import fields
import json
from pathlib import Path

from .models import ReviewReport, ReviewRequest


def schemas():
    text = {"type": "string"}
    objects = {"type": "array", "items": {"type": "object"}}
    finding = {"type": "object", "required": ["id", "fingerprint", "file", "line", "severity", "description",
                "locations", "evidence", "introduced_by", "provenance", "validation_status", "confidence"],
               "properties": {"id": text, "fingerprint": {"type": "string", "pattern": "^v1:[a-f0-9]{64}$"},
                "file": text, "line": {"type": "integer", "minimum": 1}, "end_line": {"type": "integer", "minimum": 1},
                "severity": {"enum": ["HIGH", "MEDIUM", "LOW", "CRITICAL"]}, "description": {"type": "string", "minLength": 1},
                "validation_status": {"enum": ["confirmed", "rejected", "uncertain", "unvalidated"]},
                "confidence": {"type": ["number", "null"], "minimum": 0, "maximum": 1},
                "locations": objects, "evidence": objects, "provenance": {"type": "object"}, "introduced_by": text}}
    report = {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "ReviewReport 1.0", "type": "object",
              "additionalProperties": False, "required": [f.name for f in fields(ReviewReport)],
              "properties": {f.name: {} for f in fields(ReviewReport)}, "$defs": {"finding": finding}}
    report["properties"].update({"schema_version": {"const": "1.0"}, "run_id": {"type": "string", "minLength": 1},
        "status": {"enum": ["queued", "running", "completed", "partial", "failed", "cancelled"]},
        "policy_outcome": {"enum": ["pass", "fail", "unknown"]}, "events": objects,
        "runtime_seconds": {"type": "number", "minimum": 0},
        "errors": {"type": "array", "items": {"type": "object", "required": ["stage", "code", "message", "retryable"]}},
        "coverage": {"type": "object", "required": ["eligible", "assessed", "incomplete"],
                     "properties": {k: {"type": "array", "items": text} for k in ("eligible", "assessed", "incomplete")}}})
    for key in ("findings", "rejected_findings", "suppressed_findings", "candidates"):
        report["properties"][key] = {"type": "array", "items": {"$ref": "#/$defs/finding"}}
    for key in ("snapshot", "policy", "cache", "effective_config", "versions"):
        report["properties"][key] = {"type": "object"}
    report["allOf"] = [{"if": {"properties": {"status": {"const": "completed"}}},
        "then": {"properties": {"errors": {"maxItems": 0}, "coverage": {"properties": {"incomplete": {"maxItems": 0}}},
                                  "policy_outcome": {"enum": ["pass", "fail"]}}}}]
    request = {"$schema": report["$schema"], "title": "ReviewRequest 1.0", "type": "object", "additionalProperties": False,
               "required": ["repository"], "properties": {f.name: {} for f in fields(ReviewRequest)}}
    request["properties"].update({"schema_version": {"const": "1.0"}, "repository": text, "base": text, "head": text,
        "mode": {"enum": ["revisions", "staged", "unstaged", "working_tree"]}, "comparison": {"enum": ["merge_base", "direct"]},
        "timeout_seconds": {"type": "integer", "minimum": 1}, "policy": {"type": "object"},
        "cloud_allowed": {"type": "boolean"}, "include_untracked": {"type": "boolean"}, "no_cache": {"type": "boolean"},
        "denied_paths": {"type": "array", "items": text}, "blocking_severities": {"type": "array", "items": {"enum": ["HIGH", "MEDIUM", "LOW", "CRITICAL"]}}})
    publication = {"$schema": report["$schema"], "title": "PublicationResult 1.0", "type": "object",
                   "required": ["target", "run_id", "snapshot_id", "status", "created", "updated", "skipped", "errors"],
                   "properties": {"status": {"enum": ["published", "stale", "failed"]}}}
    return {"request-1.0.json": request, "report-1.0.json": report, "publication-1.0.json": publication}


if __name__ == "__main__":
    destination = Path(__file__).with_name("schemas")
    destination.mkdir(exist_ok=True)
    for name, value in schemas().items():
        (destination / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
