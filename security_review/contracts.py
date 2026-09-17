"""Wire-contract validation used on persisted and externally supplied reports."""
import json
import re


def validate_report(value):
    from dataclasses import fields
    from .models import ReviewReport
    if not isinstance(value, dict) or value.get("schema_version") != "1.0":
        raise ValueError("Unsupported report schema")
    if set(value) != {field.name for field in fields(ReviewReport)}:
        raise ValueError("Report fields do not match schema")
    if value["status"] not in {"queued", "running", "completed", "partial", "failed", "cancelled"}:
        raise ValueError("Invalid report state")
    if value["policy_outcome"] not in {"pass", "fail", "unknown"}:
        raise ValueError("Invalid policy outcome")
    coverage = value["coverage"]
    for key in ("eligible", "assessed", "incomplete"):
        if not isinstance(coverage.get(key), list) or any(not isinstance(path, str) for path in coverage[key]):
            raise ValueError("Invalid coverage inventory")
        if len(coverage[key]) != len(set(coverage[key])):
            raise ValueError("Duplicate coverage entries")
    if set(coverage["assessed"]) & set(coverage["incomplete"]) or set(coverage["eligible"]) != set(coverage["assessed"]) | set(coverage["incomplete"]):
        raise ValueError("Coverage does not reconcile")
    if value["status"] == "completed" and (value["errors"] or value["coverage"]["incomplete"] or value["policy_outcome"] == "unknown"):
        raise ValueError("Completed report contains unresolved work")
    if value["status"] != "completed" and value["policy_outcome"] == "pass":
        raise ValueError("Incomplete report cannot pass policy")
    for finding in value["findings"] + value["rejected_findings"] + value["suppressed_findings"]:
        if not isinstance(finding, dict) or finding.get("validation_status") not in {"confirmed", "rejected", "uncertain", "unvalidated"}:
            raise ValueError("Invalid finding validation state")
        if type(finding.get("line")) is not int or finding["line"] < 1 or finding.get("severity") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Invalid finding location/severity")
        from .repository import validate_path
        validate_path(finding.get("file"))
        if finding.get("side") not in {"base", "head"}:
            raise ValueError("Invalid finding side")
        end = finding.get("end_line", finding["line"])
        if type(end) is not int or end < finding["line"]:
            raise ValueError("Invalid finding range")
        for key in ("id", "fingerprint", "description", "category", "exploit_scenario", "recommendation"):
            if not isinstance(finding.get(key), str) or not finding[key]:
                raise ValueError(f"Invalid finding {key}")
        if not re.fullmatch(r"v[12]:[a-f0-9]{64}", finding["fingerprint"]):
            raise ValueError("Invalid or unsupported finding fingerprint")
        confidence = finding.get("confidence")
        if confidence is not None and (type(confidence) not in {int, float} or not 0 <= confidence <= 1):
            raise ValueError("Invalid finding confidence")
        if finding["validation_status"] == "unvalidated" and confidence is not None:
            raise ValueError("Unvalidated finding has confidence")
    json.dumps(value, allow_nan=False)
    return value
