# Corrected compatibility baseline (M0)

Baseline: commit `0c6a49f1fa56a1d472575da86a94dbc1edb78eda`. The original assessment remains historical; this record identifies intentional behavior corrections and retained differences.

## Corrections implemented

| Area | Original problem | Corrected behavior / regression coverage |
|---|---|---|
| CLI output | Extraction fallback could become a successful empty review | Require a findings list of objects and explicit `review_completed: true`; reject error envelopes |
| Evaluator | Exit 1/error JSON could count as successful review | Require the same completed-report shape before scoring |
| Evidence reads | Generated paths could escape the repository | Reject absolute/traversal/ambiguous paths, symlink/junction paths, and oversized reads |
| Memory findings | File extensions suppressed native/FFI issues; Rust prompt declared memory vulnerabilities impossible | Remove extension suppression; require concrete unsafe/native evidence |
| Validation | Missing/failed validation could gain confidence 10 | Preserve as unvalidated with no confidence; reject malformed validation scores |
| Runtime config | Timeout/model configuration could diverge from execution/probing | Wire timeout and selected model through the runner and access check; disable nested SDK retries |
| Tests | Home-directory writes and deleted current directories broke Windows tests | Use fixture workspaces and restore cwd before cleanup; use synthetic GitHub credentials |

`claudecode/test_reliability_regressions.py` freezes synthetic failure/negative fixtures. Existing wrapped-success fixtures in runner/workflow tests now explicitly declare completion. These tests freeze transport and policy behavior, not model quality.

## Existing entry-point differences

The historical GitHub Action executed the Python investigator/filter followed by the JavaScript publisher. The migrated Action now invokes the common engine and Python publisher. Frozen compatibility fixtures live in `tests/fixtures/compatibility-v1.json`; named policy profiles are packaged under `security_review/profiles`.

The corrected legacy profile explicitly names DoS/resource/rate-limiting, redirect and regex categories. These are historical scope choices, not statements that the categories cannot contain vulnerabilities. The generic profile has no category exclusions. Filename/language impossibility assumptions are removed. The deprecated legacy Python filter retains wording heuristics only for uncategorized historical records; structured categories take precedence so mixed-impact findings are not suppressed by incidental wording. The new engine never uses that text-matching layer.

The slash command is a prompt-driven interactive review with its own instructions and human-readable output. It does not execute the Action's Python filter or supply the new engine's coverage/status contract. Correcting its Rust instruction does not establish parity between entry points.

The standalone engine uses structured candidate validation and an injected evidence validator. It separates completion from HIGH-only finding policy and operational exit codes. API/CLI/Action parity tests verify these outcomes with the same fixtures. Historical direct-script entry points remain for compatibility reference and are not invoked by the migrated Action.

## Remaining live validation

- Validate live completed negatives, positives, failures, and reviewed evidence against a pinned corpus before making a detection-quality parity claim.
- Conformance-test supported Claude Code releases and all declared OS/Python combinations.

Path containment here is a trusted-workspace correction. It is not protection against a hostile same-user process racing filesystem changes.
