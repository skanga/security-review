# M0/M1 implementation and release status

## Agreed decisions

- Native providers (M2): configurable OpenAI API-compatible endpoints/models and Claude.
- Reviewed source may be sent to configured cloud providers.
- Default finding-based CI failure: confirmed HIGH findings only; operational failures remain distinct.

## Implementation delivered

M0 reliability corrections and the M1 engine/integration implementation are present. The release gate is **not certified** until the external checks below pass. This distinction does not waive the original requirements.

| Area | Implementation / acceptance evidence |
|---|---|
| M0 result integrity | Complete-report checks; malformed/error/incomplete results rejected; corrected evaluator classification; frozen compatibility fixtures |
| M0 evidence/policy | Confined reads; no Rust/memory/HTML impossibility assumptions; structured category precedence; explicit generic/legacy profiles; no invented validation confidence |
| M0 test/resource isolation | Temporary workspaces, restored cwd, synthetic credentials; evaluator removes only recorded owned worktrees; raw parse/API error content omitted |
| M1 contracts/config | Versioned request/report/publication schemas, strict selected JSON/TOML configuration, independent models/adapters, hashes/provenance, explicit registry |
| M1 sources | Immutable commit/index/worktree/combined snapshots; untracked opt-in; capture-race detection; mode changes, deletion/base evidence, rename metadata, bounded reader, denied content rules |
| M1 lifecycle | Canonical status/policy separation, coverage reconciliation/reasons/counts, deterministic policy/suppressions, candidate retention/dedup, structured events, cancellation/deadlines |
| M1 runtime | Bounded owned subprocesses; Windows Job Objects and POSIX groups; Claude version/key/cloud preflight; independently supervised API validation with base/head/change evidence |
| M1 persistence | SQLite reports/leases, complete-only validated cache reuse, full context identity, source-run provenance, ownership checks, scoped retention cleanup |
| M1 interfaces | CLI scan/config/backends/publish/cache/runs commands; synchronous/asynchronous public APIs; JSON/Markdown; atomic artifacts and output recovery |
| M1 GitHub | Paginated immutable PR source, direct/merge-base comparisons, stale-head protection, author/revision deduplication, inline/summary publishing and independent retries |
| M1 Action | Shared engine invocation isolated from source imports; per-revision reviews; blocking/advisory modes; canonical outputs; aliases and trusted instruction paths |
| M1 packaging | No core runtime dependencies; pinned optional SDK versions; Python 3.11–3.14 matrix definition; offline clean-environment wheel installation |

See [usage/migration/troubleshooting](local-review.md), [corrected baseline](legacy-policy-baseline.md), and [completion plan](m0-m1-completion-plan.md). Tests are grouped by those acceptance areas under `tests/test_m0_completion.py`, `tests/test_m1_*.py`, and the original `claudecode` suite.

## Verification record

Local environment: Windows, Python 3.13.7, pytest 9.1.1, Bun 1.3.14.

- `python -m pytest -q --tb=short --basetemp=.cache/m0-m1-verified-final`: **285 passed** in 146.97 seconds.
- `bun test` in `scripts/`: **11 passed**, 0 failed.
- Focused real-process checks: output limits, deadlines, cancellation, and termination of a child after its parent exits pass on Windows.
- Recorded API/CLI/Action fixtures agree on completed negatives, HIGH blocking, and MEDIUM advisory behavior.
- Wheel builds with `python -m pip wheel . --no-deps --no-build-isolation --no-index --wheel-dir .cache/dist`.
- `python scripts/smoke_package.py .cache/dist/security_review_engine-0.1.0-py3-none-any.whl` installs into a fresh environment offline, verifies optional SDK absence, loads packaged schemas, and defeats package shadowing from the invocation directory.
- Runtime 2.1.248 exists in the official npm registry. No unqualified latest runtime is installed by the Action.
- Published JSON Schemas passed Draft 2020-12 schema validation; generated Action reports were checked against the report schema. `git diff --check` passed.
- A fresh reviewer identified Action import shadowing, Git pathspec leakage, missing mode-only scope, incomplete cache identity, installation-token publication identity, artifact links, PR comparison mismatch, and context cleanup issues. Regression cases cover their corrections.

## External acceptance still required

### First GitHub matrix attempt

The candidate was committed and pushed to the private repository [skanga/security-review](https://github.com/skanga/security-review). Candidate commit: `a08cc3589aabd9000caac19715b45e84e2c9bd42`.

[Workflow run 35063597036](https://github.com/skanga/security-review/actions/runs/35063597036) was triggered by the push. All 13 jobs failed before test steps started. GitHub's job annotation reports that recent account payments failed or the spending limit needs to be increased. No remote tests or wheel installation checks executed, so this attempt provides no platform acceptance evidence.

After resolving the account's Actions billing/spending restriction, retry the same candidate:

```text
gh run rerun 35063597036 --repo skanga/security-review
gh run watch 35063597036 --repo skanga/security-review --exit-status
```

### Remaining gates

1. Run the committed Windows/Linux/macOS × Python 3.11–3.14 matrix. Only Windows/Python 3.13 has run here. WSL enumeration outside the sandbox found no installed distribution; no macOS runner is available in this session.
2. Run the pinned Claude runtime conformance cases with deliberately configured authentication and synthetic source, including managed policy and repository instruction isolation. Offline process tests cannot establish runtime isolation or model quality.
3. Run a GitHub test PR with installation-token permissions to verify the real API source/publication lifecycle. Transport fixtures exercise those contracts locally; no external comment was sent.

The candidate and release-check record have been committed and pushed at the user's request. No deployments, paid model reviews or PR comment publication were performed. New native providers and quality comparisons are M2; MCP/framework integration and SARIF are M3.
