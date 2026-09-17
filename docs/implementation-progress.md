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

## External acceptance record

### First GitHub matrix attempt

The candidate was initially committed and pushed to the private repository [skanga/security-review](https://github.com/skanga/security-review). Candidate commit: `a08cc3589aabd9000caac19715b45e84e2c9bd42`. The repository is now public at the user's request.

[Workflow run 35063597036, attempt 1](https://github.com/skanga/security-review/actions/runs/35063597036/attempts/1) was triggered by the push. All 13 jobs failed before test steps started because of an account billing/spending restriction. Making the repository public allowed the jobs to start on the next attempt.

### Platform gate passed

[Workflow run 35064408314](https://github.com/skanga/security-review/actions/runs/35064408314) **passed all 13 jobs** for commit `3b8a212a57be4c3a030d8fdc1b4037f5e7d2ddda`:

- Windows, Linux and macOS, each on Python 3.11, 3.12, 3.13 and 3.14.
- The full offline Python suite, wheel build and isolated wheel installation in every Python job.
- The legacy publisher's 11 Bun tests.

The Python suite now contains 289 tests. Representative Python 3.11 logs report 289 passed on each OS, with no skips: Linux 30.14 seconds, Windows 72.17 seconds, macOS 107.34 seconds.

Real runner failures led to corrections before this passing run: create the test cache parent on fresh checkouts; remove a legacy offline test's dependence on an installed Claude CLI; reject a subdirectory that would silently select its parent repository; and report output-limit violations consistently across process completion timings. Four new source-boundary regressions cover all local modes. The earlier fixtures and policy assertions remain enabled.

### Remaining gates

1. Run the pinned Claude runtime conformance cases with deliberately configured authentication and synthetic source, including managed policy and repository instruction isolation. Offline process tests cannot establish runtime isolation or model quality.
2. Run a GitHub test PR with installation-token permissions to verify the real API source/publication lifecycle. Transport fixtures exercise those contracts locally; no external comment was sent.

The candidate and release-check record have been committed and pushed at the user's request. No deployments, paid model reviews or PR comment publication were performed. New native providers and quality comparisons are M2; MCP/framework integration and SARIF are M3.

## Code review remediation

The approved review of `d6e9961` identified seven defects. Their fixes and 71 additional regression cases are implemented locally. The [remediation plan and mapping](code-review-remediation-plan.md#implementation-record) links each defect to its implementation and coverage.

- Distinct call sites now have separate `v2:` fingerprints. Old cache identities are invalidated; historical reports remain readable. Existing `v1:` suppressions require the [documented migration](local-review.md#trusted-configuration).
- Cache hits reevaluate retained and suppressed findings against one captured policy date, preserving validation and rejected candidates.
- Working-copy selection distinguishes unavailable content from actual changes, uses metadata for opaque paths, and applies guarded Git EOL rules while retaining raw evidence.
- Action artifact failures return exit 2 in both CI modes and preserve valid scan/publication results. Unset Action inputs preserve configured timeouts and independent models. Explicitly injected validators are retained.
- Independent review added regressions for initialized/dirty submodules, regular-file symlink checkouts, and denied attribute sources, including equivalent parent-traversal paths.

Local verification for these repairs (Windows, Python 3.13.7):

- `python -m pytest -q --basetemp=.cache/remediation-final --tb=short`: **360 passed** in 425.53 seconds, with no skips.
- `bun test` in `scripts/`: **11 passed**.
- Generated schemas pass Draft 2020-12 schema validation; schema parity and report round trips are covered by the Python suite.
- `python -m pip wheel . --no-deps --no-build-isolation --no-index --wheel-dir .cache/remediation-dist`: passed.
- `python scripts/smoke_package.py .cache/remediation-dist/security_review_engine-0.1.0-py3-none-any.whl`: passed offline installation, optional-dependency absence, packaged schema, and package-shadowing checks.
- `git diff --check`: passed.

The earlier 13-job platform result applies to the historical commit named above. This repair set has not yet been verified through that matrix. Live Claude conformance and real GitHub PR publication remain unverified; no provider requests or external comments were needed for the repairs.
