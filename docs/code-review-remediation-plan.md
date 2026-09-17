# Code review remediation plan

## Objective and completion criteria

Fix all seven findings from the repository review of `d6e9961`. Eliminate the two reproduced false-pass cases, restore accurate local change selection, and preserve the documented configuration, adapter, artifact, and report contracts.

Complete when the nine review probes have been promoted into maintained tests and pass, the additional boundary cases below pass, the existing Python and JavaScript suites pass, and compatibility/documentation changes are recorded. Each change follows RED (reproduce), GREEN (minimal fix), then focused cleanup.

Baseline: 289 Python tests and 11 JavaScript tests passed. Nine probes in `.cache/test_review_regressions.py` reproduce seven defects. That ignored file is a starting point; move its cases into the appropriate tracked test modules and reuse their fixtures rather than depending on `.cache`.

## Constraints

- Keep the existing HIGH-only default blocking policy and separation between review status and publication status.
- Use existing dependencies. Preserve immutable evidence, denied-content boundaries, process isolation, cancellation, and capture-race checks.
- Tests use disposable Git histories, synthetic findings, mocked dates, and fake publishers. No paid model requests or external comments are needed.
- Keep each repair independently reviewable. Avoid unrelated legacy cleanup.
- Do not reuse cached reports whose earlier deduplication could already have discarded candidates.

## Implementation sequence

### 1. Distinguish separate finding locations (P1)

Files: `security_review/engine.py`, `contracts.py`, `schema.py`, packaged report schema, `github.py`, and finding/contract tests.

1. Promote the two-call-site regression: identical source text, first candidate rejected, second candidate confirmed. Require both to reach validation and the confirmed HIGH finding to block.
2. Introduce a location-aware identity using path, side, start/end lines, category, and evidence hash. Exact repeated candidates at the same location still deduplicate. Use the identity consistently for findings, suppression matching, and publication deduplication.
3. Version the fingerprint format because changing its meaning under `v1` would silently reinterpret saved suppressions. Emit a new fingerprint version, accept supported historical reports for inspection, and explicitly handle old suppression identities without broadening their matches. Document that line movement may change the new identity.
4. Update publication markers/contract checks and invalidate older review-cache identities. Old cached reports cannot recover discarded candidates by merely rerunning policy.

Acceptance: distinct locations and base/head sides are preserved; exact duplicates collapse; both candidate orders produce the same blocking outcome; separate locations can be published independently; legacy suppression configuration has an explicit migration/error path; historical report loading remains deliberate and tested.

### 2. Reevaluate expiring suppressions on cache reuse (P1)

Files: `security_review/engine.py`, `policy.py`, `store.py` as needed, and `tests/test_m1_store_runtime.py`.

1. Promote the expiry regression using a controlled date and a cached confirmed HIGH candidate.
2. Rebuild policy decisions from the retained and suppressed validated candidates on every run, including cache hits. Clear previous partitioning before reevaluation so findings neither disappear nor multiply. Keep validator-rejected candidates rejected.
3. Evaluate expiry against one captured policy date per run. Preserve original validation results and cache provenance without repeating model calls.
4. Recompute reportable flags, candidate partitions, policy outcome, and persisted final state after reevaluation.

Acceptance: an exception applies through its expiry date; the next day cached and uncached runs agree; permanent exceptions remain effective; multiple cache hits do not duplicate findings; a persisted cache-hit report passes contract loading.

### 3. Separate changed-path selection from content availability (P2)

Files: `security_review/repository.py`, `tests/test_m1_contracts.py`, and `tests/test_m1_boundaries.py`.

1. Promote the clean-repository denied-file regression for staged, unstaged, and working-tree modes. Add unchanged oversized files and link/submodule cases where supported.
2. Determine staged changes from immutable HEAD/index object identities and modes, including entries whose content is unavailable. Stop treating membership in `unavailable` as proof of a change.
3. For working-copy modes, use safe filesystem/index metadata plus captured contents where access is allowed. Distinguish an unchanged unavailable entry from an entry whose state changed or cannot be established safely. Preserve conservative incomplete coverage for actual or uncertain unavailable changes.
4. Keep availability reasons as a separate inventory and intersect them with selected changes for review coverage.

Acceptance: clean repositories stay empty without provider preflight; an unrelated ordinary edit excludes unchanged denied/oversized entries; modified or deleted unavailable entries remain visible and cannot produce a false clean result; mode changes and capture races remain covered.

Implementation risk: avoid solving this with a Git worktree comparison that implicitly executes configured clean filters or reads denied contents. Confirm the chosen metadata operations preserve the existing source boundary before using them.

### 4. Respect Git line-ending rules when selecting working-copy changes (P2)

Depends on step 3's separation of selection from evidence.

Files: `security_review/repository.py` and local-source tests.

1. Promote the clean `core.autocrlf=true` regression for both unstaged and working-tree modes.
2. Account for applicable Git text/EOL settings during comparison while preserving the original immutable evidence bytes and content IDs. Limit normalization to paths for which Git text normalization applies.
3. Cover explicit text/EOL attributes, disabled normalization, binary files, and a real content edit in a CRLF file. Do not introduce custom filter execution.

Acceptance: clean CRLF checkouts select no changes; actual edits are selected; meaningful byte changes in non-normalized files remain visible; staged mode continues comparing Git objects; line locations remain correct.

### 5. Make Action artifact failures unconditional errors (P2)

Files: `security_review/action.py` and `tests/test_m1_cli_action.py`.

1. Promote the failed publication-artifact write regression for advisory and blocking modes. Add a round-trip assertion through `ReviewReport.from_dict()`.
2. Separate scan execution, publication, and artifact-write error handling. Publication failures belong to the publication result and must not add execution errors to an otherwise completed scan report.
3. Track artifact failure independently and return exit 2 in both CI modes. Still attempt the canonical scan report and workflow outputs when their destinations are usable.
4. Keep successful publication distinct from failure to persist its receipt, with a clear diagnostic and no fabricated artifact success.

Acceptance: publication-file, canonical-report, and workflow-output write failures return 2; saved scan reports remain valid; ordinary scan/publication failures retain the documented advisory behavior; recovery output remains available when writing fails.

### 6. Preserve explicit configuration under Action defaults (P2)

Files: `security_review/action.py`, `config.py` if needed, `action.yml` if needed, and configuration/Action tests.

1. Split the current combined probe into timeout-precedence and validation-model-precedence cases.
2. Pass only explicitly provided Action inputs as overrides. Leave an absent timeout or validation model unset until normal configuration resolution chooses a value.
3. Apply model fallback after merging configuration sources, while preserving independently configured validator models. Check other Action defaults for the same override problem.
4. Preserve deprecated alias conversion and conflict rejection.

Acceptance: the configured 45-second timeout and independent validator survive absent overrides; explicit inputs win; supported environment values retain precedence; empty Action inputs do not replace configuration; no-config runs retain packaged defaults; conflicting aliases still fail.

### 7. Preserve an explicitly injected validator (P2)

Files: `security_review/engine.py` and API/registry tests.

1. Promote the regression where the registry supplies the backend and the caller supplies the validator.
2. Resolve defaults only for components that require a default; never overwrite the supplied validator. Preserve the existing behavior for fully injected backends and deliberately missing required validators.
3. Keep validation-disabled behavior and preflight consistent with the selected components.

Acceptance: the supplied validator's preflight and validation methods run; the default validator factory is never invoked in this case; no default provider credentials are required by that injected path; default-only and fully injected paths retain their existing behavior.

## Final verification and delivery

1. Run each new regression RED before its fix, then its focused test group GREEN.
2. After all repairs, run the complete Python suite and `bun test` in `scripts/`.
3. Validate generated schema parity, saved-report round trips, cache compatibility, and API/CLI/Action policy agreement. Regenerate packaged schemas from their source when required.
4. Build the wheel and run `scripts/smoke_package.py` against it. Run `git diff --check`.
5. Use the existing Windows/Linux/macOS and Python 3.11-3.14 matrix for platform verification when CI is run. Report local evidence separately from pending remote checks.
6. Update usage, fingerprint/suppression migration guidance, and implementation status to describe the final behavior. Deliver a concise mapping of each finding to its fix and regression coverage, with any remaining verification limits.

## Implementation record

All seven repairs are implemented. Maintained regression tests replace the scratch probes:

| Finding | Implementation | Regression coverage |
|---|---|---|
| 1. Collapsed call sites | `engine.py`, `contracts.py`, `schema.py`, generated report schema: location-aware v2 fingerprints and cache format invalidation | `test_engine_regressions.py`: both candidate orders, exact duplicates, base/head distinction, legacy report/suppression/cache handling, independent publication |
| 2. Expired cached suppression | `engine.py`, `policy.py`: repartition validated findings using one policy date on every run | `test_engine_regressions.py`: inclusive expiry, repeated cache hits, fresh/cache agreement, permanent rules, persisted contract loading |
| 3. Unchanged unavailable paths selected | `repository.py`: separate object/mode/stat comparison from evidence availability | `test_working_scope.py`: clean and changed denied/oversized files, deletion, capture races, symlinks, regular symlink checkouts, initialized submodules |
| 4. Clean CRLF checkout selected | `repository.py`: guarded text/EOL comparison of captured bytes; raw evidence retained | `test_working_scope.py`: autocrlf and attributes in both modes, real edit diff, binary/disabled normalization, filter nonexecution, denied attribute sources |
| 5. Artifact failure hidden by advisory mode | `action.py`: independent publication and artifact outcomes, recovery output, unconditional exit 2 for artifact errors | `test_action_regressions.py`: receipt/report/workflow-output failures and returned/raised publisher failures in both modes |
| 6. Action defaults overwrite configuration | `action.py`, `action.yml`: unset inputs remain unset until shared configuration resolution | `test_action_regressions.py`: timeout/model precedence, empty inputs, defaults, independent validator model, backend YAML default |
| 7. Injected validator overwritten | `engine.py`: resolve only missing adapters | `test_engine_regressions.py`: supplied validator preflight/calls, unused factory, validation disabled |

Each defect was reproduced before its fix. Independent review added coverage for clean initialized submodules versus dirty tracked contents at the same HEAD, `core.symlinks=false`, and denied attribute files including equivalent paths containing `..`. The final verification results are recorded in [implementation progress](implementation-progress.md#code-review-remediation).

Compatibility: new scans emit `v2:` fingerprints. Old reports remain readable, but old suppression configuration requires a fresh scan and explicit selection of the intended location. See [migration guidance](local-review.md#trusted-configuration).
