# Security Review Engine: M1 usage and migration

M1 provides one engine for the Python API, CLI and GitHub Action. Investigation uses Claude Code; validation uses an independently selected Claude model through the Anthropic API. Native OpenAI-compatible and Claude investigation loops belong to M2.

## Install and inspect

From a trusted checkout, using Python 3.11–3.14:

```text
python -m pip install ".[claude]"
security-review backends list
security-review config show --redact
```

The core package has no runtime dependencies. Claude dependencies are optional and pinned; importing the API, inspecting configuration, and reviewing an empty comparison do not require provider SDKs. For a nonempty Claude review, install Claude Code >=2.1.248,<3, set `ANTHROPIC_API_KEY`, and choose model IDs your account can access. The Action pins runtime 2.1.248. Availability of this version was checked against the public npm registry; live isolation/model conformance remains a release gate.

Use the installed `security-review` command, or `python -I -m security_review`. Isolated Python invocation avoids importing code from the reviewed directory. For development from this trusted source checkout, `python -m security_review` works too.

## Select changes

```text
security-review scan --repo /repo --base main --head HEAD --model YOUR_CLAUDE_MODEL --output review.json
security-review scan --repo /repo --base HEAD~1 --head HEAD --comparison direct
security-review scan --repo /repo --staged --format markdown --output review.md
security-review scan --repo /repo --unstaged
security-review scan --repo /repo --working-tree --include-untracked
security-review scan --pr owner/repo#123 --config /trusted/review.toml --output review.json
```

| Mode | Comparison |
|---|---|
| Revisions, default | Merge base of base/head against head |
| Revisions, `--comparison direct` | Exactly base against head |
| `--staged` | HEAD against index |
| `--unstaged` | Index against tracked working files |
| `--working-tree` | HEAD against index plus tracked working files |

Untracked files are excluded unless explicitly included in a working-copy mode. Git-ignored files stay excluded. Working modes detect changes during capture and fail with a retry requirement; later edits cannot alter captured evidence. They never stage, checkout, commit, or change branches.

PR source acquisition uses GitHub REST objects, paginates files and resolves immutable base/head content. It does not execute repository Git helpers, initialize submodules, hydrate LFS, or rely on a matching local checkout. `GITHUB_SOURCE_TOKEN` supplies source access, with `GITHUB_TOKEN` as a compatibility fallback. Public access without a token is possible subject to GitHub limits.

## Trusted configuration

Configuration is loaded only with `--config`; nothing is discovered from source automatically. JSON and TOML are supported. Unknown keys and invalid combinations are errors. Precedence is explicit API/CLI input, approved `SECURITY_REVIEW_*` variables, selected file, then packaged defaults. File paths resolve against the configuration directory; CLI paths resolve against the invocation directory.

```toml
model = "YOUR_INVESTIGATION_MODEL"
validation_model = "YOUR_VALIDATION_MODEL"
timeout_seconds = 1200
cloud_allowed = true
blocking_severities = ["HIGH"]
denied_paths = ["secrets/**", "private-keys/**"]
cache_dir = "./review-state"
instructions_file = "./investigation.txt"
instructions_mode = "extend"

[policy]
profile = "generic"
version = "1"
minimum_severity = "MEDIUM"
minimum_confidence = 0.8
validation_required = true
exclude_paths = ["generated/**"]
exclude_categories = []
```

`denied_paths` restricts source access and transmission. `policy.exclude_paths` only excludes review scope: those files may still be context. Category rules match structured categories, not incidental words in a finding. Source-controlled `@generated` strings do not change scope.

`instructions`/`validation_instructions` accept inline text; their `_file` forms accept explicit trusted files. `instructions_mode=extend` appends investigation instructions, while `replace` replaces those investigation instructions. Neither changes structured policy, tool permissions, or report validation. Effective configuration stores instruction hashes rather than instruction contents. Secrets come from credential environment variables and never appear in configuration hashes.

The `generic` profile has no category exclusions. The versioned `legacy` profile retains named legacy scope categories for comparisons, with language/HTML assumptions removed. Accepted-risk suppressions match an exact finding fingerprint and include `id`, `reason`, `source`, optional `owner`, and optional ISO `expires` date. They remain separate from validation decisions.

## Results and exit codes

Reports contain execution status, policy outcome, snapshot identity/content manifests, finding evidence references, validation provenance, structured events/errors, effective configuration/policy hashes, and coverage lists/reasons/counts. Unknown usage is null. Where Claude reports token counts, investigation usage is recorded separately from unknown validation usage.

| Exit | Meaning |
|---|---|
| `0` | Completed with no finding matching the blocking policy; requested artifacts written |
| `1` | Completed with a confirmed HIGH finding meeting the configured confidence threshold |
| `2` | Configuration, execution, coverage, required validation, export, or publication failure |
| `3` | Cancelled |

HIGH is the exact default blocking set, not a minimum-severity threshold. CRITICAL, MEDIUM and LOW remain nonblocking unless the set is changed explicitly. Operational failure takes precedence over a finding failure. A partial report can contain a confirmed blocker and therefore have `policy_outcome=fail`, while returning `2` for incomplete execution.

Confirmed findings below reporting thresholds, uncertain/unvalidated candidates, rejected candidates and suppressions remain inspectable. Failed validation never invents confidence. Explicitly disabled optional validation retains unvalidated, nonblocking candidates. A completed report describes completed review work, not proof that code is vulnerability-free.

JSON is one document on stdout; diagnostics use stderr. Markdown escapes source-controlled formatting and workflow-command text. Artifact writes reject symlinks/junctions and use atomic replacement. An output failure preserves JSON on stdout and returns `2`; it does not fabricate a successful artifact.

## Persistence and publication

```text
security-review scan --repo /repo --base main --head HEAD --state-dir /private/review-state
security-review runs show --state-dir /private/review-state --id RUN_ID
security-review cache cleanup --state-dir /private/review-state --older-than-days 30
security-review publish --report review.json --pr owner/repo#123
```

State storage is opt-in through `--state-dir`/`cache_dir`. SQLite stores stage/report state and expiring ownership leases transactionally. Only validated completed reports can be reused; snapshot, full working-copy context, policy/instructions, model/backend versions and access constraints participate in identity. `--no-cache` bypasses reuse. Cache hits have a new run ID plus original-run provenance. Cleanup deletes only rows in the selected engine database; retention is explicit, with 30 days as the cleanup command default. State directories are single-user/private, not a shared trust boundary.

Publication reads a saved report; it never reruns investigation. `GITHUB_PUBLISH_TOKEN` supplies publication access. The report must be bound to the target PR. Publication checks current head before writes, uses reviewed commit/side/line locations, and falls back to summary comments for non-inline locations. Tool markers and authenticated author identity deduplicate findings per revision. It never edits another author's comments or infers resolution from a partial review. A stale/failed publication has its own result; scan status remains unchanged.

## Python API and extensions

```python
from pathlib import Path
from security_review import ReviewRequest, Policy, review, CancellationToken

token = CancellationToken()
request = ReviewRequest(
    Path("/repo"), "main", "HEAD",
    model="YOUR_INVESTIGATOR", validation_model="YOUR_VALIDATOR",
    policy=Policy(),
)
report = review(request, cancellation=token, on_event=lambda event: print(event))
```

`review_async` exposes the same engine through an asynchronous wrapper. Cancellation signals the engine and waits for its final report. Built-in subprocesses are supervised with deadlines and bounded output; Windows uses a kill-on-close Job Object assigned before process startup, and POSIX uses an owned process group. Arbitrary injected Python adapters must cooperate with the cancellation/deadline contract; the library cannot safely terminate arbitrary code running in its host thread.

Adapters can be injected directly into `review` or explicitly registered through `Registry`. Sources, investigators, validators, policies and publishers have separate registrations. No reviewed-directory module discovery or automatic plugin installation occurs. Installed adapter code is trusted executable code.

Public Python exports are in `security_review.__all__`. Version `1.0` wire schemas are packaged under `security_review/schemas`; unknown incompatible report/state versions fail loading. Canonical wire severities use uppercase values for compatibility. Engine-generated fingerprints hash normalized evidence, category and path, rather than line number or prose alone. Renaming a file or changing evidence can change identity; cross-rename/rebase identity is not guaranteed.

## GitHub Action migration

The Action now installs the package and calls `python -I -m security_review.action` from the runner's temporary directory. It reviews every PR revision and exposes `scan-status`, `policy-outcome`, `findings-count`, `results-file`, and `publication-status`. Output paths are absolute paths in the caller's workspace. `ci-mode=blocking` is the default; `advisory` retains failure/status artifacts while leaving the scan step successful. Artifact-write failures always return an error.

New inputs: `model`, `validation-model`, `backend`, `config`, `timeout-seconds`, `ci-mode`. Legacy `claude-model` and `claudecode-timeout` remain aliases; conflicting values fail. `run-every-commit` is deprecated because every revision now runs. Existing instruction-file inputs remain available, but PR runs reject files inside the reviewed workspace; supply them from a separate trusted checkout/location.

Source reading requires repository contents/PR read access; publication additionally needs pull-request write access. Fork PRs often have no provider secret or publication permission. Such missing capabilities produce explicit failure; the implementation does not switch to `pull_request_target` or another elevated execution workaround. The bundled live-review workflow runs only same-repository PRs and checks out the trusted base for its Action implementation. The offline test workflow runs for all PRs without provider credentials.

Non-PR Action invocations fail with an explicit unsupported-event result; use the local CLI for non-PR scans. Historical JavaScript publishing and the host-owned slash command remain for compatibility reference; the migrated Action does not execute them.

## Backend and platform capabilities

| Component | Requirements | Verification status |
|---|---|---|
| Core, CLI, local source, persistence | Python 3.11–3.14; Git for local snapshots; no provider SDK | Windows/Python 3.13 offline acceptance verified; Linux/macOS and remaining Python versions await CI |
| Claude Code investigation | Runtime >=2.1.248,<3, API key, cloud processing allowed; Action pins 2.1.248 | Command, environment, result and process contracts tested offline; live runtime/managed-policy isolation remains unverified |
| Claude API validation | Optional `claude` dependencies, API key, selected accessible Claude model | Fresh-context evidence and failure contracts tested offline; live model access/quality remains unverified |
| GitHub source/publication | Repository/PR read access; PR write access for publication | Paginated transport, stale-head and author ownership fixtures pass; real installation-token lifecycle awaits a test PR |
| Native OpenAI-compatible/Claude agents | Planned M2 adapters | Not implemented in M1 |

Claude runtime availability is an additional platform constraint; core support does not imply that a runtime is installed or certified on that host. The compatibility backend uses an owned temporary snapshot and restricted runtime flags, but does not provide an OS sandbox for arbitrary untrusted repositories.

## Troubleshooting and current release limits

- `source` failure: verify explicit refs, local history/object availability, Git ownership, file limits, or GitHub permissions. Local capture disables partial-clone lazy fetching; fetch missing history separately. The engine never adds Git ownership exceptions.
- `preflight` failure: inspect `backends list`, runtime version, `ANTHROPIC_API_KEY`, configured models and `cloud_allowed`. Account/model access is finally established by the actual selected-model request.
- Incomplete coverage: inspect coverage reasons. Binary/non-UTF-8, LFS pointer, link/submodule, denied and oversized changed files are not silently counted as reviewed.
- State reservation: another run owns the same input. Active leases are not stolen; expired owners cannot overwrite a successor's result.
- Stale publication: the PR moved. Review its new head; do not publish the old report as current.

Source bounds are 1 MiB per file, 32 MiB per captured side/content budget, 10,000 files and 8 MiB diff/transport responses. Repository-reader inventory/read/search/diff methods provide bounded pages. A large compatibility assignment is provided as an owned inert file. Validation currently requires its base/head/diff evidence within 1 MiB; oversized required evidence yields an incomplete result. Native context planning and token/cost ceilings are M2 work.

This release candidate is for trusted repositories and hosts. Runtime/managed-policy isolation and live detection quality are not certified by mocked tests. Linux/macOS and the declared Python-version matrix require successful CI runs before M1 release acceptance. Native provider independence, MCP/framework integrations, and SARIF remain M2/M3.
