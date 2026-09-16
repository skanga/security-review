# M0/M1 completion plan

Goal: implement the remaining M0/M1 requirements without changing the agreed provider, cloud-processing, or HIGH-only gate decisions. Native providers and framework/MCP integration stay in M2/M3.

Done means each M0/M1 requirement has implementation and acceptance evidence, or an explicitly recorded external verification gap. Do not silently reduce release gates. Preserve existing uncommitted work and upstream notices.

## Work sequence

1. Freeze corrected compatibility behavior and explicit legacy/default policy profiles; remove extension-based and mixed-impact suppression errors.
2. Complete typed configuration, policy, schemas, progress/error/provenance contracts, capability checks, and adapter registry.
3. Complete staged/unstaged/combined immutable snapshots, inventory/reasons, bounded repository readers and capture consistency tests.
4. Add cancellation/deadline controls, persistent reports, cache identity/ownership and recovery; keep unknown usage explicit.
5. Complete CLI/API commands, Markdown/JSON rendering, trusted configuration/instruction resolution, and package installation smoke tests.
6. Add GitHub PR acquisition and revision-aware publication, migrate the Action to the common engine, and test pagination/stale heads/deduplication/failures offline.
7. Add platform CI, API/schema/migration/troubleshooting docs and acceptance mapping; run final offline checks and report external verification honestly.

## Implementation constraints

- Tests first for behavior changes; real disposable Git histories and deterministic fake runtimes/transports.
- Reuse Python standard-library facilities (argparse, dataclasses, JSON/TOML, sqlite3, subprocess) and existing optional provider dependencies. No new agent framework or database service.
- Never load configuration/plugins from reviewed source implicitly. Source, model, and publisher credentials remain separate.
- No live source upload, paid evaluation, publication, commit, push, or deployment is needed for offline completion work.
- Linux/macOS and live runtime checks require appropriate execution environments. Adding CI does not mean those jobs already passed.

## Acceptance risks to exercise

Malformed reports and schemas; missed coverage; symlink/Windows path escapes; concurrent worktree changes; unavailable binary/LFS content; empty diffs; stale caches and owners; cancellation/timeout; output failures; source/publish credential isolation; >100 changed files/comments; stale PR heads and repeat publication; failed validation; advisory versus blocking Action behavior.

## Delivery record

The implementation sequence above is delivered, including offline acceptance cases, the Action migration, versioned schemas/profiles, clean wheel installation, migration documentation and CI matrix. See [implementation progress](implementation-progress.md) for exact verification. External OS/runtime/GitHub conformance remains an explicit release gate; the local changes are not a claim that those remote checks have already passed.
