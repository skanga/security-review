# Security Review Engine

An agentic security reviewer with one Python engine exposed through a CLI, Python API and GitHub Action. It investigates changes, validates findings against immutable evidence, applies explicit policy and reports whether the review completed.

This repository extends the original Anthropic Claude Code Security Reviewer. M1 uses Claude Code for investigation and the Anthropic API for validation. Native OpenAI-compatible and Claude investigation backends are planned for M2.

## Local review

From a trusted checkout, with Python 3.11–3.14:

```text
python -m pip install ".[claude]"
security-review backends list
security-review scan --repo /path/to/repo --base main --head HEAD --model YOUR_CLAUDE_MODEL --output review.json
```

Nonempty reviews require Claude Code >=2.1.248,<3 and `ANTHROPIC_API_KEY`. The minimal core, configuration inspection and empty revision comparisons work without provider SDKs.

```text
security-review scan --repo /repo --staged --format markdown
security-review scan --repo /repo --working-tree --include-untracked
security-review scan --pr owner/repo#123 --config /trusted/review.toml
security-review publish --report review.json --pr owner/repo#123
```

Use this release candidate with trusted repositories and hosts. Reviewed source is sent to the configured provider. Runtime isolation and cross-platform release acceptance remain subject to the checks in [implementation status](docs/implementation-progress.md).

## CI behavior

- Only confirmed **HIGH** findings meeting the confidence policy block by default.
- Incomplete reviews, operational failures and output failures return a separate error.
- JSON records execution status, coverage, findings, validation decisions and policy outcome.
- The Action reviews each revision and exposes `scan-status`, `policy-outcome`, `findings-count`, `results-file` and `publication-status`.

The Action pins its Claude Code runtime. Use a trusted pinned revision of this repository when integrating it into a workflow. It needs `contents: read`; PR publication also needs `pull-requests: write`. Forks with unavailable secrets/permissions are not elevated automatically. `ci-mode: advisory` preserves status/results while making findings and scan failures advisory; artifact-write failures remain errors.

Legacy `claude-model` and `claudecode-timeout` inputs remain deprecated aliases. Conflicting aliases fail. See [Action migration and configuration](docs/local-review.md#github-action-migration) for the complete contract.

## Documentation

- [Usage, configuration, Python API and troubleshooting](docs/local-review.md)
- [Implementation and verification status](docs/implementation-progress.md)
- [Requirements](docs/generic-security-review-requirements.md)
- [Design](docs/generic-security-review-design.md)
- [Corrected compatibility baseline](docs/legacy-policy-baseline.md)
- [Original repository assessment](docs/generic-tool-assessment.md)

## Development

```text
python -c "from pathlib import Path; Path('.cache').mkdir(exist_ok=True)"
python -m pytest -q --basetemp=.cache/pytest
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir .cache/dist
python scripts/smoke_package.py .cache/dist/security_review_engine-0.1.0-py3-none-any.whl
```

The Python suite uses synthetic model/API responses and disposable Git histories. The historical JavaScript publisher tests run with `bun test` in `scripts/`; the migrated Action uses the Python publisher. CI defines Windows, Linux and macOS tests for Python 3.11–3.14.

Upstream copyright notices and the [MIT license](LICENSE) are retained.
