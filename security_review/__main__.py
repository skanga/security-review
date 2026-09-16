"""CLI boundary: trusted options in, canonical reports out."""
import argparse
import json
import os
from pathlib import Path
import sys
import uuid

from . import ReviewReport, review, resolve_config, effective_config, Registry
from .rendering import render_json, render_markdown, atomic_write


def parser():
    root = argparse.ArgumentParser(description="Review code changes using the shared security review engine")
    commands = root.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Review trusted local Git or GitHub PR changes")
    scan.add_argument("--repo", type=Path)
    scan.add_argument("--pr")
    scan.add_argument("--base")
    scan.add_argument("--head")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--unstaged", action="store_true")
    mode.add_argument("--working-tree", action="store_true")
    scan.add_argument("--include-untracked", action="store_true", default=None)
    scan.add_argument("--comparison", choices=["merge_base", "direct"])
    scan.add_argument("--config", type=Path)
    scan.add_argument("--model")
    scan.add_argument("--validation-model")
    scan.add_argument("--backend")
    scan.add_argument("--validator")
    scan.add_argument("--timeout-seconds", type=int)
    scan.add_argument("--state-dir", type=Path)
    scan.add_argument("--no-cache", action="store_true", default=None)
    scan.add_argument("--format", choices=["json", "markdown"], default="json")
    scan.add_argument("--output", type=Path)
    configuration = commands.add_parser("config").add_subparsers(dest="operation", required=True)
    show = configuration.add_parser("show")
    show.add_argument("--config", type=Path)
    show.add_argument("--redact", action="store_true", help="Secrets are always redacted")
    commands.add_parser("backends").add_subparsers(dest="operation", required=True).add_parser("list")
    publish = commands.add_parser("publish", help="Publish a saved report without rerunning investigation")
    publish.add_argument("--report", type=Path, required=True)
    publish.add_argument("--pr", required=True)
    publish.add_argument("--timeout-seconds", type=int, default=180)
    cache = commands.add_parser("cache").add_subparsers(dest="operation", required=True).add_parser("cleanup")
    cache.add_argument("--state-dir", type=Path, required=True)
    cache.add_argument("--older-than-days", type=int, default=30)
    show_run = commands.add_parser("runs").add_subparsers(dest="operation", required=True).add_parser("show")
    show_run.add_argument("--state-dir", type=Path, required=True)
    show_run.add_argument("--id", required=True)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "config":
            print(json.dumps(effective_config(resolve_config(args.config)), indent=2))
            return 0
        if args.command == "backends":
            registry = Registry()
            print(json.dumps({"investigation": [{"name": name, **registry.create("backend", name).capabilities()}
                                                for name in registry.list("backend")], "validation": registry.list("validator")}, indent=2))
            return 0
        if args.command in {"cache", "runs"}:
            from .store import RunStore
            store = RunStore(args.state_dir)
            print(json.dumps({"removed": store.cleanup(args.older_than_days)}) if args.command == "cache" else render_json(store.load(args.id)), end="\n")
            return 0
        if args.command == "publish":
            from .github import GitHubClient, GitHubPublisher
            report = ReviewReport.from_dict(json.loads(args.report.read_text(encoding="utf-8")))
            result = GitHubPublisher(GitHubClient(os.environ.get("GITHUB_PUBLISH_TOKEN") or os.environ.get("GITHUB_TOKEN"),
                                                  timeout=args.timeout_seconds)).publish(report, args.pr)
            print(json.dumps(result.to_dict(), indent=2))
            return 0 if result.status == "published" else 2
        mode = "staged" if args.staged else "unstaged" if args.unstaged else "working_tree" if args.working_tree else None
        if (mode and (args.base or args.head or args.pr)) or (args.pr and (args.base or args.head)):
            raise ValueError("Revision, working-copy, and PR modes cannot be combined")
        overrides = {"repository": args.repo, "pr": args.pr, "base": args.base, "head": args.head,
                     "mode": mode, "include_untracked": args.include_untracked, "comparison": args.comparison,
                     "model": args.model, "validation_model": args.validation_model, "backend": args.backend,
                     "validator": args.validator, "timeout_seconds": args.timeout_seconds,
                     "cache_dir": args.state_dir, "no_cache": args.no_cache}
        request = resolve_config(args.config, overrides)
        if request.pr and request.mode != "revisions":
            raise ValueError("PR source cannot use a working-copy mode")
        report = review(request)
    except KeyboardInterrupt:
        report = ReviewReport(str(uuid.uuid4()), status="cancelled")
    except Exception as exc:
        report = ReviewReport(str(uuid.uuid4()), errors=[{"stage": "configuration", "code": "INVALID_REQUEST",
                              "retryable": False, "message": f"Invalid configuration ({type(exc).__name__}); check options, paths and installed adapters"}])
    if getattr(args, "output", None):
        report.artifacts = [str(args.output.absolute())]
    payload = render_markdown(report) if getattr(args, "format", "json") == "markdown" else render_json(report)
    if getattr(args, "output", None):
        try:
            atomic_write(args.output, payload)
        except OSError:
            print("Could not write requested report; JSON follows on stdout", file=sys.stderr)
            print(render_json(report), end="")
            return 2
    else:
        print(payload, end="")
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
