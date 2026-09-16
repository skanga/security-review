"""Explicit application-owned adapters. Never scan the source checkout for code."""
class Registry:
    def __init__(self):
        from .claude_backend import ClaudeCodeBackend, ClaudeFindingValidator
        from .repository import capture
        from .policy import Policy
        from .rendering import render_json, render_markdown
        from .github import GitHubClient, GitHubSource, GitHubPublisher
        self._adapters = {"backend": {"claude-code": ClaudeCodeBackend},
                          "validator": {"claude-api": ClaudeFindingValidator},
                          "source": {"local": lambda: capture, "github": lambda: GitHubSource(GitHubClient())},
                          "policy": {"generic": Policy, "legacy": lambda: Policy(profile="legacy")},
                          "publisher": {"json": lambda: render_json, "markdown": lambda: render_markdown,
                                        "github": lambda: GitHubPublisher(GitHubClient())}}

    def register(self, kind, name, factory):
        if kind not in self._adapters or name in self._adapters[kind] or not callable(factory):
            raise ValueError("Invalid or duplicate adapter registration")
        self._adapters[kind][name] = factory

    def list(self, kind):
        return sorted(self._adapters[kind])

    def create(self, kind, name):
        try:
            return self._adapters[kind][name]()
        except KeyError as exc:
            raise ValueError(f"Unknown {kind} adapter: {name}") from exc
