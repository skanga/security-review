"""Deterministic, local-only Git fixture for the pinned evaluation manifest."""
import os
from pathlib import Path
import subprocess


def build(repository):
    repository.mkdir()
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_AUTHOR_NAME="Fixture", GIT_COMMITTER_NAME="Fixture",
               GIT_AUTHOR_EMAIL="fixture@example.invalid", GIT_COMMITTER_EMAIL="fixture@example.invalid",
               GIT_AUTHOR_DATE="2000-01-01T00:00:00+0000", GIT_COMMITTER_DATE="2000-01-01T00:00:00+0000")
    def git(*arguments):
        return subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", "-C", str(repository), *arguments],
                              env=env, check=True, capture_output=True, text=True, timeout=20).stdout.strip()
    git("init", "-q", "--object-format=sha1")
    revisions = []
    for side in ("base", "head"):
        fixture = Path(__file__).parent / "fixtures" / f"authorization-{side}.py"
        (repository / "app.py").write_bytes(fixture.read_text().replace("\r\n", "\n").encode())
        git("add", "app.py")
        git("commit", "-qm", side)
        revisions.append(git("rev-parse", "HEAD"))
    return revisions
