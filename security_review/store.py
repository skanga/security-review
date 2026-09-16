"""Single-user transactional run storage and expiring ownership leases."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import time
import uuid

from .models import ReviewReport
from .rendering import render_json


class RunStore:
    def __init__(self, directory):
        directory = Path(directory).absolute()
        if directory.is_symlink() or any(p.is_symlink() for p in directory.parents):
            raise ValueError("State directory cannot be a symlink")
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "reviews.sqlite3"
        if self.path.is_symlink():
            raise ValueError("State database cannot be a symlink")
        with self.connect() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1}:
                raise ValueError("Unsupported state schema; use a compatible engine or export first")
            connection.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, cache_key TEXT, status TEXT, created REAL, report TEXT)")
            connection.execute("CREATE TABLE IF NOT EXISTS leases (cache_key TEXT PRIMARY KEY, owner TEXT, run_id TEXT, expires REAL)")
            connection.execute("PRAGMA user_version=1")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def acquire(self, key, run_id, expires):
        owner = str(uuid.uuid4())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT owner, expires FROM leases WHERE cache_key=?", (key,)).fetchone()
            if existing and existing[1] > time.time():
                raise ValueError("Review snapshot is reserved by another active run")
            connection.execute("INSERT OR REPLACE INTO leases VALUES (?, ?, ?, ?)", (key, owner, run_id, expires))
        return owner

    def release(self, key, owner):
        with self.connect() as connection:
            return bool(connection.execute("DELETE FROM leases WHERE cache_key=? AND owner=?", (key, owner)).rowcount)

    def save(self, report, key="", owner=None):
        with self.connect() as connection:
            if owner and not connection.execute("SELECT 1 FROM leases WHERE cache_key=? AND owner=? AND expires>?", (key, owner, time.time())).fetchone():
                raise ValueError("Run no longer owns its lease")
            connection.execute("INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?)",
                               (report.run_id, key, report.status, time.time(), render_json(report)))

    def cached(self, key):
        with self.connect() as connection:
            rows = connection.execute("SELECT report FROM runs WHERE cache_key=? AND status='completed' ORDER BY created DESC", (key,)).fetchall()
        import json
        for row in rows:
            try:
                return ReviewReport.from_dict(json.loads(row[0]))
            except (ValueError, TypeError):
                continue
        return None

    def load(self, run_id):
        with self.connect() as connection:
            row = connection.execute("SELECT report FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise ValueError("Unknown run ID")
        import json
        return ReviewReport.from_dict(json.loads(row[0]))

    def cleanup(self, older_than_days=30):
        if type(older_than_days) is not int or older_than_days < 1:
            raise ValueError("Retention must be at least one day")
        with self.connect() as connection:
            # Only rows in this engine-owned database; never filesystem recursion.
            return connection.execute("DELETE FROM runs WHERE created<? AND id NOT IN (SELECT run_id FROM leases WHERE expires>?)",
                                      (time.time() - older_than_days * 86400, time.time())).rowcount
