"""Baseline storage, and the comparison that makes the second review short.

A one-shot design review is a document. A review with a baseline is a process:
it runs again when the design changes and answers the only question anybody asks
the second time, which is *what did that change introduce*.

Designs come back. A vendor is swapped, a data type is added, an integration
appears -- and re-reading a full review each time is how the review ends up
skipped. "This revision adds one outbound feed of personal data to an external
party" is a sentence a requesting team will actually act on.

Two properties matter for the comparison to be trustworthy:

* **Structural keys.** Findings are compared by which facts and controls they
  rest on, not by title. Wording varies between runs; if a reworded description
  of a known risk showed up as newly introduced, the comparison would fill with
  noise and the reader would learn to ignore it. See :meth:`Finding.key`.
* **Scoped state.** Two systems sharing a state file get separate baselines.
  Without that, every run would compare against an unrelated system, find
  nothing in common, and report the whole review as new.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from .models import Intake, Review

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
DEFAULT_STATE_PATH = ".entsec/reviews.db"
DEFAULT_RETAIN = 20


class StateError(Exception):
    """The baseline could not be read or written."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scope        TEXT NOT NULL,
    finished_at  TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    model_id     TEXT NOT NULL DEFAULT '',
    path_count   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_runs_scope ON runs (scope, id);

CREATE TABLE IF NOT EXISTS run_paths (
    run_id     INTEGER NOT NULL,
    path_key   TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    payload    TEXT NOT NULL,
    PRIMARY KEY (run_id, path_key)
);

CREATE INDEX IF NOT EXISTS idx_run_paths_run ON run_paths (run_id);
"""


def state_scope(intake: Intake) -> str:
    """Namespace for one reviewed system.

    The declared system name, case-folded, is the identity. It is the only
    stable handle a design review has: there is no repository, no package and no
    URL, and the file the intake happens to arrive in is named after whoever
    sent it.

    The cost is that renaming the system on the form starts a new history --
    ``rereview`` will report there is no previous review rather than comparing
    against one. That is the honest failure: comparing a renamed system against
    a different one would be worse, and it would be silent.
    """
    return hashlib.sha256(intake.system.casefold().encode("utf-8")).hexdigest()[:16]


class BaselineStore:
    """Persists runs and answers "what is new since last time"."""

    def __init__(
        self,
        path: str | Path = DEFAULT_STATE_PATH,
        *,
        scope: str = "default",
        retain: int = DEFAULT_RETAIN,
    ) -> None:
        self.path = Path(path).expanduser()
        self.scope = scope or "default"
        self.retain = max(2, int(retain))

    # ------------------------------------------------------------------

    def _assert_safe_parent(self) -> None:
        """Refuse a state path whose directory chain contains a symlink.

        ``O_NOFOLLOW`` applies to the final component only, and
        ``Path.mkdir(exist_ok=True)`` happily accepts a pre-existing
        symlink-to-directory because ``is_dir()`` follows links. The default
        ``state_path`` is relative, so in CI it lands inside the checked-out
        repository -- which is attacker-controlled content. A planted
        ``.entsec -> /tmp/attacker`` symlink therefore redirected the whole
        database, and the database is a complete map of the system's attack
        surface.
        """
        parent = self.path.parent
        resolved = parent.resolve()
        walker = parent
        seen: set[Path] = set()
        while walker not in seen:
            seen.add(walker)
            if walker.is_symlink():
                raise StateError(
                    f"{walker} is a symlink; refusing to write the baseline through it. "
                    "The baseline maps every entry point and credential store in the "
                    "system, so where it lands is a security decision."
                )
            if walker.parent == walker:
                break
            walker = walker.parent
        if parent.exists() and parent.resolve() != resolved:
            raise StateError(f"{parent} changed while being validated; refusing to continue")

    def _connect(self) -> sqlite3.Connection:
        try:
            self._assert_safe_parent()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_safe_parent()
            # Created at 0600 before sqlite touches it: this file holds a map of
            # every entry point, sink and credential store in the system, which
            # is a working attack plan for anyone who can read it. sqlite3
            # creates at 0644 and chmod-ing afterwards leaves a window.
            #
            # O_NOFOLLOW is checked on EVERY open, not only on creation. Testing
            # `if not path.exists()` first would be worse than useless, because
            # exists() follows symlinks -- a link aimed at an existing
            # attacker-owned file would report True, skip the guarded open, and
            # let sqlite follow it.
            try:
                os.close(
                    os.open(
                        self.path,
                        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                        0o600,
                    )
                )
            except FileExistsError:
                self._assert_regular_file()

            connection = sqlite3.connect(self.path, timeout=30.0)
            connection.execute("PRAGMA journal_mode=WAL")
            self._assert_version(connection)
            connection.executescript(_SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            connection.commit()
            return connection
        except (OSError, sqlite3.Error) as exc:
            raise StateError(f"cannot open baseline at {self.path}: {exc}") from exc

    def _assert_regular_file(self) -> None:
        """Confirm an existing baseline is a real file, checked through the fd."""
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)  # ELOOP on a symlink
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise StateError(f"{self.path} is not a regular file; refusing to open it")
            if info.st_mode & 0o077:
                os.fchmod(fd, 0o600)  # repaired through the descriptor, not the path
        finally:
            os.close(fd)

    @staticmethod
    def _assert_version(connection: sqlite3.Connection) -> None:
        # Checked BEFORE the schema script runs. Applying it first would fail
        # with "no such column", which tells an upgrading operator nothing.
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if not exists:
            return
        row = connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row and str(row[0]) != str(SCHEMA_VERSION):
            raise StateError(
                f"baseline at this path has schema version {row[0]}; this build understands "
                f"{SCHEMA_VERSION}. Move the file aside to start a fresh baseline."
            )

    # ------------------------------------------------------------------

    def previous(self) -> tuple[str, set[str]] | None:
        """The most recent run for this scope: (fingerprint, path keys)."""
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT id, fingerprint FROM runs WHERE scope = ? ORDER BY id DESC LIMIT 1",
                (self.scope,),
            ).fetchone()
            if not row:
                return None
            run_id, fingerprint = row[0], str(row[1])
            keys = {
                str(r[0])
                for r in connection.execute(
                    "SELECT path_key FROM run_paths WHERE run_id = ?", (run_id,)
                )
            }
            return fingerprint, keys

    def save(self, result: Review) -> int:
        """Record a run and prune old ones. Returns the run id."""
        fingerprint = result.intake.fingerprint()
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "INSERT INTO runs (scope, finished_at, fingerprint, model_id, path_count) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    self.scope,
                    result.reviewed_at,
                    fingerprint,
                    result.model_id,
                    len(result.findings),
                ),
            )
            run_id = int(cursor.lastrowid or 0)
            connection.executemany(
                "INSERT OR REPLACE INTO run_paths (run_id, path_key, severity, title, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        run_id,
                        path.key(),
                        path.severity.value,
                        path.title,
                        json.dumps(path.to_dict()),
                    )
                    for path in result.findings
                ],
            )
            self._prune(connection)
            connection.commit()
            return run_id

    def _prune(self, connection: sqlite3.Connection) -> None:
        """Drop runs beyond the retention window for this scope.

        Uses an id threshold rather than an IN-list: the list form builds SQL
        from a variable number of placeholders, which is both slower and the
        shape static analysis flags as dynamic SQL construction.
        """
        row = connection.execute(
            "SELECT id FROM runs WHERE scope = ? ORDER BY id DESC LIMIT 1 OFFSET ?",
            (self.scope, self.retain),
        ).fetchone()
        if not row:
            return
        threshold = int(row[0])
        connection.execute(
            "DELETE FROM run_paths WHERE run_id IN "
            "(SELECT id FROM runs WHERE scope = ? AND id <= ?)",
            (self.scope, threshold),
        )
        connection.execute("DELETE FROM runs WHERE scope = ? AND id <= ?", (self.scope, threshold))


def apply_baseline(result: Review, store: BaselineStore) -> None:
    """Mark which findings are new, in place.

    A first run marks nothing as new. Reporting every finding as newly
    introduced on the first review would be technically true and completely
    useless, and it teaches the reader that the "new" marker means nothing.
    """
    previous = store.previous()
    if previous is None:
        result.baseline_available = False
        return

    fingerprint, known_keys = previous
    result.baseline_available = True
    result.baseline_fingerprint = fingerprint
    result.new_finding_keys = {f.key() for f in result.findings if f.key() not in known_keys}

    if fingerprint == result.intake.fingerprint():
        # The same declared design as last time. Any difference in the findings
        # is analysis variation, not new exposure, and saying so is more honest
        # than presenting it as a change to the system.
        result.notes.append(
            "The declared design is unchanged since the last review "
            f"(fingerprint {fingerprint}). Differences below reflect analysis variation, "
            "not a change to the design."
        )
    elif result.new_finding_keys:
        result.notes.append(
            f"The declared design changed since the last review ({fingerprint} → "
            f"{result.intake.fingerprint()}); {len(result.new_finding_keys)} finding(s) are new."
        )
