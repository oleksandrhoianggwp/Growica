"""SQLite persistence for batches, submissions and individual submission attempts."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

STATUSES = ("pending", "processing", "submitted", "failed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT NOT NULL,
    submission_type TEXT NOT NULL,
    threat_type     TEXT NOT NULL,
    reason          TEXT NOT NULL,
    attachment_path TEXT,
    attachment_name TEXT
);
CREATE TABLE IF NOT EXISTS submissions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id          INTEGER NOT NULL REFERENCES batches(id),
    line_no           INTEGER NOT NULL,
    submission_type   TEXT NOT NULL,
    target            TEXT NOT NULL,
    threat_type       TEXT NOT NULL,
    reason            TEXT NOT NULL,
    attachment_path   TEXT,
    attachment_name   TEXT,
    dedup_key         TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'submitted', 'failed')),
    progress          TEXT,
    confirmation_code TEXT,
    error             TEXT,
    outcome_uncertain INTEGER NOT NULL DEFAULT 0,
    force_resubmit    INTEGER NOT NULL DEFAULT 0,
    attempts          INTEGER NOT NULL DEFAULT 0,
    auto_attempts     INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    last_attempt_at   TEXT,
    submitted_at      TEXT
);
CREATE INDEX IF NOT EXISTS ix_submissions_dedup ON submissions (dedup_key, status);
CREATE INDEX IF NOT EXISTS ix_submissions_batch ON submissions (batch_id);
CREATE TABLE IF NOT EXISTS attempts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id     INTEGER NOT NULL REFERENCES submissions(id),
    attempt_no        INTEGER NOT NULL,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    outcome           TEXT,
    confirmation_code TEXT,
    error             TEXT,
    response_snapshot TEXT
);
CREATE INDEX IF NOT EXISTS ix_attempts_submission ON attempts (submission_id);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class NewSubmission:
    line_no: int
    target: str
    dedup_key: str


class Database:
    """Thin thread-safe wrapper around a single SQLite connection."""

    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def _one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def _all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ batches
    def create_batch(
        self,
        *,
        submission_type: str,
        threat_type: str,
        reason: str,
        attachment_path: str | None,
        attachment_name: str | None,
        items: list[NewSubmission],
        allow_resubmit: bool,
    ) -> tuple[int, list[int], list[dict[str, Any]]]:
        """Create a batch and its submissions atomically.

        Returns (batch_id, created_submission_ids, skipped_duplicates). A target is skipped when a
        submission with the same dedup key is pending/processing, or already submitted (unless
        allow_resubmit is set).
        """
        now = utcnow()
        created: list[int] = []
        skipped: list[dict[str, Any]] = []
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO batches (created_at, submission_type, threat_type, reason, attachment_path, attachment_name)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (now, submission_type, threat_type, reason, attachment_path, attachment_name),
            )
            batch_id = int(cur.lastrowid)
            for item in items:
                blocking = ("pending", "processing") if allow_resubmit else ("pending", "processing", "submitted")
                placeholders = ",".join("?" * len(blocking))
                existing = conn.execute(
                    f"SELECT id, status, confirmation_code FROM submissions WHERE dedup_key = ? AND status IN ({placeholders})"
                    " ORDER BY id DESC LIMIT 1",
                    (item.dedup_key, *blocking),
                ).fetchone()
                if existing:
                    skipped.append(
                        {
                            "line_no": item.line_no,
                            "target": item.target,
                            "existing_id": existing["id"],
                            "existing_status": existing["status"],
                            "confirmation_code": existing["confirmation_code"],
                        }
                    )
                    continue
                cur = conn.execute(
                    "INSERT INTO submissions (batch_id, line_no, submission_type, target, threat_type, reason,"
                    " attachment_path, attachment_name, dedup_key, force_resubmit, status, progress, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'Queued', ?, ?)",
                    (
                        batch_id,
                        item.line_no,
                        submission_type,
                        item.target,
                        threat_type,
                        reason,
                        attachment_path,
                        attachment_name,
                        item.dedup_key,
                        int(allow_resubmit),
                        now,
                        now,
                    ),
                )
                created.append(int(cur.lastrowid))
        return batch_id, created, skipped

    def get_batch(self, batch_id: int) -> dict[str, Any] | None:
        return self._one("SELECT * FROM batches WHERE id = ?", (batch_id,))

    def list_batches(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._all(
            "SELECT b.*,"
            " SUM(s.status = 'pending') AS pending, SUM(s.status = 'processing') AS processing,"
            " SUM(s.status = 'submitted') AS submitted, SUM(s.status = 'failed') AS failed, COUNT(s.id) AS total"
            " FROM batches b LEFT JOIN submissions s ON s.batch_id = b.id"
            " GROUP BY b.id ORDER BY b.id DESC LIMIT ?",
            (limit,),
        )

    # -------------------------------------------------------------- submissions
    def get_submission(self, submission_id: int) -> dict[str, Any] | None:
        return self._one("SELECT * FROM submissions WHERE id = ?", (submission_id,))

    def list_submissions(
        self, *, batch_id: int | None = None, status: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM submissions WHERE 1 = 1"
        params: list[Any] = []
        if batch_id is not None:
            sql += " AND batch_id = ?"
            params.append(batch_id)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY id DESC LIMIT ?" if batch_id is None else " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        return self._all(sql, tuple(params))

    def ids_with_status(self, status: str) -> list[int]:
        return [r["id"] for r in self._all("SELECT id FROM submissions WHERE status = ? ORDER BY id", (status,))]

    def count_active(self) -> int:
        row = self._one("SELECT COUNT(*) AS n FROM submissions WHERE status IN ('pending', 'processing')")
        return int(row["n"]) if row else 0

    def set_progress(self, submission_id: int, progress: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE submissions SET progress = ?, updated_at = ? WHERE id = ?",
                (progress, utcnow(), submission_id),
            )

    def start_attempt(self, submission_id: int) -> int | None:
        """Move a pending submission to processing. Returns the attempt row id, or None if it was not pending."""
        now = utcnow()
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE submissions SET status = 'processing', progress = 'Starting', error = NULL,"
                " attempts = attempts + 1, auto_attempts = auto_attempts + 1, last_attempt_at = ?, updated_at = ?"
                " WHERE id = ? AND status = 'pending'",
                (now, now, submission_id),
            )
            if cur.rowcount != 1:
                return None
            attempts = conn.execute("SELECT attempts FROM submissions WHERE id = ?", (submission_id,)).fetchone()[0]
            cur = conn.execute(
                "INSERT INTO attempts (submission_id, attempt_no, started_at) VALUES (?, ?, ?)",
                (submission_id, attempts, now),
            )
            return int(cur.lastrowid)

    def finish_attempt(
        self,
        submission_id: int,
        attempt_id: int,
        *,
        status: str,
        confirmation_code: str | None,
        error: str | None,
        outcome_uncertain: bool,
        progress: str,
        response_snapshot: str | None,
    ) -> None:
        if status not in ("pending", "submitted", "failed"):
            raise ValueError(f"invalid final status {status!r}")
        now = utcnow()
        with self.transaction() as conn:
            conn.execute(
                "UPDATE submissions SET status = ?, confirmation_code = ?, error = ?, outcome_uncertain = ?,"
                " progress = ?, updated_at = ?, submitted_at = CASE WHEN ? = 'submitted' THEN ? ELSE submitted_at END"
                " WHERE id = ?",
                (
                    status,
                    confirmation_code,
                    error,
                    int(outcome_uncertain),
                    progress,
                    now,
                    status,
                    now,
                    submission_id,
                ),
            )
            conn.execute(
                "UPDATE attempts SET finished_at = ?, outcome = ?, confirmation_code = ?, error = ?, response_snapshot = ?"
                " WHERE id = ?",
                (
                    now,
                    "retry_scheduled" if status == "pending" else status,
                    confirmation_code,
                    error,
                    response_snapshot,
                    attempt_id,
                ),
            )

    def requeue_for_retry(self, submission_id: int) -> bool:
        """Manual retry: failed -> pending. Resets the automatic-attempt counter."""
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE submissions SET status = 'pending', progress = 'Queued (retry)', auto_attempts = 0,"
                " outcome_uncertain = 0, updated_at = ? WHERE id = ? AND status = 'failed'",
                (utcnow(), submission_id),
            )
            return cur.rowcount == 1

    def has_active_duplicate(self, submission_id: int, dedup: str) -> dict[str, Any] | None:
        return self._one(
            "SELECT id, status, confirmation_code FROM submissions"
            " WHERE dedup_key = ? AND id != ? AND status IN ('pending', 'processing', 'submitted')"
            " ORDER BY id DESC LIMIT 1",
            (dedup, submission_id),
        )

    def recover_interrupted(self) -> list[int]:
        """After a restart, rows stuck in 'processing' may or may not have reached the site."""
        now = utcnow()
        with self.transaction() as conn:
            rows = conn.execute("SELECT id FROM submissions WHERE status = 'processing'").fetchall()
            ids = [r["id"] for r in rows]
            conn.execute(
                "UPDATE submissions SET status = 'failed', outcome_uncertain = 1, progress = 'Interrupted',"
                " error = 'The application stopped while this submission was in progress; it is unknown whether"
                " the form was sent. Check before retrying.', updated_at = ? WHERE status = 'processing'",
                (now,),
            )
            conn.execute(
                "UPDATE attempts SET finished_at = ?, outcome = 'interrupted' WHERE finished_at IS NULL", (now,)
            )
        return ids

    def list_attempts(self, submission_id: int) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM attempts WHERE submission_id = ? ORDER BY id", (submission_id,))
