"""Background queue that processes submissions strictly one at a time."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable

from .db import Database
from .submitter import SubmissionJob, SubmissionResult, Submitter

log = logging.getLogger(__name__)


class SubmissionWorker:
    def __init__(
        self,
        db: Database,
        submitter: Submitter,
        *,
        min_submit_interval: float = 10.0,
        max_auto_attempts: int = 2,
        submission_timeout: float = 420.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.db = db
        self.submitter = submitter
        self.min_submit_interval = min_submit_interval
        self.max_auto_attempts = max_auto_attempts
        self.submission_timeout = submission_timeout
        self._clock = clock
        self._queue: asyncio.Queue[int] = asyncio.Queue()
        self._queued: set[int] = set()
        self._task: asyncio.Task[None] | None = None
        self._last_attempt_at: float | None = None
        self.current_id: int | None = None

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        interrupted = self.db.recover_interrupted()
        if interrupted:
            log.warning("marked interrupted submissions as failed", extra={"ids": interrupted})
        for submission_id in self.db.ids_with_status("pending"):
            self.enqueue(submission_id)
        self._task = asyncio.create_task(self._run(), name="submission-worker")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self.submitter.close()

    def enqueue(self, submission_id: int) -> None:
        if submission_id in self._queued:
            return
        self._queued.add(submission_id)
        self._queue.put_nowait(submission_id)

    @property
    def queue_length(self) -> int:
        return self._queue.qsize()

    async def wait_idle(self) -> None:
        """Wait until every queued submission has been handled (used by tests)."""
        await self._queue.join()

    # ------------------------------------------------------------------ processing
    async def _run(self) -> None:
        while True:
            submission_id = await self._queue.get()
            try:
                self._queued.discard(submission_id)
                await self._process(submission_id)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the worker must survive any single failure
                log.exception("unexpected error while processing submission", extra={"submission_id": submission_id})
            finally:
                self.current_id = None
                self._queue.task_done()

    async def _respect_rate_limit(self, submission_id: int) -> None:
        if self._last_attempt_at is None or self.min_submit_interval <= 0:
            return
        wait = self._last_attempt_at + self.min_submit_interval - self._clock()
        if wait > 0:
            self.db.set_progress(submission_id, f"Waiting {wait:.0f}s (rate limit)")
            await asyncio.sleep(wait)

    async def _process(self, submission_id: int) -> None:
        row = self.db.get_submission(submission_id)
        if row is None or row["status"] != "pending":
            return
        duplicate = self.db.has_active_duplicate(submission_id, row["dedup_key"])
        if duplicate and (
            duplicate["status"] == "processing" or (duplicate["status"] == "submitted" and not row["force_resubmit"])
        ):
            # Another row with the same report is in flight or already accepted: do not send it twice.
            attempt_id = self.db.start_attempt(submission_id)
            if attempt_id is not None:
                code = duplicate.get("confirmation_code")
                self.db.finish_attempt(
                    submission_id,
                    attempt_id,
                    status="failed",
                    confirmation_code=None,
                    error=f"Duplicate of submission #{duplicate['id']} ({duplicate['status']}"
                    + (f", {code}" if code else "")
                    + "); not sent again.",
                    outcome_uncertain=False,
                    progress="Skipped (duplicate)",
                    response_snapshot=None,
                )
            return

        await self._respect_rate_limit(submission_id)
        attempt_id = self.db.start_attempt(submission_id)
        if attempt_id is None:
            return
        self.current_id = submission_id
        self._last_attempt_at = self._clock()
        row = self.db.get_submission(submission_id) or row
        job = SubmissionJob(
            submission_id=submission_id,
            submission_type=row["submission_type"],
            target=row["target"],
            threat_type=row["threat_type"],
            reason=row["reason"],
            attachment_path=row["attachment_path"],
        )
        log.info("processing submission", extra={"submission_id": submission_id, "target": job.target, "attempt": row["attempts"]})

        async def progress(text: str) -> None:
            self.db.set_progress(submission_id, text)

        try:
            result = await asyncio.wait_for(self.submitter.submit(job, progress), timeout=self.submission_timeout)
        except asyncio.TimeoutError:
            result = SubmissionResult(
                status="failed",
                error=f"The submission did not finish within {self.submission_timeout:.0f}s; outcome unknown.",
                outcome_uncertain=True,
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("submitter crashed", extra={"submission_id": submission_id})
            result = SubmissionResult(status="failed", error=f"Internal error: {exc.__class__.__name__}: {exc}")
        finally:
            self._last_attempt_at = self._clock()

        self._record(submission_id, attempt_id, row["auto_attempts"], result)

    def _record(self, submission_id: int, attempt_id: int, auto_attempts: int, result: SubmissionResult) -> None:
        auto_retry = (
            result.status == "failed"
            and result.retryable
            and not result.outcome_uncertain
            and auto_attempts < self.max_auto_attempts
        )
        if result.status == "submitted":
            progress = "Done" if result.confirmation_code else "Done (no code shown)"
            error = result.note
        elif auto_retry:
            progress = f"Retrying automatically ({auto_attempts}/{self.max_auto_attempts} failed): {result.error}"
            error = result.error
        else:
            progress = "Outcome unknown" if result.outcome_uncertain else "Failed"
            error = result.error
        self.db.finish_attempt(
            submission_id,
            attempt_id,
            status="pending" if auto_retry else result.status,
            confirmation_code=result.confirmation_code,
            error=error,
            outcome_uncertain=result.outcome_uncertain,
            progress=progress,
            response_snapshot=result.response_snapshot,
        )
        log.info(
            "submission finished",
            extra={
                "submission_id": submission_id,
                "status": result.status,
                "confirmation_code": result.confirmation_code,
                "error": result.error,
                "auto_retry": auto_retry,
                "uncertain": result.outcome_uncertain,
            },
        )
        if auto_retry:
            self.enqueue(submission_id)
