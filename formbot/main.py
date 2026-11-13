"""FastAPI application: web UI, batch creation, status polling and retries."""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, form_spec
from .captcha import CaptchaError, CaptchaSolver, ManualCaptchaSolver, TwoCaptchaSolver
from .config import Settings, get_settings
from .db import Database, NewSubmission
from .submitter import PlaywrightSubmitter, Submitter
from .validation import (
    ValidationError,
    dedup_key,
    parse_targets,
    validate_attachment,
    validate_reason,
    validate_threat_type,
)
from .worker import SubmissionWorker

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"


def build_solver(settings: Settings) -> CaptchaSolver | None:
    if settings.captcha_provider == "manual":
        return ManualCaptchaSolver(timeout=settings.captcha_solve_timeout)
    if not settings.twocaptcha_api_key.strip():
        return None
    return TwoCaptchaSolver(
        settings.twocaptcha_api_key.strip(),
        api_url=settings.twocaptcha_api_url,
        poll_interval=settings.captcha_poll_interval,
        timeout=settings.captcha_solve_timeout,
    )


def build_submitter(settings: Settings, solver: CaptchaSolver | None) -> Submitter:
    return PlaywrightSubmitter(
        form_url=settings.form_url,
        solver=solver,
        headless=settings.headless,
        navigation_timeout=settings.navigation_timeout,
        action_timeout=settings.action_timeout,
        submit_result_timeout=settings.submit_result_timeout,
        dry_run=settings.dry_run,
        snapshot_dir=settings.snapshot_dir,
        captcha_config_error=settings.captcha_config_error(),
    )


def public_submission(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "batch_id": row["batch_id"],
        "line_no": row["line_no"],
        "submission_type": row["submission_type"],
        "target": row["target"],
        "threat_type": row["threat_type"],
        "status": row["status"],
        "progress": row["progress"],
        "confirmation_code": row["confirmation_code"],
        "error": row["error"],
        "outcome_uncertain": bool(row["outcome_uncertain"]),
        "attempts": row["attempts"],
        "attachment_name": row["attachment_name"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "submitted_at": row["submitted_at"],
    }


def create_app(
    settings: Settings | None = None,
    submitter_factory: Callable[[Settings, CaptchaSolver | None], Submitter] | None = None,
    solver_factory: Callable[[Settings], CaptchaSolver | None] | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    submitter_factory = submitter_factory or build_submitter
    solver_factory = solver_factory or build_solver

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        settings.upload_dir.mkdir(parents=True, exist_ok=True)
        db = Database(settings.db_path)
        solver = solver_factory(settings)
        submitter = submitter_factory(settings, solver)
        worker = SubmissionWorker(
            db,
            submitter,
            min_submit_interval=settings.min_submit_interval,
            max_auto_attempts=settings.max_auto_attempts,
            submission_timeout=settings.submission_timeout,
        )
        app.state.settings = settings
        app.state.db = db
        app.state.solver = solver
        app.state.worker = worker
        problem = settings.captcha_config_error()
        log.info(
            "starting",
            extra={
                "version": __version__,
                "form_url": settings.form_url,
                "captcha_provider": settings.captcha_provider,
                "dry_run": settings.dry_run,
                "config_problem": problem,
            },
        )
        if problem:
            log.warning("captcha configuration problem", extra={"problem": problem})
        await worker.start()
        try:
            yield
        finally:
            await worker.stop()
            if solver is not None:
                await solver.aclose()
            db.close()
            log.info("stopped")

    app = FastAPI(title="Growica report submitter", version=__version__, lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [f"{'.'.join(str(p) for p in e['loc'][1:]) or 'request'}: {e['msg']}" for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": "Invalid request", "errors": errors})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"path": request.url.path})
        return JSONResponse(status_code=500, content={"detail": "Internal server error", "errors": [str(exc)]})

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health")
    async def health(request: Request) -> dict[str, Any]:
        s: Settings = request.app.state.settings
        worker: SubmissionWorker = request.app.state.worker
        return {
            "status": "ok",
            "version": __version__,
            "form_url": s.form_url,
            "captcha_provider": s.captcha_provider,
            "captcha_ready": s.captcha_config_error() is None,
            "config_problem": s.captcha_config_error(),
            "dry_run": s.dry_run,
            "queue_length": worker.queue_length,
            "current_submission": worker.current_id,
            "min_submit_interval": s.min_submit_interval,
        }

    @app.get("/api/options")
    async def options() -> dict[str, Any]:
        return {
            "submission_types": [{"value": k, "label": v["label"]} for k, v in form_spec.SUBMISSION_TYPES.items()],
            "threat_types": form_spec.THREAT_TYPES,
            "reason_max_length": form_spec.REASON_MAX_LENGTH,
            "attachment_extensions": sorted(form_spec.ATTACHMENT_EXTENSIONS),
            "attachment_max_bytes": form_spec.ATTACHMENT_MAX_BYTES,
            "max_targets_per_batch": settings.max_targets_per_batch,
        }

    @app.get("/api/captcha/balance")
    async def captcha_balance(request: Request) -> dict[str, Any]:
        solver = request.app.state.solver
        if not isinstance(solver, TwoCaptchaSolver):
            raise HTTPException(400, detail="Balance is only available with CAPTCHA_PROVIDER=2captcha and an API key.")
        try:
            return {"provider": "2captcha", "balance": await solver.balance()}
        except CaptchaError as exc:
            raise HTTPException(502, detail=str(exc)) from exc

    @app.post("/api/batches", status_code=201)
    async def create_batch(
        request: Request,
        submission_type: str = Form(...),
        targets: str = Form(...),
        threat_type: str = Form(...),
        reason: str = Form(...),
        allow_resubmit: bool = Form(False),
        attachment: UploadFile | None = File(None),
    ) -> dict[str, Any]:
        s: Settings = request.app.state.settings
        db: Database = request.app.state.db
        worker: SubmissionWorker = request.app.state.worker

        errors: list[str] = []
        if submission_type not in form_spec.SUBMISSION_TYPES:
            errors.append("Submission type must be Domain, IP or URL.")
        try:
            threat_type = validate_threat_type(threat_type)
        except ValidationError as exc:
            errors.append(f"Threat type: {exc}")
        try:
            reason = validate_reason(reason)
        except ValidationError as exc:
            errors.append(f"Reason: {exc}")
        parsed, target_errors = parse_targets(targets, submission_type, s.max_targets_per_batch)
        errors += [f"Targets: {e}" for e in target_errors]

        attachment_bytes: bytes | None = None
        safe_name: str | None = None
        if attachment is not None and attachment.filename:
            attachment_bytes = await attachment.read(form_spec.ATTACHMENT_MAX_BYTES + 1)
            try:
                safe_name = validate_attachment(attachment.filename, attachment_bytes)
            except ValidationError as exc:
                errors.append(f"Attachment: {exc}")
        if errors:
            raise HTTPException(422, detail={"detail": "Please fix the highlighted problems.", "errors": errors})
        if db.count_active() + len(parsed) > s.max_queue_size:
            raise HTTPException(429, detail="The queue is full. Wait for current submissions to finish.")

        attachment_path: str | None = None
        if attachment_bytes is not None and safe_name:
            folder = s.upload_dir / f"{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:12]}"
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / safe_name
            path.write_bytes(attachment_bytes)
            attachment_path = str(path)

        batch_id, created, skipped = db.create_batch(
            submission_type=submission_type,
            threat_type=threat_type,
            reason=reason,
            attachment_path=attachment_path,
            attachment_name=safe_name,
            items=[NewSubmission(t.line_no, t.value, dedup_key(submission_type, t.value, threat_type)) for t in parsed],
            allow_resubmit=allow_resubmit,
        )
        for submission_id in created:
            worker.enqueue(submission_id)
        log.info("batch created", extra={"batch_id": batch_id, "queued": len(created), "skipped": len(skipped)})
        return {
            "batch_id": batch_id,
            "queued": len(created),
            "skipped_duplicates": skipped,
            "submissions": [public_submission(r) for r in db.list_submissions(batch_id=batch_id)],
        }

    @app.get("/api/batches")
    async def list_batches(request: Request, limit: int = 50) -> list[dict[str, Any]]:
        db: Database = request.app.state.db
        return [
            {k: row[k] for k in ("id", "created_at", "submission_type", "threat_type", "attachment_name", "pending",
                                 "processing", "submitted", "failed", "total")}
            for row in db.list_batches(limit=max(1, min(limit, 500)))
        ]

    @app.get("/api/batches/{batch_id}")
    async def get_batch(request: Request, batch_id: int) -> dict[str, Any]:
        db: Database = request.app.state.db
        batch = db.get_batch(batch_id)
        if batch is None:
            raise HTTPException(404, detail="Batch not found")
        return {
            "id": batch["id"],
            "created_at": batch["created_at"],
            "submission_type": batch["submission_type"],
            "threat_type": batch["threat_type"],
            "reason": batch["reason"],
            "attachment_name": batch["attachment_name"],
            "submissions": [public_submission(r) for r in db.list_submissions(batch_id=batch_id, limit=10000)],
        }

    @app.get("/api/submissions")
    async def list_submissions(request: Request, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        db: Database = request.app.state.db
        if status is not None and status not in ("pending", "processing", "submitted", "failed"):
            raise HTTPException(422, detail="Unknown status filter")
        return [public_submission(r) for r in db.list_submissions(status=status, limit=max(1, min(limit, 1000)))]

    @app.get("/api/submissions/{submission_id}")
    async def get_submission(request: Request, submission_id: int) -> dict[str, Any]:
        db: Database = request.app.state.db
        row = db.get_submission(submission_id)
        if row is None:
            raise HTTPException(404, detail="Submission not found")
        data = public_submission(row)
        data["reason"] = row["reason"]
        data["attempt_history"] = [
            {k: a[k] for k in ("attempt_no", "started_at", "finished_at", "outcome", "confirmation_code", "error")}
            for a in db.list_attempts(submission_id)
        ]
        return data

    def _retry_one(request: Request, submission_id: int, confirm_uncertain: bool) -> dict[str, Any]:
        s: Settings = request.app.state.settings
        db: Database = request.app.state.db
        worker: SubmissionWorker = request.app.state.worker
        row = db.get_submission(submission_id)
        if row is None:
            raise HTTPException(404, detail="Submission not found")
        if row["status"] != "failed":
            raise HTTPException(409, detail=f"Only failed submissions can be retried (this one is {row['status']}).")
        if row["outcome_uncertain"] and not confirm_uncertain:
            raise HTTPException(
                409,
                detail="The previous attempt may have reached the site. Confirm the retry to accept the risk of a duplicate report.",
            )
        if row["attempts"] >= s.max_total_attempts:
            raise HTTPException(429, detail=f"Retry limit reached ({s.max_total_attempts} attempts).")
        if row["last_attempt_at"]:
            last = datetime.fromisoformat(row["last_attempt_at"])
            elapsed = (datetime.now(timezone.utc) - last).total_seconds()
            if elapsed < s.retry_cooldown:
                raise HTTPException(429, detail=f"Please wait {s.retry_cooldown - elapsed:.0f}s before retrying this target.")
        duplicate = db.has_active_duplicate(submission_id, row["dedup_key"])
        if duplicate and not (duplicate["status"] == "submitted" and row["force_resubmit"]):
            code = f" ({duplicate['confirmation_code']})" if duplicate.get("confirmation_code") else ""
            raise HTTPException(
                409, detail=f"Not retried: submission #{duplicate['id']} for the same target is {duplicate['status']}{code}."
            )
        if not db.requeue_for_retry(submission_id):
            raise HTTPException(409, detail="The submission changed state; refresh and try again.")
        worker.enqueue(submission_id)
        log.info("manual retry queued", extra={"submission_id": submission_id})
        return public_submission(db.get_submission(submission_id) or row)

    @app.post("/api/submissions/{submission_id}/retry")
    async def retry_submission(request: Request, submission_id: int, confirm_uncertain: bool = False) -> dict[str, Any]:
        return _retry_one(request, submission_id, confirm_uncertain)

    @app.post("/api/batches/{batch_id}/retry-failed")
    async def retry_batch(request: Request, batch_id: int, confirm_uncertain: bool = False) -> dict[str, Any]:
        db: Database = request.app.state.db
        if db.get_batch(batch_id) is None:
            raise HTTPException(404, detail="Batch not found")
        retried: list[int] = []
        not_retried: list[dict[str, Any]] = []
        for row in db.list_submissions(batch_id=batch_id, status="failed", limit=10000):
            try:
                _retry_one(request, row["id"], confirm_uncertain)
                retried.append(row["id"])
            except HTTPException as exc:
                not_retried.append({"id": row["id"], "target": row["target"], "reason": exc.detail})
        return {"retried": retried, "not_retried": not_retried}

    return app
