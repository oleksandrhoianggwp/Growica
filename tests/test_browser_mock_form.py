"""End-to-end Playwright test against a local replica of the real form markup (tests/fixtures/mock_form.html).

Nothing here talks to the real site: the replica is served from 127.0.0.1, the CAPTCHA solver is a stub
and the replica's /submit endpoint is a mock that returns a CF- code.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from formbot.captcha import CaptchaRequest, CaptchaSolution
from formbot.submitter import PlaywrightSubmitter, SubmissionJob

from .conftest import PNG_BYTES

FIXTURE = Path(__file__).parent / "fixtures" / "mock_form.html"
GOOD_TOKEN = "stub-recaptcha-token"


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            return Path(p.chromium.executable_path).exists()
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _chromium_available(), reason="Playwright Chromium is not installed")


def build_mock_site(received: list[dict]) -> FastAPI:
    app = FastAPI()
    template = FIXTURE.read_text(encoding="utf-8")
    tokens: set[str] = set()

    def render(alert: str = "") -> HTMLResponse:
        token = secrets.token_urlsafe(16)
        tokens.add(token)
        return HTMLResponse(template.replace("{{FORM_TOKEN}}", token).replace("{{ALERT}}", alert))

    @app.get("/")
    async def form() -> HTMLResponse:
        return render()

    @app.post("/submit")
    async def submit(request: Request) -> HTMLResponse:
        data = await request.form()
        fields = {k: v for k, v in data.items() if k != "attachment"}
        upload = data.get("attachment")
        fields["attachment_name"] = getattr(upload, "filename", None) or None
        fields["attachment_size"] = len(await upload.read()) if hasattr(upload, "read") else 0
        received.append(fields)
        errors = []
        if fields.get("form_token") not in tokens:
            errors.append("Your session expired, please try again.")
        if fields.get("website"):
            errors.append("Spam detected.")
        if fields.get("g-recaptcha-response") != GOOD_TOKEN:
            errors.append("CAPTCHA verification failed.")
        if fields.get("accept_terms") != "1":
            errors.append("You must accept the terms.")
        kind = fields.get("submission_type")
        if not fields.get(kind or ""):
            errors.append("Target is required.")
        if fields.get(kind or "") == "rejected.example":
            errors.append("This domain cannot be reported.")
        if errors:
            return render('<div class="alert">' + " ".join(errors) + "</div>")
        tokens.discard(fields["form_token"])
        return HTMLResponse("<html><body><main><h1>Thank you</h1><p>Your confirmation code is "
                            "<b class='mono'>CF-7Q2K9ZXA</b>.</p></main></body></html>")

    return app


@pytest.fixture(scope="module")
def mock_site():
    received: list[dict] = []
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(build_mock_site(received), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/", received
    server.should_exit = True
    thread.join(timeout=5)


class StubSolver:
    name = "stub"

    def __init__(self, token: str = GOOD_TOKEN):
        self.token = token
        self.requests: list[CaptchaRequest] = []
        self.bad: list[CaptchaSolution] = []
        self.good: list[CaptchaSolution] = []

    async def solve(self, request: CaptchaRequest) -> CaptchaSolution:
        self.requests.append(request)
        return CaptchaSolution(token=self.token, task_id="1", provider=self.name)

    async def report_bad(self, solution):
        self.bad.append(solution)

    async def report_good(self, solution):
        self.good.append(solution)

    async def aclose(self):
        return None


async def _noop(_text: str) -> None:
    return None


def _run(coro):
    return asyncio.run(coro)


async def _submit(url: str, solver, job: SubmissionJob, tmp_path: Path, dry_run: bool = False):
    submitter = PlaywrightSubmitter(form_url=url, solver=solver, headless=True, navigation_timeout=20,
                                    action_timeout=10, submit_result_timeout=20, dry_run=dry_run,
                                    snapshot_dir=tmp_path / "responses")
    try:
        return await submitter.submit(job, _noop)
    finally:
        await submitter.close()


@pytest.mark.parametrize("kind,target", [("domain", "evil.example"), ("ip", "192.0.2.55"),
                                         ("url", "https://evil.example/login?x=1")])
def test_fills_and_submits_each_type(mock_site, tmp_path, kind, target):
    url, received = mock_site
    attachment = tmp_path / "evidence.png"
    attachment.write_bytes(PNG_BYTES)
    solver = StubSolver()
    job = SubmissionJob(1, kind, target, "Botnet C&C", "Hosting a C&C panel", str(attachment))
    result = _run(_submit(url, solver, job, tmp_path))
    assert result.status == "submitted", result.error
    assert result.confirmation_code == "CF-7Q2K9ZXA"
    assert result.response_snapshot and Path(result.response_snapshot).exists()
    sent = received[-1]
    assert sent["submission_type"] == kind
    assert sent[kind] == target
    assert sent["threat_type"] == "Botnet C&C"
    assert sent["reason"] == "Hosting a C&C panel"
    assert sent["accept_terms"] == "1"
    assert sent["website"] == ""  # honeypot left empty
    assert sent["attachment_name"] == "evidence.png" and sent["attachment_size"] == len(PNG_BYTES)
    assert solver.requests[0].site_key == "6LfiehouAAAAAFr7759Kztp8FRrwjs0BRxuMZP28"
    assert solver.good


def test_rejected_captcha_is_reported_and_retryable(mock_site, tmp_path):
    url, _ = mock_site
    solver = StubSolver(token="wrong")
    job = SubmissionJob(2, "domain", "evil.example", "Spam", "spam")
    result = _run(_submit(url, solver, job, tmp_path))
    assert result.status == "failed" and result.retryable
    assert "CAPTCHA verification failed" in result.error
    assert result.confirmation_code is None
    assert solver.bad


def test_site_validation_error_is_shown(mock_site, tmp_path):
    url, _ = mock_site
    job = SubmissionJob(3, "domain", "rejected.example", "Spam", "spam")
    result = _run(_submit(url, StubSolver(), job, tmp_path))
    assert result.status == "failed" and not result.retryable
    assert "This domain cannot be reported." in result.error


def test_dry_run_never_submits(mock_site, tmp_path):
    url, received = mock_site
    before = len(received)
    solver = StubSolver()
    job = SubmissionJob(4, "ip", "192.0.2.1", "Malware", "malware")
    result = _run(_submit(url, solver, job, tmp_path, dry_run=True))
    assert result.status == "failed" and "DRY_RUN" in result.error
    assert len(received) == before and not solver.requests


def test_unreachable_site(tmp_path):
    job = SubmissionJob(5, "domain", "evil.example", "Spam", "spam")
    result = _run(_submit("http://127.0.0.1:9/", StubSolver(), job, tmp_path))
    assert result.status == "failed" and result.retryable and not result.outcome_uncertain
