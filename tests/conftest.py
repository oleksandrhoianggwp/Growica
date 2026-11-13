from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Callable

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from formbot.config import Settings  # noqa: E402
from formbot.submitter import ProgressCallback, SubmissionJob, SubmissionResult  # noqa: E402

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
PDF_BYTES = b"%PDF-1.4\n%test\n"


class FakeSubmitter:
    """Mocked submitter: never touches the network. Results are scripted per target."""

    def __init__(self, script: Callable[[SubmissionJob, int], SubmissionResult] | None = None, delay: float = 0.0):
        self.calls: list[SubmissionJob] = []
        self.script = script or (lambda job, n: SubmissionResult(status="submitted", confirmation_code=f"CF-{n:08d}"))
        self.delay = delay
        self.started = False
        self.closed = False

    async def start(self) -> None:
        self.started = True

    async def close(self) -> None:
        self.closed = True

    async def submit(self, job: SubmissionJob, progress: ProgressCallback) -> SubmissionResult:
        self.calls.append(job)
        await progress("Fake submitting")
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.script(job, len(self.calls))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        twocaptcha_api_key="test-key",
        min_submit_interval=0,
        retry_cooldown=0,
        max_auto_attempts=2,
        log_format="text",
    )
