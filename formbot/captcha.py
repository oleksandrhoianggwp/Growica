"""reCAPTCHA v2 solving.

* TwoCaptchaSolver: sends the page URL + site key to the 2captcha API and receives a response token
  (createTask / getTaskResult, task type RecaptchaV2TaskProxyless).
* ManualCaptchaSolver: an operator ticks the reCAPTCHA in a visible browser window; the tool waits
  until the widget has produced a token.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol

import httpx

from . import form_spec

log = logging.getLogger(__name__)

# 2captcha error codes that will not go away by retrying.
_FATAL_2CAPTCHA_ERRORS = {
    "ERROR_KEY_DOES_NOT_EXIST",
    "ERROR_WRONG_USER_KEY",
    "ERROR_ZERO_BALANCE",
    "ERROR_IP_NOT_ALLOWED",
    "IP_BANNED",
    "ERROR_GOOGLEKEY",
    "ERROR_PAGEURL",
    "ERROR_TASK_NOT_SUPPORTED",
}


class CaptchaError(Exception):
    def __init__(self, message: str, *, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class CaptchaRequest:
    website_url: str
    site_key: str
    user_agent: str | None = None
    invisible: bool = False
    page: Any = None  # Playwright Page, used by the manual solver


@dataclass
class CaptchaSolution:
    token: str
    task_id: str | None = None
    provider: str = ""


class CaptchaSolver(Protocol):
    name: str

    async def solve(self, request: CaptchaRequest) -> CaptchaSolution: ...

    async def report_bad(self, solution: CaptchaSolution) -> None: ...

    async def report_good(self, solution: CaptchaSolution) -> None: ...

    async def aclose(self) -> None: ...


class TwoCaptchaSolver:
    name = "2captcha"

    def __init__(
        self,
        api_key: str,
        *,
        api_url: str = "https://api.2captcha.com",
        poll_interval: float = 5.0,
        timeout: float = 180.0,
        initial_wait: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        if not api_key:
            raise CaptchaError("TWOCAPTCHA_API_KEY is not set", retryable=False)
        self._key = api_key
        self._poll_interval = poll_interval
        self._timeout = timeout
        self._initial_wait = min(initial_wait, timeout)
        self._sleep = sleep
        self._client = httpx.AsyncClient(base_url=api_url, timeout=30.0, transport=transport)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self._client.post(f"/{method}", json={"clientKey": self._key, **payload})
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            raise CaptchaError(f"2captcha {method} request failed: {exc.__class__.__name__}: {exc}") from exc
        except ValueError as exc:
            raise CaptchaError(f"2captcha {method} returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise CaptchaError(f"2captcha {method} returned an unexpected response")
        return data

    @staticmethod
    def _raise_for_error(data: dict[str, Any], method: str) -> None:
        if data.get("errorId", 0):
            code = str(data.get("errorCode") or "UNKNOWN_ERROR")
            description = data.get("errorDescription") or ""
            retryable = code not in _FATAL_2CAPTCHA_ERRORS
            raise CaptchaError(f"2captcha {method}: {code} {description}".strip(), retryable=retryable)

    async def balance(self) -> float:
        data = await self._call("getBalance", {})
        self._raise_for_error(data, "getBalance")
        return float(data.get("balance", 0.0))

    async def solve(self, request: CaptchaRequest) -> CaptchaSolution:
        task: dict[str, Any] = {
            "type": "RecaptchaV2TaskProxyless",
            "websiteURL": request.website_url,
            "websiteKey": request.site_key,
            "isInvisible": request.invisible,
        }
        if request.user_agent:
            task["userAgent"] = request.user_agent
        data = await self._call("createTask", {"task": task})
        self._raise_for_error(data, "createTask")
        task_id = data.get("taskId")
        if not task_id:
            raise CaptchaError("2captcha createTask did not return a taskId")
        log.info("captcha task created", extra={"provider": self.name, "task_id": task_id})

        deadline = time.monotonic() + self._timeout
        await self._sleep(self._initial_wait)
        while True:
            data = await self._call("getTaskResult", {"taskId": task_id})
            self._raise_for_error(data, "getTaskResult")
            if data.get("status") == "ready":
                solution = data.get("solution") or {}
                token = solution.get("gRecaptchaResponse") or solution.get("token")
                if not token:
                    raise CaptchaError("2captcha reported ready but returned no token")
                log.info("captcha solved", extra={"provider": self.name, "task_id": task_id})
                return CaptchaSolution(token=token, task_id=str(task_id), provider=self.name)
            if time.monotonic() >= deadline:
                raise CaptchaError(f"2captcha did not solve the CAPTCHA within {self._timeout:.0f}s")
            await self._sleep(self._poll_interval)

    async def report_bad(self, solution: CaptchaSolution) -> None:
        if not solution.task_id:
            return
        try:
            await self._call("reportIncorrect", {"taskId": int(solution.task_id)})
        except (CaptchaError, ValueError) as exc:
            log.warning("could not report incorrect captcha", extra={"task_id": solution.task_id, "error": str(exc)})

    async def report_good(self, solution: CaptchaSolution) -> None:
        if not solution.task_id:
            return
        try:
            await self._call("reportCorrect", {"taskId": int(solution.task_id)})
        except (CaptchaError, ValueError) as exc:
            log.debug("could not report correct captcha", extra={"task_id": solution.task_id, "error": str(exc)})


class ManualCaptchaSolver:
    """Operator-assisted: wait for a human to complete the reCAPTCHA in the visible browser."""

    name = "manual"

    def __init__(self, *, timeout: float = 180.0, poll_interval: float = 1.0):
        self._timeout = timeout
        self._poll_interval = poll_interval

    async def solve(self, request: CaptchaRequest) -> CaptchaSolution:
        page = request.page
        if page is None:
            raise CaptchaError("manual CAPTCHA mode needs a browser page", retryable=False)
        log.info("waiting for operator to complete the CAPTCHA", extra={"timeout": self._timeout})
        try:
            await page.bring_to_front()
        except Exception:  # noqa: BLE001 - purely cosmetic
            pass
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            token = await page.evaluate(
                "sel => { const el = document.querySelector(sel); return el ? el.value : ''; }",
                form_spec.RECAPTCHA_RESPONSE,
            )
            if token:
                return CaptchaSolution(token=token, provider=self.name)
            await asyncio.sleep(self._poll_interval)
        raise CaptchaError(f"operator did not complete the CAPTCHA within {self._timeout:.0f}s")

    async def report_bad(self, solution: CaptchaSolution) -> None:
        return None

    async def report_good(self, solution: CaptchaSolution) -> None:
        return None

    async def aclose(self) -> None:
        return None
