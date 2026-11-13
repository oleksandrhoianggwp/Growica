"""Fills and submits the target form with Playwright, then classifies the server response."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Protocol

from playwright.async_api import Browser, Page, Playwright, async_playwright
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from . import form_spec
from .captcha import CaptchaError, CaptchaRequest, CaptchaSolution, CaptchaSolver

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str], Awaitable[None]]

_SUCCESS_HINTS = re.compile(
    r"\b(thank you|thanks|received|has been submitted|successfully submitted|submission (was )?accepted|confirmation)\b",
    re.IGNORECASE,
)
_RETRYABLE_ERROR_HINTS = re.compile(
    r"captcha|too many|rate limit|try again|expired|session|token|temporar", re.IGNORECASE
)
_CAPTCHA_ERROR_HINTS = re.compile(r"captcha|robot|recaptcha", re.IGNORECASE)


@dataclass
class SubmissionJob:
    submission_id: int
    submission_type: str
    target: str
    threat_type: str
    reason: str
    attachment_path: str | None = None


@dataclass
class SubmissionResult:
    status: str  # "submitted" | "failed"
    confirmation_code: str | None = None
    error: str | None = None
    retryable: bool = False
    outcome_uncertain: bool = False
    note: str | None = None
    response_snapshot: str | None = None
    details: dict[str, object] = field(default_factory=dict)


class Submitter(Protocol):
    async def start(self) -> None: ...

    async def close(self) -> None: ...

    async def submit(self, job: SubmissionJob, progress: ProgressCallback) -> SubmissionResult: ...


class SubmissionError(Exception):
    def __init__(self, message: str, *, retryable: bool = False, uncertain: bool = False):
        super().__init__(message)
        self.retryable = retryable
        self.uncertain = uncertain


# --------------------------------------------------------------------------- response analysis
@dataclass
class PageSnapshot:
    url: str
    status: int | None
    title: str
    text: str
    alerts: list[str]
    field_errors: list[tuple[str, str]]
    form_present: bool


def detect_block(title: str, text: str, status: int | None) -> str | None:
    """Recognise anti-bot interstitials and HTTP-level refusals."""
    lowered = f"{title}\n{text[:3000]}".lower()
    if "just a moment" in lowered or "checking your browser" in lowered or "cf-chl" in lowered:
        return "The site showed a Cloudflare browser challenge instead of the form; automated access was refused."
    if "attention required" in lowered or "sorry, you have been blocked" in lowered:
        return "Cloudflare blocked the request (\"Attention Required\")."
    if status == 429:
        return "The site rate-limited the request (HTTP 429). Wait before retrying."
    if status == 403:
        return "The site refused access (HTTP 403)."
    return None


def extract_confirmation_codes(text: str, exclude: list[str]) -> list[str]:
    """CF-XXXXXXXX codes present in the response but not echoed back from our own inputs."""
    excluded = {m.group(0).upper() for value in exclude for m in form_spec.CONFIRMATION_CODE_RE.finditer(value or "")}
    codes: list[str] = []
    for match in form_spec.CONFIRMATION_CODE_RE.finditer(text):
        code = match.group(0).upper()
        if code not in excluded and code not in codes:
            codes.append(code)
    return codes


def analyze_response(snapshot: PageSnapshot, job: SubmissionJob) -> SubmissionResult:
    """Decide what the page shown after clicking Submit means. Never invents a confirmation code."""
    codes = extract_confirmation_codes(snapshot.text, [job.target, job.reason])
    if codes:
        note = None
        if len(codes) > 1:
            note = f"Response contained several codes: {', '.join(codes)}; the first one was recorded."
        return SubmissionResult(status="submitted", confirmation_code=codes[0], note=note)

    block = detect_block(snapshot.title, snapshot.text, snapshot.status)
    if block:
        return SubmissionResult(status="failed", error=block, retryable=snapshot.status == 429)

    if snapshot.alerts or snapshot.field_errors:
        parts = [a.strip() for a in snapshot.alerts if a.strip()]
        parts += [f"{label}: {message}" if label else message for label, message in snapshot.field_errors]
        message = "; ".join(parts) or "the site rejected the submission"
        retryable = bool(_RETRYABLE_ERROR_HINTS.search(message))
        return SubmissionResult(
            status="failed",
            error=f"Rejected by the site: {message}",
            retryable=retryable,
            details={"captcha_rejected": bool(_CAPTCHA_ERROR_HINTS.search(message))},
        )

    if snapshot.status is not None and snapshot.status >= 500:
        return SubmissionResult(
            status="failed",
            error=f"The site returned HTTP {snapshot.status}; it is unknown whether the report was stored.",
            outcome_uncertain=True,
        )

    if not snapshot.form_present and _SUCCESS_HINTS.search(snapshot.text):
        return SubmissionResult(
            status="submitted",
            note="The site confirmed the submission but did not show a CF- confirmation code.",
        )

    excerpt = " ".join(snapshot.text.split())[:300]
    return SubmissionResult(
        status="failed",
        error=(
            "No confirmation code or error message was found in the response, so the outcome is unknown. "
            f"Page excerpt: {excerpt!r}"
        ),
        outcome_uncertain=True,
    )


# --------------------------------------------------------------------------- Playwright submitter
_COLLECT_FIELD_ERRORS_JS = """
(sel) => Array.from(document.querySelectorAll(sel)).map(el => {
  const field = el.closest('.field');
  const label = field ? field.querySelector('label.title, label') : null;
  return [label ? label.textContent.trim() : '', el.textContent.trim()];
}).filter(pair => pair[1])
"""


class PlaywrightSubmitter:
    def __init__(
        self,
        *,
        form_url: str,
        solver: CaptchaSolver | None,
        headless: bool = True,
        navigation_timeout: float = 45.0,
        action_timeout: float = 15.0,
        submit_result_timeout: float = 60.0,
        dry_run: bool = False,
        snapshot_dir: Path | None = None,
        captcha_config_error: str | None = None,
    ):
        self.form_url = form_url
        self.solver = solver
        self.headless = headless
        self.navigation_timeout_ms = navigation_timeout * 1000
        self.action_timeout_ms = action_timeout * 1000
        self.submit_result_timeout_ms = submit_result_timeout * 1000
        self.dry_run = dry_run
        self.snapshot_dir = snapshot_dir
        self.captcha_config_error = captcha_config_error
        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        await self._ensure_browser()

    async def _ensure_browser(self) -> Browser:
        async with self._lock:
            if self._browser is not None and self._browser.is_connected():
                return self._browser
            if self._pw is None:
                self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=self.headless)
            log.info("browser launched", extra={"headless": self.headless})
            return self._browser

    async def close(self) -> None:
        async with self._lock:
            if self._browser is not None:
                try:
                    await self._browser.close()
                except PlaywrightError:
                    pass
                self._browser = None
            if self._pw is not None:
                await self._pw.stop()
                self._pw = None

    async def submit(self, job: SubmissionJob, progress: ProgressCallback) -> SubmissionResult:
        if self.captcha_config_error and not self.dry_run:
            return SubmissionResult(status="failed", error=self.captcha_config_error)
        if job.submission_type not in form_spec.SUBMISSION_TYPES:
            return SubmissionResult(status="failed", error=f"Unsupported submission type {job.submission_type!r}")
        if job.attachment_path and not Path(job.attachment_path).is_file():
            return SubmissionResult(status="failed", error="The stored attachment file is missing on disk.")

        browser = await self._ensure_browser()
        context = await browser.new_context(locale="en-US", viewport={"width": 1280, "height": 900})
        context.set_default_timeout(self.action_timeout_ms)
        context.set_default_navigation_timeout(self.navigation_timeout_ms)
        page = await context.new_page()
        clicked_submit = False
        solution: CaptchaSolution | None = None
        try:
            await progress("Opening form")
            response = await page.goto(self.form_url, wait_until="domcontentloaded")
            status = response.status if response else None
            title = await page.title()
            body = await page.locator("body").inner_text() if await page.locator("body").count() else ""
            block = detect_block(title, body, status)
            if block:
                raise SubmissionError(block, retryable=status == 429)
            if status is not None and status >= 400:
                raise SubmissionError(f"The form page returned HTTP {status}.", retryable=status >= 500)
            try:
                await page.locator(form_spec.FORM_SELECTOR).wait_for(state="visible")
            except PlaywrightTimeoutError as exc:
                raise SubmissionError("The report form was not found on the page (site layout changed?).") from exc

            await progress("Filling form")
            await self._fill_form(page, job)
            await self._verify_form(page, job)

            if self.dry_run:
                return SubmissionResult(
                    status="failed",
                    error="DRY_RUN is enabled: the form was filled and validated, but the CAPTCHA was not solved "
                    "and nothing was submitted.",
                )

            await progress(f"Solving CAPTCHA ({self.solver.name if self.solver else 'none'})")
            solution = await self._solve_captcha(page)

            await progress("Submitting")
            submit_button = page.locator(form_spec.SUBMIT_BUTTON)
            async with page.expect_navigation(wait_until="domcontentloaded", timeout=self.submit_result_timeout_ms) as nav:
                clicked_submit = True
                await submit_button.click()
            nav_response = await nav.value

            await progress("Reading confirmation")
            snapshot = await self._snapshot(page, nav_response.status if nav_response else None)
            result = analyze_response(snapshot, job)
            result.response_snapshot = await self._save_snapshot(page, job)
            if self.solver and solution:
                if result.details.get("captcha_rejected"):
                    await self.solver.report_bad(solution)
                elif result.status == "submitted":
                    await self.solver.report_good(solution)
            return result
        except SubmissionError as exc:
            return SubmissionResult(
                status="failed", error=str(exc), retryable=exc.retryable, outcome_uncertain=exc.uncertain
            )
        except CaptchaError as exc:
            return SubmissionResult(status="failed", error=f"CAPTCHA not solved: {exc}", retryable=exc.retryable)
        except PlaywrightTimeoutError as exc:
            if clicked_submit:
                return SubmissionResult(
                    status="failed",
                    error="Timed out waiting for the site's response after clicking Submit; the report may or may "
                    "not have been stored.",
                    outcome_uncertain=True,
                    response_snapshot=await self._save_snapshot(page, job),
                )
            return SubmissionResult(status="failed", error=f"Timed out while loading or filling the form: {_short(exc)}", retryable=True)
        except PlaywrightError as exc:
            return SubmissionResult(
                status="failed",
                error=f"Browser error: {_short(exc)}",
                retryable=not clicked_submit,
                outcome_uncertain=clicked_submit,
            )
        finally:
            try:
                await context.close()
            except PlaywrightError:
                pass

    # ------------------------------------------------------------------ steps
    async def _choose_dropdown(self, page: Page, select_selector: str, value: str) -> None:
        """Use the site's custom dropdown like a person would; fall back to the native <select>."""
        select = page.locator(select_selector)
        if await select.count() != 1:
            raise SubmissionError(f"Form field {select_selector} not found (site layout changed?).")
        option_exists = await select.evaluate(
            "(el, v) => Array.from(el.options).some(o => o.value === v && !o.disabled)", value
        )
        if not option_exists:
            raise SubmissionError(f"The site no longer offers the option {value!r} for {select_selector}.")
        trigger = page.locator(f"{select_selector}_dd")
        try:
            if await trigger.count() == 1 and await trigger.is_visible():
                await trigger.click()
                option = page.locator(f".dd.open .dd-option[data-value=\"{_css_escape(value)}\"]")
                await option.click()
        except PlaywrightTimeoutError:
            log.warning("custom dropdown did not respond; using the native select", extra={"field": select_selector})
            await page.keyboard.press("Escape")
        if await select.input_value() != value:
            await select.select_option(value=value, force=True)
        if await select.input_value() != value:
            raise SubmissionError(f"Could not select {value!r} in {select_selector}.")

    async def _fill_form(self, page: Page, job: SubmissionJob) -> None:
        await self._choose_dropdown(page, form_spec.SUBMISSION_TYPE_SELECT, job.submission_type)
        target_selector = str(form_spec.SUBMISSION_TYPES[job.submission_type]["input"])
        target_input = page.locator(target_selector)
        try:
            await target_input.wait_for(state="visible")
        except PlaywrightTimeoutError as exc:
            raise SubmissionError(f"The {job.submission_type} field did not appear after choosing the type.") from exc
        await target_input.fill(job.target)

        await self._choose_dropdown(page, form_spec.THREAT_TYPE_SELECT, job.threat_type)
        await page.locator(form_spec.REASON_INPUT).fill(job.reason)
        if job.attachment_path:
            await page.locator(form_spec.ATTACHMENT_INPUT).set_input_files(job.attachment_path)
        terms = page.locator(form_spec.TERMS_CHECKBOX)
        if await terms.count() != 1:
            raise SubmissionError("The terms checkbox was not found (site layout changed?).")
        await terms.check()

    async def _verify_form(self, page: Page, job: SubmissionJob) -> None:
        state = await page.evaluate(
            """([formSel, hpSel]) => {
                const form = document.querySelector(formSel);
                const honeypots = Array.from(document.querySelectorAll(hpSel)).filter(el => el.value);
                const invalid = Array.from(form.querySelectorAll('input, select, textarea'))
                    .filter(el => !el.checkValidity())
                    .map(el => (el.name || el.id) + ': ' + el.validationMessage);
                return { honeypotsFilled: honeypots.length, invalid };
            }""",
            [form_spec.FORM_SELECTOR, form_spec.HONEYPOT_INPUTS],
        )
        if state["honeypotsFilled"]:
            raise SubmissionError("A hidden honeypot field has a value; refusing to submit.")
        if state["invalid"]:
            raise SubmissionError("The form reports invalid fields: " + "; ".join(state["invalid"]))
        target_selector = str(form_spec.SUBMISSION_TYPES[job.submission_type]["input"])
        if await page.locator(target_selector).input_value() != job.target:
            raise SubmissionError("The target field did not keep the entered value.")

    async def _solve_captcha(self, page: Page) -> CaptchaSolution | None:
        widget = page.locator(form_spec.RECAPTCHA_WIDGET)
        if await widget.count() == 0:
            log.warning("no reCAPTCHA widget found on the form; submitting without a token")
            return None
        if self.solver is None:
            raise CaptchaError("no CAPTCHA solver is configured", retryable=False)
        site_key = await widget.first.get_attribute("data-sitekey")
        size = await widget.first.get_attribute("data-size")
        callback = await widget.first.get_attribute("data-callback")
        if not site_key:
            raise SubmissionError("The reCAPTCHA widget has no site key.")
        user_agent = await page.evaluate("navigator.userAgent")
        solution = await self.solver.solve(
            CaptchaRequest(
                website_url=page.url,
                site_key=site_key,
                user_agent=user_agent,
                invisible=(size == "invisible"),
                page=page,
            )
        )
        await page.evaluate(
            """([formSel, respSel, token, callback]) => {
                const form = document.querySelector(formSel);
                let fields = Array.from(document.querySelectorAll(respSel));
                if (!fields.length) {
                    const ta = document.createElement('textarea');
                    ta.name = 'g-recaptcha-response';
                    ta.style.display = 'none';
                    form.appendChild(ta);
                    fields = [ta];
                }
                fields.forEach(el => { el.value = token; el.innerHTML = token; });
                if (callback && typeof window[callback] === 'function') { window[callback](token); }
            }""",
            [form_spec.FORM_SELECTOR, form_spec.RECAPTCHA_RESPONSE, solution.token, callback],
        )
        return solution

    async def _snapshot(self, page: Page, status: int | None) -> PageSnapshot:
        body = page.locator("body")
        text = await body.inner_text() if await body.count() else ""
        alerts = await page.locator(form_spec.ALERT).all_inner_texts()
        field_errors = await page.evaluate(_COLLECT_FIELD_ERRORS_JS, form_spec.FIELD_ERROR)
        return PageSnapshot(
            url=page.url,
            status=status,
            title=await page.title(),
            text=text,
            alerts=alerts,
            field_errors=[(str(a), str(b)) for a, b in field_errors],
            form_present=await page.locator(form_spec.FORM_SELECTOR).count() > 0,
        )

    async def _save_snapshot(self, page: Page, job: SubmissionJob) -> str | None:
        if self.snapshot_dir is None:
            return None
        try:
            self.snapshot_dir.mkdir(parents=True, exist_ok=True)
            path = self.snapshot_dir / f"submission-{job.submission_id}-{_timestamp()}.html"
            path.write_text(await page.content(), encoding="utf-8")
            return str(path)
        except (OSError, PlaywrightError) as exc:
            log.warning("could not save response snapshot", extra={"error": str(exc)})
            return None


def _short(exc: BaseException) -> str:
    return str(exc).strip().splitlines()[0][:300] if str(exc).strip() else exc.__class__.__name__


def _css_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
