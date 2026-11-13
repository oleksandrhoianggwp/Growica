import json

import httpx
import pytest

from formbot.captcha import CaptchaError, CaptchaRequest, TwoCaptchaSolver


async def _no_sleep(_seconds: float) -> None:
    return None


def _solver(handler) -> TwoCaptchaSolver:
    return TwoCaptchaSolver(
        "KEY", transport=httpx.MockTransport(handler), sleep=_no_sleep, poll_interval=1, timeout=60, initial_wait=0
    )


REQUEST = CaptchaRequest(website_url="https://form.test/", site_key="SITEKEY", user_agent="UA")


async def test_solve_success_polls_until_ready():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append((request.url.path, body))
        if request.url.path == "/createTask":
            assert body["clientKey"] == "KEY"
            assert body["task"] == {
                "type": "RecaptchaV2TaskProxyless",
                "websiteURL": "https://form.test/",
                "websiteKey": "SITEKEY",
                "isInvisible": False,
                "userAgent": "UA",
            }
            return httpx.Response(200, json={"errorId": 0, "taskId": 123})
        polls = sum(1 for path, _ in calls if path == "/getTaskResult")
        if polls < 3:
            return httpx.Response(200, json={"errorId": 0, "status": "processing"})
        return httpx.Response(200, json={"errorId": 0, "status": "ready", "solution": {"gRecaptchaResponse": "TOKEN"}})

    solver = _solver(handler)
    solution = await solver.solve(REQUEST)
    await solver.aclose()
    assert solution.token == "TOKEN" and solution.task_id == "123"
    assert [p for p, _ in calls].count("/getTaskResult") == 3


async def test_fatal_error_is_not_retryable():
    solver = _solver(lambda r: httpx.Response(200, json={"errorId": 10, "errorCode": "ERROR_ZERO_BALANCE",
                                                         "errorDescription": "No funds"}))
    with pytest.raises(CaptchaError) as info:
        await solver.solve(REQUEST)
    await solver.aclose()
    assert not info.value.retryable
    assert "ERROR_ZERO_BALANCE" in str(info.value)


async def test_unsolvable_is_retryable():
    def handler(request):
        if request.url.path == "/createTask":
            return httpx.Response(200, json={"errorId": 0, "taskId": 5})
        return httpx.Response(200, json={"errorId": 12, "errorCode": "ERROR_CAPTCHA_UNSOLVABLE"})

    solver = _solver(handler)
    with pytest.raises(CaptchaError) as info:
        await solver.solve(REQUEST)
    await solver.aclose()
    assert info.value.retryable


async def test_timeout():
    def handler(request):
        if request.url.path == "/createTask":
            return httpx.Response(200, json={"errorId": 0, "taskId": 5})
        return httpx.Response(200, json={"errorId": 0, "status": "processing"})

    solver = TwoCaptchaSolver("KEY", transport=httpx.MockTransport(handler), sleep=_no_sleep, timeout=0.01,
                              initial_wait=0, poll_interval=0.001)
    import asyncio

    async def slow_sleep(s):
        await asyncio.sleep(0.02)

    solver._sleep = slow_sleep
    with pytest.raises(CaptchaError, match="did not solve"):
        await solver.solve(REQUEST)
    await solver.aclose()


async def test_http_error_and_report_bad():
    reported = []

    def handler(request):
        if request.url.path == "/reportIncorrect":
            reported.append(json.loads(request.content)["taskId"])
            return httpx.Response(200, json={"errorId": 0, "status": "success"})
        return httpx.Response(503, text="down")

    solver = _solver(handler)
    with pytest.raises(CaptchaError, match="createTask request failed"):
        await solver.solve(REQUEST)
    from formbot.captcha import CaptchaSolution

    await solver.report_bad(CaptchaSolution(token="t", task_id="77"))
    await solver.aclose()
    assert reported == [77]


def test_missing_key():
    with pytest.raises(CaptchaError):
        TwoCaptchaSolver("")
