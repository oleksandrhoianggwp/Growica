import time

import pytest
from fastapi.testclient import TestClient

from formbot.main import create_app
from formbot.submitter import SubmissionResult

from .conftest import PNG_BYTES, FakeSubmitter


def wait_done(client: TestClient, batch_id: int, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        batch = client.get(f"/api/batches/{batch_id}").json()
        if all(s["status"] in ("submitted", "failed") for s in batch["submissions"]):
            return batch
        time.sleep(0.05)
    raise AssertionError(f"batch {batch_id} did not finish: {batch}")


@pytest.fixture
def make_client(settings):
    clients = []

    def _make(fake: FakeSubmitter, **overrides):
        s = settings.model_copy(update=overrides)
        app = create_app(s, submitter_factory=lambda _s, _solver: fake, solver_factory=lambda _s: None)
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


FORM = {"submission_type": "domain", "threat_type": "Phishing", "reason": "Credential phishing page"}


def test_index_and_options(make_client):
    client = make_client(FakeSubmitter())
    assert "Report Submitter" in client.get("/").text
    options = client.get("/api/options").json()
    assert [t["value"] for t in options["submission_types"]] == ["domain", "ip", "url"]
    assert "Botnet C&C" in options["threat_types"]
    assert client.get("/api/health").json()["status"] == "ok"


def test_each_line_submitted_separately_in_order(make_client):
    fake = FakeSubmitter()
    client = make_client(fake)
    response = client.post(
        "/api/batches",
        data={**FORM, "targets": "a.example.com\nb.example.com\n\nc.example.com"},
        files={"attachment": ("shot.png", PNG_BYTES, "image/png")},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["queued"] == 3
    batch = wait_done(client, body["batch_id"])
    assert [c.target for c in fake.calls] == ["a.example.com", "b.example.com", "c.example.com"]
    assert all(c.attachment_path and c.attachment_path.endswith("shot.png") for c in fake.calls)
    assert [s["status"] for s in batch["submissions"]] == ["submitted"] * 3
    assert [s["confirmation_code"] for s in batch["submissions"]] == ["CF-00000001", "CF-00000002", "CF-00000003"]
    history = client.get("/api/submissions?status=submitted").json()
    assert len(history) == 3


def test_validation_errors_reject_whole_batch(make_client):
    fake = FakeSubmitter()
    client = make_client(fake)
    response = client.post(
        "/api/batches",
        data={**FORM, "threat_type": "Nope", "targets": "ok.com\nnot a domain"},
        files={"attachment": ("x.exe", b"MZ", "application/octet-stream")},
    )
    assert response.status_code == 422
    errors = response.json()["detail"]["errors"]
    assert any("Threat type" in e for e in errors)
    assert any("line 2" in e for e in errors)
    assert any("Attachment" in e for e in errors)
    assert fake.calls == []


def test_attachment_too_large(make_client):
    client = make_client(FakeSubmitter())
    big = PNG_BYTES + b"\x00" * (2 * 1024 * 1024)
    response = client.post("/api/batches", data={**FORM, "targets": "a.com"}, files={"attachment": ("b.png", big, "image/png")})
    assert response.status_code == 422
    assert any("2 MB" in e for e in response.json()["detail"]["errors"])


def test_duplicate_prevention(make_client):
    fake = FakeSubmitter()
    client = make_client(fake)
    first = client.post("/api/batches", data={**FORM, "targets": "dup.com"}).json()
    wait_done(client, first["batch_id"])
    second = client.post("/api/batches", data={**FORM, "targets": "dup.com\nnew.com"}).json()
    assert second["queued"] == 1
    assert second["skipped_duplicates"][0]["target"] == "dup.com"
    assert second["skipped_duplicates"][0]["confirmation_code"] == "CF-00000001"
    wait_done(client, second["batch_id"])
    # explicit re-send is allowed
    third = client.post("/api/batches", data={**FORM, "targets": "dup.com", "allow_resubmit": "true"}).json()
    assert third["queued"] == 1
    wait_done(client, third["batch_id"])
    assert [c.target for c in fake.calls] == ["dup.com", "new.com", "dup.com"]


def test_failed_then_manual_retry(make_client):
    outcomes = {"bad.com": [SubmissionResult(status="failed", error="Rejected by the site: Enter a valid domain.")]}

    def script(job, n):
        queue = outcomes.get(job.target)
        if queue:
            return queue.pop(0)
        return SubmissionResult(status="submitted", confirmation_code="CF-ABCDEF12")

    fake = FakeSubmitter(script)
    client = make_client(fake)
    body = client.post("/api/batches", data={**FORM, "targets": "good.com\nbad.com"}).json()
    batch = wait_done(client, body["batch_id"])
    by_target = {s["target"]: s for s in batch["submissions"]}
    assert by_target["bad.com"]["status"] == "failed"
    assert "Enter a valid domain" in by_target["bad.com"]["error"]
    assert by_target["bad.com"]["attempts"] == 1  # non-retryable: no automatic retry

    # submitted rows can't be retried
    assert client.post(f"/api/submissions/{by_target['good.com']['id']}/retry").status_code == 409

    result = client.post(f"/api/batches/{body['batch_id']}/retry-failed").json()
    assert result["retried"] == [by_target["bad.com"]["id"]]
    batch = wait_done(client, body["batch_id"])
    bad = next(s for s in batch["submissions"] if s["target"] == "bad.com")
    assert bad["status"] == "submitted" and bad["confirmation_code"] == "CF-ABCDEF12" and bad["attempts"] == 2
    detail = client.get(f"/api/submissions/{bad['id']}").json()
    assert [a["outcome"] for a in detail["attempt_history"]] == ["failed", "submitted"]


def test_retryable_failure_is_retried_automatically(make_client):
    results = [SubmissionResult(status="failed", error="CAPTCHA not solved: ERROR_CAPTCHA_UNSOLVABLE", retryable=True),
               SubmissionResult(status="submitted", confirmation_code="CF-77777777")]
    fake = FakeSubmitter(lambda job, n: results[n - 1])
    client = make_client(fake)
    body = client.post("/api/batches", data={**FORM, "targets": "x.com"}).json()
    batch = wait_done(client, body["batch_id"])
    assert batch["submissions"][0]["status"] == "submitted"
    assert batch["submissions"][0]["attempts"] == 2


def test_uncertain_failure_needs_confirmation(make_client):
    results = [SubmissionResult(status="failed", error="Timed out after clicking Submit", outcome_uncertain=True, retryable=True),
               SubmissionResult(status="submitted", confirmation_code="CF-12121212")]
    fake = FakeSubmitter(lambda job, n: results[n - 1])
    client = make_client(fake)
    body = client.post("/api/batches", data={**FORM, "targets": "x.com"}).json()
    batch = wait_done(client, body["batch_id"])
    row = batch["submissions"][0]
    assert row["status"] == "failed" and row["outcome_uncertain"] and row["attempts"] == 1  # never auto-retried
    assert client.post(f"/api/submissions/{row['id']}/retry").status_code == 409
    assert client.post(f"/api/submissions/{row['id']}/retry?confirm_uncertain=true").status_code == 200
    batch = wait_done(client, body["batch_id"])
    assert batch["submissions"][0]["confirmation_code"] == "CF-12121212"


def test_retry_cooldown(make_client):
    fake = FakeSubmitter(lambda job, n: SubmissionResult(status="failed", error="nope"))
    client = make_client(fake, retry_cooldown=3600)
    body = client.post("/api/batches", data={**FORM, "targets": "x.com"}).json()
    row = wait_done(client, body["batch_id"])["submissions"][0]
    response = client.post(f"/api/submissions/{row['id']}/retry")
    assert response.status_code == 429 and "wait" in response.json()["detail"]


def test_batch_size_limit(make_client):
    client = make_client(FakeSubmitter(), max_targets_per_batch=2)
    response = client.post("/api/batches", data={**FORM, "targets": "a.com\nb.com\nc.com"})
    assert response.status_code == 422
    assert any("too many targets" in e for e in response.json()["detail"]["errors"])


def test_unknown_ids(make_client):
    client = make_client(FakeSubmitter())
    assert client.get("/api/batches/999").status_code == 404
    assert client.post("/api/submissions/999/retry").status_code == 404
    assert client.get("/api/submissions?status=weird").status_code == 422


def test_total_attempt_limit(make_client):
    fake = FakeSubmitter(lambda job, n: SubmissionResult(status="failed", error="nope"))
    client = make_client(fake, max_total_attempts=2)
    body = client.post("/api/batches", data={**FORM, "targets": "x.com"}).json()
    row = wait_done(client, body["batch_id"])["submissions"][0]
    assert client.post(f"/api/submissions/{row['id']}/retry").status_code == 200
    wait_done(client, body["batch_id"])
    response = client.post(f"/api/submissions/{row['id']}/retry")
    assert response.status_code == 429 and "limit" in response.json()["detail"]
