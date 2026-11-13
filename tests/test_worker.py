import asyncio

from formbot.db import Database, NewSubmission
from formbot.submitter import SubmissionResult
from formbot.validation import dedup_key
from formbot.worker import SubmissionWorker

from .conftest import FakeSubmitter


def _add(db: Database, targets: list[str], allow_resubmit: bool = False) -> list[int]:
    _, ids, _ = db.create_batch(
        submission_type="domain",
        threat_type="Spam",
        reason="r",
        attachment_path=None,
        attachment_name=None,
        items=[NewSubmission(i + 1, t, dedup_key("domain", t, "Spam")) for i, t in enumerate(targets)],
        allow_resubmit=allow_resubmit,
    )
    return ids


async def test_rate_limit_spacing():
    db = Database(":memory:")
    fake = FakeSubmitter()
    worker = SubmissionWorker(db, fake, min_submit_interval=0.3)
    ids = _add(db, ["a.com", "b.com", "c.com"])
    stamps = []
    original = fake.submit

    async def timed(job, progress):
        stamps.append(asyncio.get_running_loop().time())
        return await original(job, progress)

    fake.submit = timed
    await worker.start()
    for i in ids:
        worker.enqueue(i)
    await asyncio.wait_for(worker.wait_idle(), 5)
    await worker.stop()
    assert len(stamps) == 3
    assert all(b - a >= 0.29 for a, b in zip(stamps, stamps[1:]))


async def test_strictly_sequential():
    db = Database(":memory:")
    running = 0
    peak = 0

    class Slow(FakeSubmitter):
        async def submit(self, job, progress):
            nonlocal running, peak
            running += 1
            peak = max(peak, running)
            await asyncio.sleep(0.02)
            running -= 1
            return SubmissionResult(status="submitted", confirmation_code="CF-00000000")

    worker = SubmissionWorker(db, Slow(), min_submit_interval=0)
    ids = _add(db, [f"h{i}.com" for i in range(5)])
    await worker.start()
    for i in ids:
        worker.enqueue(i)
        worker.enqueue(i)  # enqueuing twice must not process twice
    await asyncio.wait_for(worker.wait_idle(), 5)
    await worker.stop()
    assert peak == 1
    assert all(db.get_submission(i)["attempts"] == 1 for i in ids)


async def test_timeout_marks_uncertain():
    db = Database(":memory:")
    worker = SubmissionWorker(db, FakeSubmitter(delay=1), min_submit_interval=0, submission_timeout=0.05)
    [sid] = _add(db, ["slow.com"])
    await worker.start()
    worker.enqueue(sid)
    await asyncio.wait_for(worker.wait_idle(), 5)
    await worker.stop()
    row = db.get_submission(sid)
    assert row["status"] == "failed" and row["outcome_uncertain"] == 1


async def test_submitter_exception_is_contained():
    db = Database(":memory:")

    def boom(job, n):
        raise RuntimeError("kaput")

    worker = SubmissionWorker(db, FakeSubmitter(boom), min_submit_interval=0)
    [sid] = _add(db, ["x.com"])
    await worker.start()
    worker.enqueue(sid)
    await asyncio.wait_for(worker.wait_idle(), 5)
    await worker.stop()
    row = db.get_submission(sid)
    assert row["status"] == "failed" and "kaput" in row["error"]


async def test_recovery_after_restart(tmp_path):
    db = Database(tmp_path / "x.db")
    ids = _add(db, ["a.com", "b.com"])
    db.start_attempt(ids[0])  # simulate a crash while processing a.com
    fake = FakeSubmitter()
    worker = SubmissionWorker(db, fake, min_submit_interval=0)
    await worker.start()  # pending b.com is picked up automatically
    await asyncio.wait_for(worker.wait_idle(), 5)
    await worker.stop()
    a, b = db.get_submission(ids[0]), db.get_submission(ids[1])
    assert a["status"] == "failed" and a["outcome_uncertain"] == 1
    assert b["status"] == "submitted"
    assert [c.target for c in fake.calls] == ["b.com"]


async def test_forced_resubmit_runs_but_plain_duplicate_is_skipped():
    db = Database(":memory:")
    fake = FakeSubmitter()
    worker = SubmissionWorker(db, fake, min_submit_interval=0)
    await worker.start()
    [first] = _add(db, ["d.com"])
    worker.enqueue(first)
    await asyncio.wait_for(worker.wait_idle(), 5)
    [forced] = _add(db, ["d.com"], allow_resubmit=True)
    worker.enqueue(forced)
    await asyncio.wait_for(worker.wait_idle(), 5)
    await worker.stop()
    assert db.get_submission(forced)["status"] == "submitted"
    assert len(fake.calls) == 2
