# Growica report submitter

A web tool that fills in and sends the report form at <https://linkreclamatiogrwc.uk/> once per target.
The operator enters a list of domains, IPs or URLs. The tool sends them one by one, solves the reCAPTCHA
through 2captcha, and shows each target's status and its `CF-XXXXXXXX` confirmation code.

**Stack:** Python 3.12 · FastAPI · Playwright (Chromium) · SQLite · plain HTML/CSS/JS · Docker Compose.

## Быстрый старт (RU)

```bash
cp .env.example .env          # впишите TWOCAPTCHA_API_KEY
docker compose up --build     # затем откройте http://localhost:8000
```

Без Docker: `pip install -r requirements.txt && python -m playwright install chromium && python app.py`.

## Quick start

1. Copy the example config and add your 2captcha key:

   ```bash
   cp .env.example .env
   ```

   Then set `TWOCAPTCHA_API_KEY=` in `.env`. The `.env` file is git-ignored.

2. Start the app:

   ```bash
   docker compose up --build
   ```

3. Open <http://localhost:8000>.

### Without Docker

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt        # Windows: .venv\Scripts\pip
.venv/bin/python -m playwright install chromium
.venv/bin/python app.py
```

## Using it

1. Pick **Domain**, **IP** or **URL**, and paste the targets, one per line.
2. Pick the **Threat type**, write the **Reason**, and optionally attach a JPG/JPEG/PNG/PDF file up to 2 MB.
   The same attachment goes with every target.
3. Click **Queue submissions**. Each line becomes its own submission and is processed one at a time:
   **Pending → Processing → Submitted / Failed**. The table refreshes on its own.
4. **Submitted** rows show the confirmation code the site returned. **Failed** rows show the reason, for example
   the site's own validation message, a 2captcha error, or a timeout. Use **Retry** on one row or **Retry failed**
   for the whole batch.
5. **History** lists every submission stored in SQLite.

### Duplicate prevention and rate limits

* Lines repeated inside one batch are merged.
* A target that is already pending, processing or submitted with the same type and threat type is skipped.
  The response lists what was skipped and its existing code. To send it again on purpose, tick
  *Re-send targets that were already submitted*.
* Only failed rows can be retried. Retries respect `RETRY_COOLDOWN` and `MAX_TOTAL_ATTEMPTS`.
* Some failures happen after Submit was clicked, such as a timeout waiting for the response or the app
  restarting mid-submission. The report may already be on the site, so these rows are marked *outcome unknown*.
  They are never retried automatically, and a manual retry asks for confirmation.
* Transient failures before Submit is clicked are retried automatically up to `MAX_AUTO_ATTEMPTS` times. This
  covers an unsolved CAPTCHA, a CAPTCHA the site rejected, and page-load timeouts.
* Submissions are strictly sequential, at least `MIN_SUBMIT_INTERVAL` seconds apart (default 10).

## Configuration

All settings come from environment variables or `.env`. See [.env.example](.env.example).

| Variable | Default | Meaning |
|---|---|---|
| `CAPTCHA_PROVIDER` | `2captcha` | `2captcha` (automatic) or `manual` (operator ticks the CAPTCHA in a visible browser) |
| `TWOCAPTCHA_API_KEY` | — | 2captcha API key |
| `DRY_RUN` | `false` | Fill and validate the form but never solve the CAPTCHA or click Submit |
| `FORM_URL` | `https://linkreclamatiogrwc.uk/` | Target form |
| `MIN_SUBMIT_INTERVAL` | `10` | Seconds between submissions |
| `MAX_AUTO_ATTEMPTS` / `MAX_TOTAL_ATTEMPTS` | `2` / `6` | Attempt limits per target |
| `RETRY_COOLDOWN` | `30` | Seconds before a target can be retried manually |
| `MAX_TARGETS_PER_BATCH` | `100` | Lines per batch |
| `HEADLESS` | `true` | Must be `false` for `manual` CAPTCHA mode |
| `NAVIGATION_TIMEOUT`, `ACTION_TIMEOUT`, `SUBMIT_RESULT_TIMEOUT`, `SUBMISSION_TIMEOUT` | 45 / 15 / 60 / 420 | Timeouts in seconds |
| `LOG_LEVEL`, `LOG_FORMAT` | `INFO`, `json` | Structured JSON logs on stdout (`text` for human-readable) |

Data lives in `data/`: `submissions.db` (SQLite), `uploads/` (attachments), and `responses/` (the HTML page
returned after each submit, for audit). In Docker this is the `app-data` volume.

### Operator-assisted CAPTCHA (no 2captcha)

Run locally with `CAPTCHA_PROVIDER=manual` and `HEADLESS=false`. A Chromium window opens for each target. The
tool fills the form, an operator ticks the reCAPTCHA, and the tool submits as soon as a token is present. This
mode cannot run inside Docker because the container has no display.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Configuration and queue state |
| `GET` | `/api/options` | Submission types and threat types, exactly as offered by the form |
| `POST` | `/api/batches` | multipart: `submission_type`, `targets`, `threat_type`, `reason`, `attachment?`, `allow_resubmit?` |
| `GET` | `/api/batches/{id}` | Batch with per-target status |
| `POST` | `/api/batches/{id}/retry-failed` | Retry all failed rows (`?confirm_uncertain=true` to include *outcome unknown* rows) |
| `GET` | `/api/submissions?status=` | History |
| `GET` | `/api/submissions/{id}` | One submission with its attempt history |
| `POST` | `/api/submissions/{id}/retry` | Retry one failed row |
| `GET` | `/api/captcha/balance` | 2captcha balance |

## Tests

```bash
pip install -r requirements-dev.txt
python -m playwright install chromium
python -m pytest
```

Or run them inside the image: `docker compose run --rm app python -m pytest`.

No test sends anything to the real site or to 2captcha:

* API and worker tests use a mocked submitter: sequential order, statuses, duplicate prevention, rate limits,
  automatic and manual retries, *outcome unknown* handling, and crash recovery.
* 2captcha tests use `httpx.MockTransport`.
* Browser tests drive real Chromium against `tests/fixtures/mock_form.html`, a copy of the real form markup
  served from 127.0.0.1 with a stub CAPTCHA solver and a mock `/submit` endpoint. They test the real selectors,
  the custom dropdowns, the honeypot, the attachment upload, error parsing and code extraction.

## How the form works and known limitations

See [docs/FORM_ANALYSIS.md](docs/FORM_ANALYSIS.md) for the inspected fields, selectors and flow. In short:

* **reCAPTCHA v2.** The token comes from 2captcha and is injected into `g-recaptcha-response` right before
  Submit, because tokens expire after about 2 minutes. Each solve costs 2captcha credit and usually takes
  15–60 s, so a target takes roughly 20–70 s. If the site rejects a token, the tool reports it to 2captcha
  (`reportIncorrect`) and retries once.
* **Success page not observed.** No real report was sent during development, so the layout of the success page
  is not known. The tool takes the code from any `CF-XXXXXXXX` in the response and never generates one. If the
  site confirms without a code, the row is Submitted with a note. If the response cannot be classified, the row
  is Failed with *outcome unknown*, and the saved HTML in `data/responses/` shows what the site returned.
* **Cloudflare.** The form is behind Cloudflare. No challenge appeared during inspection. If one appears, the
  tool reports "Cloudflare challenge" and does not try to bypass it.
* **Raw source.** The site's "Raw source" (email headers) type is not supported; the task covers Domain, IP
  and URL.
* **Attachment.** Optional on the site and in this tool. One file is shared by all targets of a batch.
