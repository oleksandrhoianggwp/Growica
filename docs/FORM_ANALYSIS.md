# Target form analysis — https://linkreclamatiogrwc.uk/

Inspected on 2026-11-13 by fetching the page (GET only) and by loading it in headless Chromium.
No report was submitted during inspection or testing.

## Transport

| Item | Observed |
|---|---|
| Hosting | Behind Cloudflare (`Server: cloudflare`). A plain GET and headless Chromium both received the form; no browser challenge was shown at inspection time. |
| Session | `Set-Cookie: session=…; Secure; HttpOnly; SameSite=Lax`, `Cache-Control: no-store`, `Vary: Cookie`. |
| Form | `<form method="post" action="/submit" enctype="multipart/form-data">` (a regular page navigation, not XHR). |
| CSRF-like token | `<input type="hidden" name="form_token">`, different on every page load (tied to the session cookie). The tool therefore loads a fresh page in a fresh browser context for every target. |
| robots.txt | `User-agent: * Allow: /` (only some AI crawlers are disallowed; this tool does not crawl). |

## Fields

| Label | Element | Name | Rules |
|---|---|---|---|
| Submission Type | `select#submission_type` (hidden behind a custom JS dropdown, trigger `#submission_type_dd`) | `submission_type` | `raw` (Raw source), `domain` (default), `ip`, `url` |
| Raw source | `textarea#raw_source` | `raw_source` | maxlength 50000, shown only for `raw` (out of scope for this tool) |
| Domain | `input#domain` | `domain` | maxlength 253, shown/required only for `domain` |
| IP | `input#ip` | `ip` | maxlength 64, shown/required only for `ip` |
| URL | `input#url` | `url` | maxlength 2000, shown/required only for `url` |
| Threat Type | `select#threat_type` (custom dropdown `#threat_type_dd`) | `threat_type` | required; `Spam`, `Phishing`, `Malware`, `Botnet C&C`, `Fraud / Scam`, `Other` |
| Reason | `textarea#reason` | `reason` | required, maxlength 2000 |
| Attachment | `input#attachment[type=file]` | `attachment` | optional, `accept=".jpg,.jpeg,.png,.pdf"`, hint "up to 2 MB" |
| Terms | `input[type=checkbox]` | `accept_terms` | required, value `1` |
| CAPTCHA | `div.g-recaptcha[data-sitekey="6LfiehouAAAAAFr7759Kztp8FRrwjs0BRxuMZP28"]` | `g-recaptcha-response` | Google reCAPTCHA **v2 checkbox** (`api.js`, no `data-size="invisible"`, no `data-callback`) |
| Submit | `button[type=submit]` | — | — |

Page script behaviour:

* The custom dropdowns write to the native `<select>` and dispatch `change`.
* A `change` listener on `#submission_type` shows the matching target field and sets `required` only on it.
* The CSS defines a honeypot class `.hp` ("off-screen for humans, still present for naive bots"). The tool never
  touches anything inside `.hp` and refuses to submit if a honeypot input has a value.
* Error styles `.alert` (page-level) and `.field-error` (under a field) exist, so server-side errors are rendered
  on the re-displayed form. The tool reads both and reports them per target.

## Confirmation flow

The success page could not be observed without submitting a real report, which was not authorised during
development. The tool therefore makes no assumptions about its layout:

* `CF-` followed by 8 letters/digits anywhere in the response → **Submitted** with that code
  (codes that also appear in our own inputs are ignored, so an echoed value can never be mistaken for a code).
* `.alert` / `.field-error` text → **Failed** with that text as the reason.
* Cloudflare challenge / HTTP 403 / 429 → **Failed** with a specific reason.
* Thank-you text without a code and without the form → **Submitted**, with the note "no code shown".
* Anything else → **Failed** and flagged *outcome unknown*; a retry requires explicit confirmation.

The HTML of every response page is saved to `data/responses/` for inspection.
