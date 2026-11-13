"""Facts about the target form, taken from inspecting https://linkreclamatiogrwc.uk/ (see docs/FORM_ANALYSIS.md).

Every selector here exists in the live page markup. Nothing is guessed: if the site changes,
the submitter fails with a "form structure changed" error instead of filling the wrong field.
"""

from __future__ import annotations

import re

FORM_SELECTOR = 'form[action="/submit"]'
SUBMIT_BUTTON = f'{FORM_SELECTOR} button[type="submit"]'

# <select id="submission_type" name="submission_type" class="js-dd"> (native select is hidden by a custom dropdown)
SUBMISSION_TYPE_SELECT = "#submission_type"
# <select id="threat_type" name="threat_type" required class="js-dd">
THREAT_TYPE_SELECT = "#threat_type"
# <textarea id="reason" name="reason" maxlength="2000" required>
REASON_INPUT = "#reason"
# <input type="file" id="attachment" name="attachment" accept=".jpg,.jpeg,.png,.pdf">
ATTACHMENT_INPUT = "#attachment"
# <input type="checkbox" name="accept_terms" value="1" required>
TERMS_CHECKBOX = 'input[name="accept_terms"]'
# <div class="g-recaptcha" data-sitekey="..." data-theme="dark"> (reCAPTCHA v2 checkbox)
RECAPTCHA_WIDGET = ".g-recaptcha[data-sitekey]"
RECAPTCHA_RESPONSE = 'textarea[name="g-recaptcha-response"]'
# Honeypot container: positioned off-screen for humans. Its inputs must stay empty.
HONEYPOT_INPUTS = ".hp input, .hp textarea"
# Server-rendered error elements (styles exist in the page CSS).
ALERT = ".alert"
FIELD_ERROR = ".field-error"

# Submission types offered by the form. "raw" (email source) is also offered by the site but is
# out of scope for this tool, which handles one domain / IP / URL per submission.
SUBMISSION_TYPES: dict[str, dict[str, str | int]] = {
    "domain": {"label": "Domain", "input": "#domain", "maxlength": 253},
    "ip": {"label": "IP", "input": "#ip", "maxlength": 64},
    "url": {"label": "URL", "input": "#url", "maxlength": 2000},
}

# Exact <option value="..."> strings of #threat_type.
THREAT_TYPES: list[str] = ["Spam", "Phishing", "Malware", "Botnet C&C", "Fraud / Scam", "Other"]

REASON_MAX_LENGTH = 2000

ATTACHMENT_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf"}
ATTACHMENT_MAX_BYTES = 2 * 1024 * 1024

# Confirmation codes look like CF-XXXXXXXX.
CONFIRMATION_CODE_RE = re.compile(r"\bCF-[A-Z0-9]{8}\b", re.IGNORECASE)
