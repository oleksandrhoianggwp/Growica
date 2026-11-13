from formbot.submitter import PageSnapshot, SubmissionJob, analyze_response, detect_block, extract_confirmation_codes

JOB = SubmissionJob(submission_id=1, submission_type="domain", target="example.com", threat_type="Spam", reason="spam")


def snap(text="", alerts=(), field_errors=(), form_present=False, status=200, title="Report"):
    return PageSnapshot(url="https://x/submit", status=status, title=title, text=text, alerts=list(alerts),
                        field_errors=list(field_errors), form_present=form_present)


def test_code_extracted():
    result = analyze_response(snap("Thank you. Your confirmation code is CF-1A2B3C4D."), JOB)
    assert result.status == "submitted" and result.confirmation_code == "CF-1A2B3C4D"


def test_code_echoed_from_input_is_ignored():
    job = SubmissionJob(1, "domain", "example.com", "Spam", "previous report CF-AAAAAAAA was ignored")
    result = analyze_response(snap("Error. You wrote: previous report CF-AAAAAAAA was ignored", form_present=True), job)
    assert result.confirmation_code is None and result.status == "failed"


def test_code_not_matched_when_too_short_or_long():
    assert extract_confirmation_codes("CF-1234567 CF-123456789 xCF-12345678", []) == []
    assert extract_confirmation_codes("code: cf-abcdefgh", []) == ["CF-ABCDEFGH"]


def test_server_errors_are_reported():
    result = analyze_response(
        snap(form_present=True, alerts=["Please correct the errors below."],
             field_errors=[("Domain", "Enter a valid domain.")]), JOB)
    assert result.status == "failed"
    assert "Please correct the errors below." in result.error and "Domain: Enter a valid domain." in result.error
    assert not result.retryable and not result.outcome_uncertain


def test_captcha_error_is_retryable_and_flagged():
    result = analyze_response(snap(form_present=True, alerts=["CAPTCHA verification failed."]), JOB)
    assert result.retryable and result.details["captcha_rejected"]


def test_block_pages():
    assert detect_block("Just a moment...", "", 403)
    result = analyze_response(snap("", status=429, title="Too Many Requests"), JOB)
    assert result.status == "failed" and result.retryable


def test_success_without_code():
    result = analyze_response(snap("Thank you, your report has been received."), JOB)
    assert result.status == "submitted" and result.confirmation_code is None and result.note


def test_unknown_page_is_uncertain():
    result = analyze_response(snap("Something odd", form_present=False), JOB)
    assert result.status == "failed" and result.outcome_uncertain


def test_5xx_is_uncertain():
    result = analyze_response(snap("Internal Server Error", status=500), JOB)
    assert result.status == "failed" and result.outcome_uncertain
