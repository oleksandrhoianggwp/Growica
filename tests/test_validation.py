import pytest

from formbot.validation import (
    ValidationError,
    dedup_key,
    normalize_domain,
    normalize_ip,
    normalize_url,
    parse_targets,
    validate_attachment,
    validate_reason,
    validate_threat_type,
)

from .conftest import PDF_BYTES, PNG_BYTES


@pytest.mark.parametrize("raw,expected", [("Example.COM", "example.com"), ("sub.example.org.", "sub.example.org"),
                                          ("  xn--80ak6aa92e.com ", "xn--80ak6aa92e.com"), ("пример.рф", "пример.рф")])
def test_domain_valid(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["localhost", "http://example.com", "example.com/path", "-bad.com", "exa mple.com",
                                 "example.c", "a" * 64 + ".com", "example.com:8080"])
def test_domain_invalid(raw):
    with pytest.raises(ValidationError):
        normalize_domain(raw)


def test_ip():
    assert normalize_ip(" 192.0.2.1 ") == "192.0.2.1"
    assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    for bad in ("256.1.1.1", "1.2.3", "example.com", ""):
        with pytest.raises(ValidationError):
            normalize_ip(bad)


def test_url():
    assert normalize_url("https://example.com/a?b=1") == "https://example.com/a?b=1"
    assert normalize_url("http://192.0.2.1:8080/x") == "http://192.0.2.1:8080/x"
    for bad in ("example.com/page", "ftp://example.com", "https://", "https://exa mple.com", "https://x/" + "a" * 2000):
        with pytest.raises(ValidationError):
            normalize_url(bad)


def test_parse_targets_dedups_and_reports_line_numbers():
    text = "example.com\n\nEXAMPLE.com\nbad_domain\nfoo.org\n"
    targets, errors = parse_targets(text, "domain", 10)
    assert [(t.line_no, t.value) for t in targets] == [(1, "example.com"), (5, "foo.org")]
    assert len(errors) == 1 and errors[0].startswith("line 4")


def test_parse_targets_limits():
    targets, errors = parse_targets("\n".join(f"h{i}.com" for i in range(5)), "domain", 3)
    assert any("too many targets" in e for e in errors)
    assert parse_targets("   \n", "ip", 3)[1] == ["enter at least one target (one per line)"]
    assert parse_targets("x", "raw", 3)[1] == ["unsupported submission type 'raw'"]


def test_threat_and_reason():
    assert validate_threat_type("Botnet C&C") == "Botnet C&C"
    with pytest.raises(ValidationError):
        validate_threat_type("Botnet")
    assert validate_reason("  hello ") == "hello"
    with pytest.raises(ValidationError):
        validate_reason("   ")
    with pytest.raises(ValidationError):
        validate_reason("x" * 2001)


def test_attachment():
    assert validate_attachment("C:\\fakepath\\shot 1.PNG", PNG_BYTES) == "shot_1.png"
    assert validate_attachment("doc.pdf", PDF_BYTES) == "doc.pdf"
    with pytest.raises(ValidationError, match="JPG, JPEG, PNG or PDF"):
        validate_attachment("a.gif", b"GIF89a")
    with pytest.raises(ValidationError, match="does not match"):
        validate_attachment("a.jpg", PNG_BYTES)
    with pytest.raises(ValidationError, match="2 MB"):
        validate_attachment("a.pdf", b"%PDF-" + b"0" * (2 * 1024 * 1024))
    with pytest.raises(ValidationError, match="empty"):
        validate_attachment("a.png", b"")


def test_dedup_key():
    assert dedup_key("domain", "Example.com", "Spam") == dedup_key("domain", "example.com", "Spam")
    assert dedup_key("domain", "example.com", "Spam") != dedup_key("domain", "example.com", "Phishing")
    assert dedup_key("url", "https://e.com/A", "Spam") != dedup_key("url", "https://e.com/a", "Spam")
