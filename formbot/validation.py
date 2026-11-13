"""Input validation for targets, form text fields and attachments."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import PurePath
from urllib.parse import urlsplit

from . import form_spec

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class ValidationError(ValueError):
    """A user-facing validation problem."""


@dataclass(frozen=True)
class TargetLine:
    line_no: int
    value: str


def normalize_domain(raw: str) -> str:
    value = raw.strip().rstrip(".").lower()
    if not value:
        raise ValidationError("empty domain")
    if "://" in value or "/" in value or ":" in value or " " in value:
        raise ValidationError("a domain must not contain a scheme, path, port or spaces (use URL type for links)")
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError("not a valid internationalised domain name") from exc
    if len(ascii_value) > 253:
        raise ValidationError("domain is longer than 253 characters")
    labels = ascii_value.split(".")
    if len(labels) < 2:
        raise ValidationError("domain needs at least one dot, e.g. example.com")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise ValidationError("domain contains an invalid label")
    if not _TLD_RE.match(labels[-1]):
        raise ValidationError("domain has an invalid top-level domain")
    return value


def normalize_ip(raw: str) -> str:
    value = raw.strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError("not a valid IPv4 or IPv6 address") from exc
    return ip.compressed


def normalize_url(raw: str) -> str:
    value = raw.strip()
    if any(ch.isspace() for ch in value):
        raise ValidationError("URL must not contain spaces")
    if len(value) > int(form_spec.SUBMISSION_TYPES["url"]["maxlength"]):
        raise ValidationError("URL is longer than 2000 characters")
    parts = urlsplit(value)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValidationError("URL must start with http:// or https://")
    if not parts.hostname:
        raise ValidationError("URL has no host")
    host = parts.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        normalize_domain(host)  # raises ValidationError if the host is not a domain
    return value


NORMALIZERS = {"domain": normalize_domain, "ip": normalize_ip, "url": normalize_url}


def parse_targets(text: str, submission_type: str, max_targets: int) -> tuple[list[TargetLine], list[str]]:
    """Split the textarea into one target per line.

    Returns (targets, errors). Blank lines are ignored, duplicates inside the batch are removed
    (keeping the first occurrence). Any invalid line produces an error mentioning its line number.
    """
    if submission_type not in NORMALIZERS:
        return [], [f"unsupported submission type {submission_type!r}"]
    normalize = NORMALIZERS[submission_type]
    targets: list[TargetLine] = []
    errors: list[str] = []
    seen: set[str] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = normalize(line)
        except ValidationError as exc:
            errors.append(f"line {line_no} ({line.strip()[:80]!r}): {exc}")
            continue
        key = value.lower() if submission_type != "url" else value
        if key in seen:
            continue
        seen.add(key)
        targets.append(TargetLine(line_no, value))
    if not targets and not errors:
        errors.append("enter at least one target (one per line)")
    if len(targets) > max_targets:
        errors.append(f"too many targets: {len(targets)} (limit is {max_targets} per batch)")
    return targets, errors


def validate_threat_type(value: str) -> str:
    if value not in form_spec.THREAT_TYPES:
        raise ValidationError(f"threat type must be one of: {', '.join(form_spec.THREAT_TYPES)}")
    return value


def validate_reason(value: str) -> str:
    text = value.strip()
    if not text:
        raise ValidationError("reason is required")
    if len(text) > form_spec.REASON_MAX_LENGTH:
        raise ValidationError(f"reason is longer than {form_spec.REASON_MAX_LENGTH} characters")
    return text


def validate_attachment(filename: str, content: bytes) -> str:
    """Validate an uploaded attachment and return a safe file name for it."""
    name = PurePath(filename.replace("\\", "/")).name
    suffix = PurePath(name).suffix.lower()
    if suffix not in form_spec.ATTACHMENT_EXTENSIONS:
        raise ValidationError("attachment must be a JPG, JPEG, PNG or PDF file")
    if not content:
        raise ValidationError("attachment is empty")
    if len(content) > form_spec.ATTACHMENT_MAX_BYTES:
        raise ValidationError("attachment is larger than 2 MB")
    is_jpeg = content.startswith(b"\xff\xd8\xff")
    is_png = content.startswith(b"\x89PNG\r\n\x1a\n")
    is_pdf = content.lstrip()[:5] == b"%PDF-"
    expected = {".jpg": is_jpeg, ".jpeg": is_jpeg, ".png": is_png, ".pdf": is_pdf}[suffix]
    if not expected:
        raise ValidationError(f"attachment content does not match its {suffix} extension")
    stem = _SAFE_NAME_RE.sub("_", PurePath(name).stem).strip("._") or "attachment"
    return f"{stem[:80]}{suffix}"


def dedup_key(submission_type: str, target: str, threat_type: str) -> str:
    """Identity of a report used for duplicate prevention: same type + target + threat type."""
    normalized = target if submission_type == "url" else target.lower()
    raw = f"{submission_type}\x1f{normalized}\x1f{threat_type}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
