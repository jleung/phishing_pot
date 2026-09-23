"""Offline, metadata-only feature extraction for eligible RFC email bytes."""

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from dataclasses import replace
from email import policy
from email.header import decode_header
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from phishing_contract.models import (
    AttachmentMetadata,
    CorpusManifest,
    FeatureRecord,
    Provenance,
    SourceRecord,
)

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w.-]+")


def extract_feature_record(
    corpus_directory: Path, source: SourceRecord
) -> FeatureRecord:
    """Extract safe metadata from one eligible file without rendering or traversal."""
    raw_bytes = (corpus_directory / source.relative_path).read_bytes()
    if not raw_bytes:
        return _empty_feature(source)

    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    body_text, charsets, attachments, flags = _content_metadata(message)
    from_domain = _address_domain(_decoded_header(message, "From"))
    reply_to_domain = _address_domain(_decoded_header(message, "Reply-To"))
    envelope_domain = _address_domain(_decoded_header(message, "Return-Path"))
    urls: tuple[str, ...] = tuple(URL_PATTERN.findall(body_text))
    safe_body = _safe_text(body_text)
    quality_flags = _quality_flags(message, safe_body, flags)
    return FeatureRecord(
        source=source,
        subject=_safe_text(_decoded_header(message, "Subject")),
        body_evidence=safe_body,
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        envelope_domain=envelope_domain,
        sender_reply_agree=_domains_agree(from_domain, reply_to_domain),
        sender_envelope_agree=_domains_agree(from_domain, envelope_domain),
        mime_form=message.get_content_type(),
        attachments=attachments,
        url_count=len(urls),
        url_host_hashes=tuple(
            sorted({_host_hash(url) for url in urls if _host_hash(url)})
        ),
        languages=_language_indicators(safe_body),
        charsets=tuple(sorted(charsets)),
        unicode_obfuscation=_has_unicode_obfuscation(safe_body),
        authentication=_authentication_indicators(message),
        quality_flags=quality_flags,
        provenance=Provenance(
            source_commit="unavailable",
            config_digest=source.sha256,
            model_identifier="openai/gpt-5.6-terra",
        ),
    )


def serialize_feature(record: FeatureRecord) -> str:
    """Serialize one feature as canonical newline-terminated JSONL."""
    return json.dumps(record.as_json(), sort_keys=True) + "\n"


def extract_feature_records(
    corpus_directory: Path, manifest: CorpusManifest
) -> tuple[FeatureRecord, ...]:
    """Extract stable feature records in the manifest's deterministic order."""
    return tuple(
        replace(
            extract_feature_record(corpus_directory, source),
            provenance=manifest.provenance,
        )
        for source in manifest.records
    )


def write_features(records: tuple[FeatureRecord, ...], output_path: Path) -> None:
    """Write deterministic newline-delimited feature artifacts without raw payloads."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _ = output_path.write_text(
        "".join(serialize_feature(record) for record in records), encoding="utf-8"
    )


def _content_metadata(
    message: EmailMessage,
) -> tuple[str, set[str], tuple[AttachmentMetadata, ...], set[str]]:
    body_parts: list[str] = []
    charsets: set[str] = set()
    attachments: list[AttachmentMetadata] = []
    flags: set[str] = set()
    for part in message.walk():
        charset = part.get_content_charset()
        if charset is not None:
            charsets.add(charset.lower())
        decoded_payload = part.get_payload(decode=True)
        payload = decoded_payload if isinstance(decoded_payload, bytes) else b""
        if part.get_content_disposition() == "attachment":
            attachments.append(_attachment_metadata(part.get_filename(), payload))
        elif part.get_content_maintype() == "text" and not part.is_multipart():
            body_parts.append(_decode_bytes(payload, charset, flags))
        if part.get("Content-Transfer-Encoding", "").lower() == "base64":
            raw_payload = part.get_payload(decode=False)
            if isinstance(raw_payload, str | bytes):
                _validate_base64(raw_payload, flags)
    return "\n".join(body_parts), charsets, tuple(attachments), flags


def _attachment_metadata(name: str | None, payload: bytes) -> AttachmentMetadata:
    safe_name = _safe_text(name or "unnamed")
    suffix = Path(safe_name).suffix.lower().removeprefix(".")
    return AttachmentMetadata(
        name=safe_name,
        extension=suffix,
        byte_size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _decode_bytes(payload: bytes, charset: str | None, flags: set[str]) -> str:
    encoding = charset or "utf-8"
    try:
        return payload.decode(encoding, errors="replace")
    except LookupError:
        flags.add("unknown_charset")
        return payload.decode("utf-8", errors="replace")


def _validate_base64(payload: str | bytes | None, flags: set[str]) -> None:
    if isinstance(payload, str):
        try:
            _ = base64.b64decode(payload.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError):
            flags.add("invalid_transfer_encoding")
            flags.add("malformed")


def _decoded_header(message: EmailMessage, header_name: str) -> str:
    raw_value = message.get(header_name, "")
    if not isinstance(raw_value, str):
        return ""
    parts = cast(
        "list[tuple[bytes | str, str | None]]", decode_header(raw_value)
    )
    return "".join(
        value.decode(charset or "utf-8", errors="replace")
        if isinstance(value, bytes)
        else value
        for value, charset in parts
    )


def _safe_text(value: str) -> str:
    without_urls = URL_PATTERN.sub("[url]", value)
    without_emails = EMAIL_PATTERN.sub("[email]", without_urls)
    return " ".join(without_emails.split())


def _address_domain(value: str) -> str:
    match = EMAIL_PATTERN.search(value)
    return "" if match is None else match.group().rsplit("@", maxsplit=1)[1].lower()


def _domains_agree(first: str, second: str) -> bool:
    return bool(first) and first == second


def _host_hash(url: str) -> str:
    host = urlsplit(url).hostname
    return "" if host is None else hashlib.sha256(host.lower().encode()).hexdigest()


def _language_indicators(text: str) -> tuple[str, ...]:
    labels: set[str] = {"ascii"} if text.isascii() else {"unicode"}
    if any("CJK" in unicodedata.name(char, "") for char in text):
        labels.add("cjk")
    return tuple(sorted(labels))


def _has_unicode_obfuscation(text: str) -> bool:
    return any(unicodedata.category(char).startswith("M") for char in text)


def _authentication_indicators(message: EmailMessage) -> tuple[str, ...]:
    values = " ".join(message.get_all("Authentication-Results", []))
    indicators = {item for item in ("spf", "dkim", "dmarc") if item in values.lower()}
    return tuple(sorted(indicators))


def _quality_flags(
    message: EmailMessage, text: str, flags: set[str]
) -> tuple[str, ...]:
    if message.defects:
        flags.add("malformed")
    if not text:
        flags.add("low_text")
    return tuple(sorted(flags))


def _empty_feature(source: SourceRecord) -> FeatureRecord:
    return FeatureRecord(
        source=source,
        subject="",
        body_evidence="",
        from_domain="",
        reply_to_domain="",
        envelope_domain="",
        sender_reply_agree=False,
        sender_envelope_agree=False,
        mime_form="",
        attachments=(),
        url_count=0,
        url_host_hashes=(),
        languages=(),
        charsets=(),
        unicode_obfuscation=False,
        authentication=(),
        quality_flags=("empty",),
        provenance=Provenance("unavailable", source.sha256, "openai/gpt-5.6-terra"),
    )
