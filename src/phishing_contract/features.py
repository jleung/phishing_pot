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
from html.parser import HTMLParser
from pathlib import Path
from typing import Final, cast, override
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
ENCODED_WORD_PATTERN = re.compile(r"=\?[A-Za-z0-9_-]+\?[QqBb]\?")
AUTH_MECHANISMS: Final = ("spf", "dkim", "dmarc")
STANDARD_CHARSETS: Final = frozenset({"utf-8", "us-ascii"})
MIN_QUOTED_NAME_LENGTH: Final = 2
SKIP_TAGS: Final = frozenset({"script", "style"})
BLOCK_TAGS: Final = frozenset(
    {
        "br",
        "blockquote",
        "div",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "li",
        "ol",
        "p",
        "pre",
        "section",
        "table",
        "td",
        "tr",
        "ul",
    }
)


def extract_feature_record(
    corpus_directory: Path, source: SourceRecord
) -> FeatureRecord:
    """Extract safe metadata from one eligible file without rendering or traversal."""
    raw_bytes = (corpus_directory / source.relative_path).read_bytes()
    if not raw_bytes:
        return _empty_feature(source)

    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    body_text, charsets, attachments, flags, href_urls = _content_metadata(message)
    from_domain = _address_domain(_decoded_header(message, "From"))
    reply_to_domain = _address_domain(_decoded_header(message, "Reply-To"))
    envelope_domain = _address_domain(_decoded_header(message, "Return-Path"))
    urls: tuple[str, ...] = tuple(URL_PATTERN.findall(body_text)) + href_urls
    url_hosts = tuple(host for host in (_url_host(url) for url in urls) if host)
    safe_body = _safe_text(body_text)
    quality_flags = _quality_flags(message, safe_body, flags)
    auth = _auth_results(message)
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
        url_host_hashes=tuple(sorted({_host_hash(host) for host in url_hosts})),
        url_host_matches_from=_url_host_matches_from(url_hosts, from_domain),
        languages=_language_indicators(safe_body),
        charsets=tuple(sorted(charsets)),
        unicode_obfuscation=_has_unicode_obfuscation(safe_body),
        from_display_name=_display_name(_decoded_header(message, "From")),
        message_id_domain=_message_id_domain(message),
        spf_result=auth["spf"],
        dkim_result=auth["dkim"],
        dmarc_result=auth["dmarc"],
        header_encoding_anomaly=_header_encoding_anomaly(message, charsets),
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
) -> tuple[str, set[str], tuple[AttachmentMetadata, ...], set[str], tuple[str, ...]]:
    body_parts: list[str] = []
    charsets: set[str] = set()
    attachments: list[AttachmentMetadata] = []
    flags: set[str] = set()
    href_urls: list[str] = []
    for part in message.walk():
        charset = part.get_content_charset()
        if charset is not None:
            charsets.add(charset.lower())
        decoded_payload = part.get_payload(decode=True)
        payload = decoded_payload if isinstance(decoded_payload, bytes) else b""
        if part.get_content_disposition() == "attachment":
            attachments.append(_attachment_metadata(part.get_filename(), payload))
        elif part.get_content_maintype() == "text" and not part.is_multipart():
            text = _decode_bytes(payload, charset, flags)
            if part.get_content_subtype() == "html":
                extractor = _HtmlTextExtractor()
                extractor.feed(text)
                extractor.close()
                body_parts.append(extractor.text())
                href_urls.extend(extractor.hrefs)
            else:
                body_parts.append(text)
        if part.get("Content-Transfer-Encoding", "").lower() == "base64":
            raw_payload = part.get_payload(decode=False)
            if isinstance(raw_payload, str | bytes):
                _validate_base64(raw_payload, flags)
    return "\n".join(body_parts), charsets, tuple(attachments), flags, tuple(href_urls)


class _HtmlTextExtractor(HTMLParser):
    """Collect visible text and link targets from markup without rendering."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self.hrefs: list[str] = []
        self._skip_depth: int = 0

    @override
    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag in SKIP_TAGS:
            self._skip_depth += 1
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.hrefs.append(value)
        if tag in BLOCK_TAGS:
            self._chunks.append(" ")

    @override
    def handle_endtag(self, tag: str) -> None:
        if tag in SKIP_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
        elif tag in BLOCK_TAGS:
            self._chunks.append(" ")

    @override
    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self._chunks.append(data)

    def text(self) -> str:
        return " ".join(self._chunks)


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


def _display_name(from_header: str) -> str:
    """Return the normalized display-name portion of a decoded From header."""
    name = from_header
    if "<" not in name:
        return ""
    name = name.split("<", 1)[0]
    name = name.strip().rstrip(" ,_")
    if (
        len(name) >= MIN_QUOTED_NAME_LENGTH
        and name.startswith('"')
        and name.endswith('"')
    ):
        name = name[1:-1]
    return " ".join(name.split())


def _message_id_domain(message: EmailMessage) -> str:
    """Return the lowercased domain of the Message-ID, or '' if absent."""
    raw = message.get("Message-ID", "")
    if not isinstance(raw, str):
        return ""
    value = raw.strip().strip("<>")
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[1].lower()


def _auth_results(message: EmailMessage) -> dict[str, str]:
    """Return per-mechanism Authentication-Results tokens, 'none' if absent."""
    values = " ".join(message.get_all("Authentication-Results", []))
    results: dict[str, str] = {}
    for mechanism in AUTH_MECHANISMS:
        match = re.search(rf"\b{mechanism}=([A-Za-z0-9_-]+)", values)
        results[mechanism] = match.group(1).lower() if match else "none"
    return results


def _header_encoding_anomaly(message: EmailMessage, charsets: set[str]) -> bool:
    """Flag RFC-2047 encoded-word subjects or non-standard charsets."""
    for item in message.raw_items():
        name, raw_value = cast("tuple[str, object]", item)
        if name.lower() != "subject":
            continue
        if isinstance(raw_value, str) and ENCODED_WORD_PATTERN.search(raw_value):
            return True
    return any(charset not in STANDARD_CHARSETS for charset in charsets)


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


def _url_host(url: str) -> str:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return ""
    return "" if host is None else host.lower().rstrip(".")


def _host_hash(host: str) -> str:
    return hashlib.sha256(host.encode()).hexdigest()


def _url_host_matches_from(url_hosts: tuple[str, ...], from_domain: str) -> bool:
    normalized_from = from_domain.lower().rstrip(".")
    if not normalized_from:
        return False
    return any(
        host == normalized_from or host.endswith(f".{normalized_from}")
        for host in url_hosts
    )


def _language_indicators(text: str) -> tuple[str, ...]:
    labels: set[str] = {"ascii"} if text.isascii() else {"unicode"}
    if any("CJK" in unicodedata.name(char, "") for char in text):
        labels.add("cjk")
    return tuple(sorted(labels))


def _has_unicode_obfuscation(text: str) -> bool:
    return any(unicodedata.category(char).startswith("M") for char in text)


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
        url_host_matches_from=False,
        languages=(),
        charsets=(),
        unicode_obfuscation=False,
        from_display_name="",
        message_id_domain="",
        spf_result="none",
        dkim_result="none",
        dmarc_result="none",
        header_encoding_anomaly=False,
        quality_flags=("empty",),
        provenance=Provenance("unavailable", source.sha256, "openai/gpt-5.6-terra"),
    )
