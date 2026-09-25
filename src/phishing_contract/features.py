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
from phishing_contract.textfold import (
    has_math_stylization,
    is_encoded_body,
)

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w.-]+")
ENCODED_WORD_PATTERN = re.compile(r"=\?[A-Za-z0-9_-]+\?[QqBb]\?")
AUTH_MECHANISMS: Final = ("spf", "dkim", "dmarc")
FREE_SUBDOMAIN_SUFFIXES: Final = frozenset(
    {
        "eu.org",
        "uk.to",
        "us.to",
        "za.to",
        "eu.com",
        "eu.net",
        "eu.bz",
    }
)
DISPOSABLE_TLDS: Final = frozenset(
    {
        "tk", "ml", "ga", "cf", "gq", "top", "click", "icu",
        "buzz", "rest", "quest", "monster",
    }
)
CDN_HOST_SUFFIXES: Final = frozenset(
    {
        "github.io",
        "netlify.app",
        "vercel.app",
        "pages.dev",
        "s3.amazonaws.com",
        "s3.eu-central-1.amazonaws.com",
        "blob.core.windows.net",
        "storage.googleapis.com",
        "digitaloceanspaces.com",
        "fastly.net",
        "cloudfront.net",
    }
)
BRAND_CLAIM_BRANDS: Final = {
    "apple": ("apple.com", "icloud.com", "apple", "iphone", "ipad"),
    "google": ("google.com", "gmail.com", "gstatic.com", "google", "gmail"),
    "microsoft": (
        "microsoft.com", "live.com", "office.com", "outlook.com",
        "microsoft", "outlook",
    ),
    "paypal": ("paypal.com", "paypal", "sandvik"),
    "amex": ("amex.com", "americanexpress.com", "amex", "american express"),
    "visa": ("visa.com", "visa"),
    "mastercard": ("mastercard.com", "mastercard"),
    "netflix": ("netflix.com", "netflix"),
    "amazon": ("amazon.com", "amazon", "prime"),
    "ebay": ("ebay.com", "ebay"),
    "dyson": ("dyson.com", "dyson"),
    "adidas": ("adidas.com", "adidas"),
    "apple-store": (),
    "n26": ("n26.com", "n26"),
    "revolut": ("revolut.com", "revolut"),
    "wise": ("wise.com", "wisesender.com", "wise"),
    "postnl": ("post.nl", "postnl"),
    "dlv": ("dlv.nl", "dlv"),
    "bpost": ("bpost.be", "bpost"),
    "dhl": ("dhl.com", "dhl", "dhlec"),
    "fedex": ("fedex.com", "fedex"),
    "ups": ("ups.com", "ups"),
    "bradesco": ("bradesco.com.br", "bradesco"),
    "itau": ("itau.com.br", "itau"),
    "knab": ("knab.nl", "knab"),
    "rabobank": ("rabobank.nl", "rabobank"),
    "ing": ("ing.com", "ing.nl", "ing-bank"),
    "sns-bank": ("snsbank.nl", "sns bank"),
    "bunq": ("bunq.com", "bunq"),
    "coinbase": ("coinbase.com", "coinbase"),
    "binance": ("binance.com", "binance"),
    "ledger": ("ledger.com", "ledger"),
    "crypto": (),
    "metamask": ("metamask.io", "metamask"),
    "poe": ("poe.com", "poe"),
    "openai": ("openai.com", "openai"),
    "meta-ai": ("meta.ai", "meta ai"),
    "airline": (),
    "dutch-tax": (),
}
URGENCY_PATTERN = re.compile(
    r"\b(within (24|48) hours?|24 hours|48 hours|last chance|final (notice|warning|reminder)|immediat\w+|act now|urgent\b|no later than\b|by (midnight|end of day|9:5[09])\b|today only|expires? (today|now|immediately)\b|deadline\b|within one day\b|(?:suspension|lock(?:out)?|freeze|block)(?: of| to)? your account\b|om (meteen|direct)\b|uiterlijk\b|vandaag\b|within (24|48)\b)"  # noqa: E501
)
GENERIC_SALUTATION_PATTERN = re.compile(
    r"(?:dear (?:customer|client|user|member|valued)|hallo\b\s*[,;:]|hello\b\s*[,;:]|bonjour\b|guten tag\b|liebe[rs]\b|geachte[rs]\b|estimat[oa]\b|estimat[ao]|cari[as]?\b|caro[oa]\b|d\u00e9ar\b|querido[as]?\b)"  # noqa: E501
)
NAMED_SALUTATION_PATTERN = re.compile(
    r"^(?:hi|hey|hallo|hello|bonjour|guten tag|liebe[rs]|geachte[rs]|estimat[oa]|cari[as]?|caro[oa])\s+(?:\"|\u201c)?([a-z\u00e0-\u00ff]{4,})"  # noqa: E501
)
GENERIC_NAME_WORDS: Final = frozenset(
    {
        "customer",
        "client",
        "user",
        "member",
        "valued",
        "friend",
        "team",
        "everyone",
        "someone",
        "dear",
        "hello",
        "hi",
    }
)
MIN_STOPWORD_HITS: Final = 3
LAST_TWO_LABELS: Final = 2
LANGUAGE_STOPWORDS: Final = {
    "en": frozenset(
        {
            "your", "you", "our", "the", "and", "account", "please", "click",
            "here", "update", "verify", "security", "we", "will", "not", "for",
            "with", "from",
        }
    ),
    "de": frozenset(
        {
            "und", "nicht", "ihre", "ihrer", "ihren", "ihres", "das", "die",
            "den", "dem", "ein", "eine", "sich", "bitte", "wir", "sind",
            "haben", "kann", "muss", "soll", "auch", "für", "mit",
        }
    ),
    "pt": frozenset(
        {
            "você", "para", "com", "nossa", "sua", "seu", "seus",
            "este", "esta", "isso", "mais", "como", "pela",
            "pelo", "vcs", "cartão", "pontos",
        }
    ),
    "nl": frozenset(
        {
            "u", "uw", "de", "het", "een", "en", "niet", "met", "van", "voor",
            "naar", "ook", "kan", "moet", "zou", "zijn", "is", "bij",
        }
    ),
    "fr": frozenset(
        {
            "vous", "votre", "vos", "et", "le", "la", "les", "une", "des",
            "pour", "avec", "dans", "sur", "pas", "mais", "aussi", "sera",
        }
    ),
    "es": frozenset(
        {
            "su", "sus", "y", "la", "el", "los", "las", "un", "una", "para",
            "con", "en", "de", "por", "que", "no", "como", "está",
        }
    ),
    "it": frozenset(
        {
            "e", "la", "il", "un", "una", "per", "con", "di", "a", "che",
            "non", "ma", "sono", "hai", "suo", "lei",
        }
    ),
}
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
    raw_subject = _decoded_header(message, "Subject")
    safe_body = _safe_text(body_text)
    quality_flags = _quality_flags(message, safe_body, flags)
    auth = _auth_results(message)
    return FeatureRecord(
        source=source,
        subject=_safe_text(raw_subject),
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
        subject_math_stylized=has_math_stylization(raw_subject),
        body_encoded=is_encoded_body(safe_body),
        url_hosts=tuple(sorted({_last_two_labels(host) for host in url_hosts})),
        url_host_classes=tuple(sorted({_url_host_class(host) for host in url_hosts})),
        salutation=_salutation(raw_subject, safe_body),
        urgency=_urgency_level(raw_subject, safe_body),
        brand_claims=_brand_claims(
            _display_name(_decoded_header(message, "From")),
            raw_subject,
            safe_body,
            from_domain,
        ),
        body_math_stylized=has_math_stylization(safe_body),
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


def _last_two_labels(host: str) -> str:
    """Return the normalized last-two-label token for a URL host."""
    parts = [part for part in host.split(".") if part]
    return ".".join(parts[-2:]) if len(parts) >= LAST_TWO_LABELS else host


def _url_host_class(host: str) -> str:
    """Classify one URL host by its risk-bearing structural tell."""
    if host and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return "ip-literal"
    if host in CDN_HOST_SUFFIXES or any(
        host.endswith("." + suffix) for suffix in CDN_HOST_SUFFIXES
    ):
        return "cdn-hosted"
    parts = [part for part in host.split(".") if part]
    if len(parts) >= LAST_TWO_LABELS:
        two_label = ".".join(parts[-2:])
        if two_label in FREE_SUBDOMAIN_SUFFIXES:
            return "free-subdomain"
    if len(parts) == 1:
        return "normal"
    tld = parts[-1]
    if tld in DISPOSABLE_TLDS:
        return "disposable-tld"
    return "normal"


def _salutation(subject: str, body: str) -> str:
    """Return none|generic|named for the first salutation in the email."""
    text = f"{subject} {body[:400]}".casefold()
    named = NAMED_SALUTATION_PATTERN.search(text)
    if named and named.group(1) not in GENERIC_NAME_WORDS:
        return "named"
    if GENERIC_SALUTATION_PATTERN.search(text):
        return "generic"
    return "none"


def _urgency_level(subject: str, body: str) -> int:
    """Bucket deadline/threat/payment-tell match counts as 0, 1, or 2+."""
    text = f"{subject} {body[:1200]}".casefold()
    matches: set[str] = set()
    for match in URGENCY_PATTERN.finditer(text):
        matches.add(match.group(0))
    return min(2, len(matches))


def _brand_claims(
    display_name: str, subject: str, body: str, from_domain: str
) -> tuple[str, ...]:
    """Return static brand slugs claimed in text but absent from the sender domain."""
    text = f"{display_name} {subject} {body[:800]}".casefold()
    claims: set[str] = set()
    for brand, tokens in BRAND_CLAIM_BRANDS.items():
        if not any(token and token in text for token in tokens):
            continue
        if any(token and token in from_domain.casefold() for token in tokens[:3]):
            continue
        claims.add(brand)
    return tuple(sorted(claims))


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
    """Return deterministic stopword-frequency language codes, plus cjk when present."""
    words = set(
        re.findall(r"[a-z\u00e0-\u00ff]{3,}", text.casefold())
    )
    labels: set[str] = set()
    for language, stopwords in LANGUAGE_STOPWORDS.items():
        if len(words & stopwords) >= MIN_STOPWORD_HITS:
            labels.add(language)
    if any("CJK" in unicodedata.name(char, "") for char in text):
        labels.add("cjk")
    return tuple(sorted(labels)) if labels else ("other",)


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
        subject_math_stylized=False,
        body_encoded=False,
    )
