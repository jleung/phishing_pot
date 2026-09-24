"""Typed, serializable records for the offline corpus-contract artifact."""

from dataclasses import dataclass
from pathlib import Path
from typing import NewType, TypedDict

SampleId = NewType("SampleId", int)


class SourceRecordJson(TypedDict):
    """Stable JSON representation of an eligible corpus file."""

    sample_id: int
    relative_path: str
    byte_size: int
    sha256: str


class ExclusionJson(TypedDict):
    """Stable JSON representation of a file excluded from the contract."""

    relative_path: str
    reason: str


class ProvenanceJson(TypedDict):
    """Stable JSON representation of an artifact's reproducibility metadata."""

    source_commit: str
    config_digest: str
    model_identifier: str


class ManifestJson(TypedDict):
    """Stable JSON schema for a Task 1 corpus manifest."""

    schema_version: int
    eligible_record_count: int
    empty_record_count: int
    parse_failure_count: int
    records: list[SourceRecordJson]
    exclusions: list[ExclusionJson]
    provenance: ProvenanceJson


class AttachmentJson(TypedDict):
    """Safe metadata for an attachment whose content is never emitted."""

    name: str
    extension: str
    byte_size: int
    sha256: str


class FeatureJson(TypedDict):
    """Stable JSONL schema for normalized, privacy-preserving email features."""

    sample_id: int
    relative_path: str
    subject: str
    body_evidence: str
    from_domain: str
    reply_to_domain: str
    envelope_domain: str
    sender_reply_agree: bool
    sender_envelope_agree: bool
    mime_form: str
    attachments: list[AttachmentJson]
    url_count: int
    url_host_hashes: list[str]
    url_host_matches_from: bool
    languages: list[str]
    charsets: list[str]
    unicode_obfuscation: bool
    from_display_name: str
    message_id_domain: str
    spf_result: str
    dkim_result: str
    dmarc_result: str
    header_encoding_anomaly: bool
    quality_flags: list[str]
    provenance: ProvenanceJson


@dataclass(frozen=True, slots=True)
class ManifestConfiguration:
    """Validated inputs controlling a single manifest generation run."""

    corpus_directory: Path
    model_identifier: str
    source_commit: str


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """Safe metadata for one eligible EML file, without parsed message content."""

    sample_id: SampleId
    relative_path: str
    byte_size: int
    sha256: str

    def as_json(self) -> SourceRecordJson:
        """Return safe metadata in the artifact's stable JSON shape."""
        return SourceRecordJson(
            sample_id=int(self.sample_id),
            relative_path=self.relative_path,
            byte_size=self.byte_size,
            sha256=self.sha256,
        )


@dataclass(frozen=True, slots=True)
class Exclusion:
    """A discovered filesystem entry that is outside the EML filename contract."""

    relative_path: str
    reason: str

    def as_json(self) -> ExclusionJson:
        """Return the exclusion record in the artifact's stable JSON shape."""
        return ExclusionJson(relative_path=self.relative_path, reason=self.reason)


@dataclass(frozen=True, slots=True)
class Provenance:
    """Reproducibility inputs recorded with every generated manifest."""

    source_commit: str
    config_digest: str
    model_identifier: str

    def as_json(self) -> ProvenanceJson:
        """Return reproducibility metadata in the artifact's stable JSON shape."""
        return ProvenanceJson(
            source_commit=self.source_commit,
            config_digest=self.config_digest,
            model_identifier=self.model_identifier,
        )


@dataclass(frozen=True, slots=True)
class CorpusManifest:
    """Deterministic, metadata-only inventory for an eligible EML corpus."""

    schema_version: int
    records: tuple[SourceRecord, ...]
    exclusions: tuple[Exclusion, ...]
    empty_record_count: int
    parse_failure_count: int
    provenance: Provenance

    def as_json(self) -> ManifestJson:
        """Return the complete metadata-only manifest artifact shape."""
        return ManifestJson(
            schema_version=self.schema_version,
            eligible_record_count=len(self.records),
            empty_record_count=self.empty_record_count,
            parse_failure_count=self.parse_failure_count,
            records=[record.as_json() for record in self.records],
            exclusions=[exclusion.as_json() for exclusion in self.exclusions],
            provenance=self.provenance.as_json(),
        )


@dataclass(frozen=True, slots=True)
class AttachmentMetadata:
    """Attachment metadata derived transiently without exposing body bytes."""

    name: str
    extension: str
    byte_size: int
    sha256: str

    def as_json(self) -> AttachmentJson:
        """Return the attachment's metadata-only stable JSON shape."""
        return AttachmentJson(
            name=self.name,
            extension=self.extension,
            byte_size=self.byte_size,
            sha256=self.sha256,
        )


@dataclass(frozen=True, slots=True)
class FeatureRecord:
    """One safe normalized feature record for an eligible source email."""

    source: SourceRecord
    subject: str
    body_evidence: str
    from_domain: str
    reply_to_domain: str
    envelope_domain: str
    sender_reply_agree: bool
    sender_envelope_agree: bool
    mime_form: str
    attachments: tuple[AttachmentMetadata, ...]
    url_count: int
    url_host_hashes: tuple[str, ...]
    url_host_matches_from: bool
    languages: tuple[str, ...]
    charsets: tuple[str, ...]
    unicode_obfuscation: bool
    from_display_name: str
    message_id_domain: str
    spf_result: str
    dkim_result: str
    dmarc_result: str
    header_encoding_anomaly: bool
    quality_flags: tuple[str, ...]
    provenance: Provenance

    def as_json(self) -> FeatureJson:
        """Return the feature record's stable, content-safe JSON shape."""
        return FeatureJson(
            sample_id=int(self.source.sample_id),
            relative_path=self.source.relative_path,
            subject=self.subject,
            body_evidence=self.body_evidence,
            from_domain=self.from_domain,
            reply_to_domain=self.reply_to_domain,
            envelope_domain=self.envelope_domain,
            sender_reply_agree=self.sender_reply_agree,
            sender_envelope_agree=self.sender_envelope_agree,
            mime_form=self.mime_form,
            attachments=[attachment.as_json() for attachment in self.attachments],
            url_count=self.url_count,
            url_host_hashes=list(self.url_host_hashes),
            url_host_matches_from=self.url_host_matches_from,
            languages=list(self.languages),
            charsets=list(self.charsets),
            unicode_obfuscation=self.unicode_obfuscation,
            from_display_name=self.from_display_name,
            message_id_domain=self.message_id_domain,
            spf_result=self.spf_result,
            dkim_result=self.dkim_result,
            dmarc_result=self.dmarc_result,
            header_encoding_anomaly=self.header_encoding_anomaly,
            quality_flags=list(self.quality_flags),
            provenance=self.provenance.as_json(),
        )
