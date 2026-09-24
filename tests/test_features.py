from pathlib import Path

from phishing_contract.features import extract_feature_record, serialize_feature
from phishing_contract.models import SampleId, SourceRecord

FIXTURES = Path(__file__).parent / "fixtures" / "features"


def test_feature_record_redacts_urls_and_recipients_and_keeps_host_metadata() -> None:
    # Given: a text fixture with a recipient and a URL carrying a query string.
    record = SourceRecord(
        sample_id=SampleId(1),
        relative_path="sample-1.eml",
        byte_size=(FIXTURES / "sample-1.eml").stat().st_size,
        sha256="fixture",
    )

    # When: the offline extractor reads the eligible fixture.
    feature = extract_feature_record(FIXTURES, record)

    # Then: text evidence is redacted while host metadata remains available.
    assert feature.url_count == 1
    assert feature.url_host_hashes
    assert feature.url_host_matches_from is True
    assert "recipient@example.test" not in feature.body_evidence
    assert "secret=token" not in feature.body_evidence
    assert "[url]" in feature.body_evidence


def test_feature_record_reports_attachment_metadata_and_quality_flags() -> None:
    # Given: multipart, malformed, and empty byte-only EML fixtures.
    mixed = SourceRecord(SampleId(2), "sample-2.eml", 0, "fixture")
    malformed = SourceRecord(SampleId(3), "sample-3.eml", 0, "fixture")
    empty = SourceRecord(SampleId(4), "sample-4.eml", 0, "fixture")

    # When: the extractor reads each eligible fixture.
    mixed_feature = extract_feature_record(FIXTURES, mixed)
    malformed_feature = extract_feature_record(FIXTURES, malformed)
    empty_feature = extract_feature_record(FIXTURES, empty)

    # Then: attachment bytes remain absent from output and failures are flagged.
    assert mixed_feature.attachments[0].extension == "pdf"
    assert mixed_feature.attachments[0].byte_size > 0
    assert "attachment-body" not in serialize_feature(mixed_feature)
    assert "malformed" in malformed_feature.quality_flags
    assert "empty" in empty_feature.quality_flags
