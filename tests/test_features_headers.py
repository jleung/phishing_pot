"""Extraction tests for the header-derived feature fields."""

import json
from pathlib import Path
from typing import cast

from phishing_contract.features import extract_feature_record, serialize_feature
from phishing_contract.models import FeatureRecord, SampleId, SourceRecord

FIXTURES = Path(__file__).parent / "fixtures" / "features-headers"


def _extract(sample_id: int, relative_path: str) -> FeatureRecord:
    record = SourceRecord(
        sample_id=SampleId(sample_id),
        relative_path=relative_path,
        byte_size=0,
        sha256="fixture",
    )
    return extract_feature_record(FIXTURES, record)


def test_header_features_are_derived_from_raw_headers() -> None:
    # Given: a fixture with a display name, Message-ID, auth results, and
    # an encoded subject.
    feature = _extract(5, "sample-5.eml")

    # When: the header-derived fields are inspected.
    # Then: each carries the deterministic, privacy-safe value.
    assert feature.from_display_name == "Microsoft account team"
    assert feature.message_id_domain == "mailer.example"
    assert feature.spf_result == "pass"
    assert feature.dkim_result == "fail"
    assert feature.dmarc_result == "none"
    assert feature.header_encoding_anomaly is True

    # And: the sanitized serialization exposes the new fields.
    payload = cast(
        "dict[str, object]", json.loads(serialize_feature(feature).strip())
    )
    assert payload["spf_result"] == "pass"
    assert payload["dkim_result"] == "fail"
    assert "authentication" not in payload


def test_oddly_formatted_from_header_still_yields_clean_name() -> None:
    # Given: a fixture whose From line has trailing junk after the name.
    feature = _extract(7, "sample-7.eml")

    # Then: the display name is normalized without the junk.
    assert feature.from_display_name == "Microsoft account team"
    assert feature.message_id_domain == "access-accsecurity.com"


def test_missing_header_values_fall_back_to_safe_defaults() -> None:
    # Given: a plain fixture with no display name or auth results.
    feature = _extract(6, "sample-6.eml")

    # Then: every derived field reports its deterministic absent value.
    assert feature.from_display_name == ""
    assert feature.message_id_domain == "example.test"
    assert feature.spf_result == "none"
    assert feature.dkim_result == "none"
    assert feature.dmarc_result == "none"
    assert feature.header_encoding_anomaly is False
