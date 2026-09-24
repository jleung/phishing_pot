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


def test_html_body_becomes_readable_text_evidence() -> None:
    # Given: a fixture whose single part is HTML with tags, script, and styles.
    feature = _extract(9, "sample-9.eml")
    evidence = feature.body_evidence

    # Then: the evidence is visible text, not markup.
    assert "we detected unusual activity" in evidence
    assert "<table" not in evidence
    assert "<p>" not in evidence
    assert "style=" not in evidence
    assert "0800 111 222 333" in evidence


def test_html_urls_count_including_href_but_not_script() -> None:
    # Given: the same HTML fixture with a visible URL, an href URL, and a
    # URL hidden inside a <script> tag.
    feature = _extract(9, "sample-9.eml")

    # Then: both real links count, the script URL does not, and it never
    # leaks into the evidence.
    assert feature.url_count == 2
    assert len(feature.url_host_hashes) == 2
    assert "evil.example" not in feature.body_evidence


def test_malformed_ipv6_urls_do_not_break_extraction() -> None:
    # Given: a fixture whose body contains an unparseable IPv6-style URL.
    feature = _extract(8, "sample-8.eml")

    # Then: extraction survives and hashes only the parseable host.
    assert feature.url_count == 2
    assert len(feature.url_host_hashes) == 1


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
