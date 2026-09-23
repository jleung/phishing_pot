from pathlib import Path

import pytest

from phishing_contract.manifest import (
    DuplicateSampleIdError,
    build_manifest,
    serialize_manifest,
)
from phishing_contract.models import ManifestConfiguration

FIXTURES = Path(__file__).parent / "fixtures" / "corpus-contract"


def test_manifest_discovers_only_contract_eml_files_deterministically() -> None:
    # Given: a byte-only fixture corpus with eligible and excluded files.
    config = ManifestConfiguration(
        corpus_directory=FIXTURES / "valid",
        model_identifier="openai/gpt-5.6-terra",
        source_commit="test-commit",
    )

    # When: the offline corpus contract produces a manifest.
    manifest = build_manifest(config)

    # Then: it records stable eligible metadata and explicit exclusions only.
    assert [record.sample_id for record in manifest.records] == [2, 4, 10]
    assert manifest.records[0].relative_path == "sample-2.eml"
    assert manifest.records[0].byte_size == 3
    assert (
        manifest.records[0].sha256
        == "5751a7858912e3f21c17bc0d2df884a231d5dce900c68eedf7dd1f59584c914e"
    )
    assert manifest.empty_record_count == 1
    assert manifest.parse_failure_count == 0
    assert [exclusion.relative_path for exclusion in manifest.exclusions] == [
        "not-an-email.eml",
        "sample-3989.csv",
    ]
    assert "excluded fixture bytes" not in serialize_manifest(manifest)


def test_manifest_rejects_duplicate_numeric_sample_ids() -> None:
    # Given: two contract filenames that normalize to the same sample ID.
    config = ManifestConfiguration(
        corpus_directory=FIXTURES / "duplicate-ids",
        model_identifier="openai/gpt-5.6-terra",
        source_commit="test-commit",
    )

    # When: the offline corpus contract produces a manifest.
    # Then: it reports structured validation for the duplicate ID.
    with pytest.raises(DuplicateSampleIdError, match="sample ID 1"):
        _ = build_manifest(config)
