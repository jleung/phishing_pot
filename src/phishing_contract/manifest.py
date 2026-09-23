"""Deterministic, metadata-only discovery for the EML filename contract."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final, override

from phishing_contract.models import (
    CorpusManifest,
    Exclusion,
    ManifestConfiguration,
    Provenance,
    SampleId,
    SourceRecord,
)
from phishing_contract.policy import ensure_model_allowed

MANIFEST_SCHEMA_VERSION: Final = 1
SAMPLE_FILE_PATTERN: Final = re.compile(r"sample-([0-9]+)\.eml\Z")
FILE_READ_CHUNK_SIZE: Final = 1_048_576


@dataclass(frozen=True, slots=True)
class DuplicateSampleIdError(Exception):
    """Raised when distinct filenames normalize to the same numeric sample ID."""

    sample_id: SampleId
    relative_paths: tuple[str, ...]

    @override
    def __str__(self) -> str:
        """Describe duplicate filename metadata without reading email content."""
        paths = ", ".join(self.relative_paths)
        return f"Duplicate sample ID {self.sample_id}: {paths}"


def build_manifest(config: ManifestConfiguration) -> CorpusManifest:
    """Discover direct EML children without parsing message data."""
    ensure_model_allowed(config.model_identifier)
    records: list[SourceRecord] = []
    exclusions: list[Exclusion] = []

    for entry in sorted(config.corpus_directory.iterdir(), key=lambda path: path.name):
        match = SAMPLE_FILE_PATTERN.fullmatch(entry.name)
        if entry.is_symlink():
            exclusions.append(
                Exclusion(relative_path=entry.name, reason="symbolic_link")
            )
        elif not entry.is_file():
            exclusions.append(
                Exclusion(relative_path=entry.name, reason="not_regular_file")
            )
        elif match is None:
            exclusions.append(
                Exclusion(relative_path=entry.name, reason=_exclusion_reason(entry))
            )
        else:
            sample_id = SampleId(int(match.group(1)))
            byte_size, sha256 = _metadata_for_file(entry)
            records.append(
                SourceRecord(
                    sample_id=sample_id,
                    relative_path=entry.name,
                    byte_size=byte_size,
                    sha256=sha256,
                )
            )

    ordered_records = tuple(sorted(records, key=lambda record: int(record.sample_id)))
    _raise_if_duplicate_ids(ordered_records)
    ordered_exclusions = tuple(
        sorted(exclusions, key=lambda exclusion: exclusion.relative_path)
    )
    empty_record_count = sum(record.byte_size == 0 for record in ordered_records)

    return CorpusManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        records=ordered_records,
        exclusions=ordered_exclusions,
        empty_record_count=empty_record_count,
        parse_failure_count=0,
        provenance=Provenance(
            source_commit=config.source_commit,
            config_digest=_configuration_digest(config),
            model_identifier=config.model_identifier,
        ),
    )


def serialize_manifest(manifest: CorpusManifest) -> str:
    """Serialize a manifest into canonical, newline-terminated JSON."""
    return json.dumps(manifest.as_json(), indent=2, sort_keys=True) + "\n"


def write_manifest(manifest: CorpusManifest, output_path: Path) -> None:
    """Persist a manifest through one deterministic JSON file write."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _ = output_path.write_text(serialize_manifest(manifest), encoding="utf-8")


def _exclusion_reason(entry: Path) -> str:
    if entry.suffix == ".eml":
        return "filename_out_of_contract"
    return "non_eml_extension"


def _metadata_for_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    byte_size = 0
    with path.open("rb") as source_file:
        while chunk := source_file.read(FILE_READ_CHUNK_SIZE):
            byte_size += len(chunk)
            digest.update(chunk)
    return byte_size, digest.hexdigest()


def _raise_if_duplicate_ids(records: tuple[SourceRecord, ...]) -> None:
    for index, record in enumerate(records[1:], start=1):
        previous = records[index - 1]
        if record.sample_id == previous.sample_id:
            raise DuplicateSampleIdError(
                sample_id=record.sample_id,
                relative_paths=(previous.relative_path, record.relative_path),
            )


def _configuration_digest(config: ManifestConfiguration) -> str:
    stable_config = "\x00".join(
        (
            str(MANIFEST_SCHEMA_VERSION),
            config.corpus_directory.as_posix(),
            config.model_identifier,
        )
    )
    return hashlib.sha256(stable_config.encode("utf-8")).hexdigest()
