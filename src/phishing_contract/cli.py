"""Command-line interface for deterministic offline corpus manifests."""

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypedDict, override

from phishing_contract.features import extract_feature_records, write_features
from phishing_contract.manifest import (
    DuplicateSampleIdError,
    build_manifest,
    write_manifest,
)
from phishing_contract.models import ManifestConfiguration
from phishing_contract.policy import (
    DEFAULT_MODEL_ID,
    ModelPolicyError,
    ensure_model_allowed,
)

RUN_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")
DEFAULT_OUTPUT_DIRECTORY: Final = "artifacts/manifests"
DEFAULT_SOURCE_COMMIT: Final = "unavailable"
MANIFEST_OPTIONS: Final = frozenset(
    {"--corpus", "--model", "--output-dir", "--run-id", "--source-commit"}
)


class ErrorJson(TypedDict):
    """Structured, content-free error payload emitted by the command line."""

    error: str
    detail: str


class ModelPolicyErrorJson(TypedDict):
    """Structured model-routing rejection emitted before filesystem discovery."""

    error: str
    model_identifier: str


@dataclass(frozen=True, slots=True)
class CliUsageError(Exception):
    """Raised when command-line arguments cannot form a valid manifest request."""

    detail: str

    @override
    def __str__(self) -> str:
        """Describe invalid CLI structure without inspecting corpus files."""
        return self.detail


@dataclass(frozen=True, slots=True)
class ManifestCommand:
    """Parsed command-line values needed to generate one manifest artifact."""

    corpus_directory: Path
    output_directory: Path
    run_id: str
    model_identifier: str
    source_commit: str


def main() -> int:
    """Run the CLI from process arguments and return its exit code."""
    return run(tuple(sys.argv[1:]))


def run(arguments: tuple[str, ...]) -> int:
    """Run a CLI request while converting expected contract failures to JSON."""
    if arguments and arguments[0] == "features":
        return _run_features(arguments[1:])
    try:
        command = _parse_command(arguments)
        ensure_model_allowed(command.model_identifier)
        manifest = build_manifest(
            ManifestConfiguration(
                corpus_directory=command.corpus_directory,
                model_identifier=command.model_identifier,
                source_commit=command.source_commit,
            )
        )
        output_path = command.output_directory / f"{command.run_id}.json"
        write_manifest(manifest, output_path)
    except ModelPolicyError as error:
        _write_model_policy_error(error)
        return 2
    except CliUsageError as error:
        _write_error("usage", str(error))
        return 2
    except DuplicateSampleIdError as error:
        _write_error("duplicate_sample_id", str(error))
        return 2

    _ = sys.stdout.write(f"{output_path}\n")
    return 0


def _run_features(arguments: tuple[str, ...]) -> int:
    """Generate a deterministic JSONL feature artifact from eligible EML records."""
    try:
        command = _parse_manifest_command(arguments)
        ensure_model_allowed(command.model_identifier)
        manifest = build_manifest(
            ManifestConfiguration(
                corpus_directory=command.corpus_directory,
                model_identifier=command.model_identifier,
                source_commit=command.source_commit,
            )
        )
        output_path = command.output_directory / f"{command.run_id}.jsonl"
        write_features(
            extract_feature_records(command.corpus_directory, manifest), output_path
        )
    except ModelPolicyError as error:
        _write_model_policy_error(error)
        return 2
    except CliUsageError as error:
        _write_error("usage", str(error))
        return 2
    except DuplicateSampleIdError as error:
        _write_error("duplicate_sample_id", str(error))
        return 2

    _ = sys.stdout.write(f"{output_path}\n")
    return 0


def _parse_command(arguments: tuple[str, ...]) -> ManifestCommand:
    if not arguments:
        raise CliUsageError(detail="Expected the 'manifest' command.")

    match arguments[0]:
        case "manifest":
            return _parse_manifest_command(arguments[1:])
        case command:
            raise CliUsageError(detail=f"Unsupported command: {command!r}.")


def _parse_manifest_command(arguments: tuple[str, ...]) -> ManifestCommand:
    if len(arguments) % 2 != 0:
        raise CliUsageError(detail="Manifest options require a value.")

    options = dict(zip(arguments[::2], arguments[1::2], strict=True))
    option_names = tuple(options)
    if len(options) != len(arguments) // 2:
        raise CliUsageError(detail="Manifest options must not be repeated.")
    if not all(option in MANIFEST_OPTIONS for option in option_names):
        raise CliUsageError(detail="Manifest options include an unsupported name.")
    if "--corpus" not in options or "--run-id" not in options:
        raise CliUsageError(detail="Manifest requires --corpus and --run-id.")

    run_id = options["--run-id"]
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise CliUsageError(
            detail="Run ID must contain only letters, digits, '_' or '-'."
        )

    return ManifestCommand(
        corpus_directory=Path(options["--corpus"]),
        output_directory=Path(options.get("--output-dir", DEFAULT_OUTPUT_DIRECTORY)),
        run_id=run_id,
        model_identifier=options.get("--model", DEFAULT_MODEL_ID),
        source_commit=options.get("--source-commit", DEFAULT_SOURCE_COMMIT),
    )


def _write_error(error_name: str, detail: str) -> None:
    payload = ErrorJson(error=error_name, detail=detail)
    _ = sys.stderr.write(json.dumps(payload, sort_keys=True) + "\n")


def _write_model_policy_error(error: ModelPolicyError) -> None:
    payload = ModelPolicyErrorJson(
        error="model_policy", model_identifier=error.model_id
    )
    _ = sys.stderr.write(json.dumps(payload, sort_keys=True) + "\n")
