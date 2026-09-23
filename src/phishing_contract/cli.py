"""Command-line interface for deterministic offline corpus manifests."""

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypedDict, override

from phishing_contract.classify import (
    classify_record,
    load_decisions,
    write_decisions,
)
from phishing_contract.discover import discover_clusters, write_dossiers
from phishing_contract.features import (
    extract_feature_record,
    extract_feature_records,
    serialize_feature,
    write_features,
)
from phishing_contract.manifest import (
    DuplicateSampleIdError,
    build_manifest,
    write_manifest,
)
from phishing_contract.models import ManifestConfiguration, SampleId, SourceRecord
from phishing_contract.policy import (
    DEFAULT_MODEL_ID,
    ModelPolicyError,
    ensure_model_allowed,
)
from phishing_contract.registry import RegistryError, load_registry
from phishing_contract.report import (
    AcceptanceError,
    check_acceptance,
    diff_decisions,
    serialize_diff,
    serialize_summary,
    summarize_decisions,
)

RUN_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")
DEFAULT_OUTPUT_DIRECTORY: Final = "artifacts/manifests"
DEFAULT_SOURCE_COMMIT: Final = "unavailable"
MANIFEST_OPTIONS: Final = frozenset(
    {"--corpus", "--model", "--output-dir", "--run-id", "--source-commit"}
)
CLASSIFY_OPTIONS: Final = frozenset(
    {"--corpus", "--registry", "--run-id", "--output-dir", "--source-commit"}
)
DISCOVER_OPTIONS: Final = frozenset(
    {
        "--corpus",
        "--registry",
        "--run-id",
        "--output-dir",
        "--source-commit",
        "--threshold",
        "--min-size",
    }
)
DIFF_OPTIONS: Final = frozenset({"--before", "--after"})
SHOW_OPTIONS: Final = frozenset({"--corpus", "--sample"})
DEFAULT_DISCOVERY_THRESHOLD: Final = 0.35
DEFAULT_MIN_CLUSTER_SIZE: Final = 3


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


@dataclass(frozen=True, slots=True)
class ClassifyCommand:
    """Parsed options shared by the classify and discover commands."""

    corpus_directory: Path
    registry_path: Path
    output_directory: Path
    run_id: str
    source_commit: str


@dataclass(frozen=True, slots=True)
class DiscoverCommand:
    """Parsed options for the discover command."""

    corpus_directory: Path
    registry_path: Path
    output_directory: Path
    run_id: str
    source_commit: str
    threshold: float
    min_cluster_size: int


def main() -> int:
    """Run the CLI from process arguments and return its exit code."""
    return run(tuple(sys.argv[1:]))


def run(arguments: tuple[str, ...]) -> int:
    """Run a CLI request while converting expected contract failures to JSON."""
    if arguments:
        handler = COMMAND_HANDLERS.get(arguments[0])
        if handler is not None:
            return handler(arguments[1:])
    return _run_manifest(arguments)


def _run_manifest(arguments: tuple[str, ...]) -> int:
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


def _run_classify(arguments: tuple[str, ...]) -> int:
    """Classify a corpus with a category registry and audit every decision."""
    command, usage_error = _parse_classify_command(arguments)
    if command is None:
        _write_error("usage", usage_error or "Usage error.")
        return 2
    try:
        registry = load_registry(command.registry_path)
    except RegistryError as error:
        _write_error("registry", str(error))
        return 2

    try:
        ensure_model_allowed(DEFAULT_MODEL_ID)
        manifest = build_manifest(
            ManifestConfiguration(
                corpus_directory=command.corpus_directory,
                model_identifier=DEFAULT_MODEL_ID,
                source_commit=command.source_commit,
            )
        )
        features = extract_feature_records(command.corpus_directory, manifest)
    except ModelPolicyError as error:
        _write_model_policy_error(error)
        return 2
    except DuplicateSampleIdError as error:
        _write_error("duplicate_sample_id", str(error))
        return 2

    decisions = tuple(classify_record(record, registry) for record in features)
    decisions_path = command.output_directory / f"{command.run_id}.decisions.jsonl"
    summary_path = command.output_directory / f"{command.run_id}.summary.json"
    write_decisions(decisions, decisions_path)
    summary = serialize_summary(summarize_decisions(decisions))
    _ = summary_path.write_text(summary + "\n", encoding="utf-8")
    try:
        check_acceptance(registry, decisions)
    except AcceptanceError as error:
        payload = {
            "error": "acceptance_failure",
            "category": error.category,
            "sample_id": error.sample_id,
            "actual": error.actual,
        }
        _ = sys.stderr.write(json.dumps(payload, sort_keys=True) + "\n")
        return 3

    _ = sys.stdout.write(f"{decisions_path}\n")
    return 0


def _run_discover(arguments: tuple[str, ...]) -> int:
    """Cluster the unmatched samples and write a reviewable dossier."""
    command, usage_error = _parse_discover_command(arguments)
    if command is None:
        _write_error("usage", usage_error or "Usage error.")
        return 2
    try:
        registry = load_registry(command.registry_path)
    except RegistryError as error:
        _write_error("registry", str(error))
        return 2

    try:
        ensure_model_allowed(DEFAULT_MODEL_ID)
        manifest = build_manifest(
            ManifestConfiguration(
                corpus_directory=command.corpus_directory,
                model_identifier=DEFAULT_MODEL_ID,
                source_commit=command.source_commit,
            )
        )
        features = extract_feature_records(command.corpus_directory, manifest)
    except ModelPolicyError as error:
        _write_model_policy_error(error)
        return 2
    except DuplicateSampleIdError as error:
        _write_error("duplicate_sample_id", str(error))
        return 2

    classified = tuple(
        (record, classify_record(record, registry)) for record in features
    )
    unmatched = tuple(
        record for record, decision in classified if decision.decision == "unmatched"
    )
    dossiers = discover_clusters(
        unmatched,
        threshold=command.threshold,
        min_cluster_size=command.min_cluster_size,
    )
    output_path = command.output_directory / f"{command.run_id}.dossiers.json"
    write_dossiers(
        dossiers,
        total_unmatched=len(unmatched),
        output_path=output_path,
        threshold=command.threshold,
        min_cluster_size=command.min_cluster_size,
    )
    _ = sys.stdout.write(f"{output_path}\n")
    return 0


def _run_show(arguments: tuple[str, ...]) -> int:
    """Print one sample's raw headers alongside its sanitized features."""
    try:
        options = _parse_options(arguments, SHOW_OPTIONS, ("--corpus", "--sample"))
    except CliUsageError as error:
        _write_error("usage", str(error))
        return 2

    try:
        sample_id = int(options["--sample"])
    except ValueError:
        _write_error("usage", "Sample must be a non-negative integer.")
        return 2
    if sample_id < 0:
        _write_error("usage", "Sample must be a non-negative integer.")
        return 2

    corpus_directory = Path(options["--corpus"])
    relative_path = f"sample-{sample_id}.eml"
    source_path = corpus_directory / relative_path
    if not source_path.is_file():
        payload = {"error": "not_found", "sample": sample_id}
        _ = sys.stderr.write(json.dumps(payload, sort_keys=True) + "\n")
        return 2

    raw_bytes = source_path.read_bytes()
    source = SourceRecord(
        sample_id=SampleId(sample_id),
        relative_path=relative_path,
        byte_size=len(raw_bytes),
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )
    record = extract_feature_record(corpus_directory, source)

    _ = sys.stdout.write(f"# sample-{sample_id}\n")
    _ = sys.stdout.write(_raw_header_block(raw_bytes) + "\n")
    _ = sys.stdout.write("\n")
    _ = sys.stdout.write(serialize_feature(record))
    return 0


def _raw_header_block(raw_bytes: bytes) -> str:
    """Return the header section of a message, up to the first blank line."""
    for separator in (b"\r\n\r\n", b"\n\n"):
        index = raw_bytes.find(separator)
        if index != -1:
            return raw_bytes[:index].decode("utf-8", errors="replace")
    return raw_bytes.decode("utf-8", errors="replace")


def _run_diff(arguments: tuple[str, ...]) -> int:
    """Compare two decision runs and report the reflow between them."""
    try:
        options = _parse_options(arguments, DIFF_OPTIONS, ("--before", "--after"))
    except CliUsageError as error:
        _write_error("usage", str(error))
        return 2
    try:
        before = load_decisions(Path(options["--before"]))
        after = load_decisions(Path(options["--after"]))
    except OSError as error:
        _write_error("not_found", str(error))
        return 2
    except json.JSONDecodeError as error:
        _write_error("malformed_decisions", str(error))
        return 2
    except ValueError as error:
        _write_error("malformed_decisions", str(error))
        return 2

    payload = serialize_diff(diff_decisions(before, after))
    _ = sys.stdout.write(payload + "\n")
    return 0


def _parse_options(
    arguments: tuple[str, ...],
    allowed: frozenset[str],
    required: tuple[str, ...],
) -> dict[str, str]:
    if len(arguments) % 2 != 0:
        raise CliUsageError(detail="Options require a value.")
    options = dict(zip(arguments[::2], arguments[1::2], strict=True))
    if len(options) != len(arguments) // 2:
        raise CliUsageError(detail="Options must not be repeated.")
    if not all(option in allowed for option in options):
        raise CliUsageError(detail="Options include an unsupported name.")
    if any(option not in options for option in required):
        missing = ", ".join(option for option in required if option not in options)
        raise CliUsageError(detail=f"Missing required options: {missing}.")
    return options


def _parse_classify_command(
    arguments: tuple[str, ...],
) -> tuple[ClassifyCommand | None, str | None]:
    try:
        options = _parse_options(
            arguments, CLASSIFY_OPTIONS, ("--corpus", "--registry", "--run-id")
        )
    except CliUsageError as error:
        return None, str(error.detail)
    run_id = options["--run-id"]
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        return None, "Run ID must contain only letters, digits, '_' or '-'"
    return (
        ClassifyCommand(
            corpus_directory=Path(options["--corpus"]),
            registry_path=Path(options["--registry"]),
            output_directory=Path(
                options.get("--output-dir", DEFAULT_OUTPUT_DIRECTORY)
            ),
            run_id=run_id,
            source_commit=options.get("--source-commit", DEFAULT_SOURCE_COMMIT),
        ),
        None,
    )


def _parse_discover_command(
    arguments: tuple[str, ...],
) -> tuple[DiscoverCommand | None, str | None]:
    try:
        options = _parse_options(
            arguments, DISCOVER_OPTIONS, ("--corpus", "--registry", "--run-id")
        )
    except CliUsageError as error:
        return None, str(error.detail)
    run_id = options["--run-id"]
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        return None, "Run ID must contain only letters, digits, '_' or '-'"
    threshold_raw = options.get("--threshold", str(DEFAULT_DISCOVERY_THRESHOLD))
    min_size_raw = options.get("--min-size", str(DEFAULT_MIN_CLUSTER_SIZE))
    try:
        threshold = float(threshold_raw)
        min_cluster_size = int(min_size_raw)
    except ValueError:
        return None, "Discovery options must be numbers."
    if threshold <= 0.0:
        return None, "Discovery threshold must be positive."
    if min_cluster_size < 1:
        return None, "Minimum cluster size must be at least 1."
    return (
        DiscoverCommand(
            corpus_directory=Path(options["--corpus"]),
            registry_path=Path(options["--registry"]),
            output_directory=Path(
                options.get("--output-dir", DEFAULT_OUTPUT_DIRECTORY)
            ),
            run_id=run_id,
            source_commit=options.get("--source-commit", DEFAULT_SOURCE_COMMIT),
            threshold=threshold,
            min_cluster_size=min_cluster_size,
        ),
        None,
    )


def _write_model_policy_error(error: ModelPolicyError) -> None:
    payload = ModelPolicyErrorJson(
        error="model_policy", model_identifier=error.model_id
    )
    _ = sys.stderr.write(json.dumps(payload, sort_keys=True) + "\n")


COMMAND_HANDLERS: Final = {
    "classify": _run_classify,
    "discover": _run_discover,
    "diff": _run_diff,
    "features": _run_features,
    "show": _run_show,
}
