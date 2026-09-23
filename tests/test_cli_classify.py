import json
from pathlib import Path
from typing import cast

import pytest

from phishing_contract.classify import Decision, load_decisions, serialize_decision
from phishing_contract.cli import run

FIXTURES = Path(__file__).parent / "fixtures"
FEATURE_CORPUS = FIXTURES / "features"
REGISTRY = FIXTURES / "categories" / "valid.toml"
BAD_ACCEPTANCE_REGISTRY = FIXTURES / "categories" / "bad-acceptance.toml"


def _run(tmp_path: Path, *arguments: str) -> int:
    return run(
        (
            *arguments,
            "--corpus",
            str(FEATURE_CORPUS),
            "--output-dir",
            str(tmp_path / "artifacts"),
        )
    )


def test_classify_cli_writes_decisions_and_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given: the fixture corpus and the fixture registry.
    exit_code = _run(
        tmp_path, "classify", "--registry", str(REGISTRY), "--run-id", "t1"
    )

    # Then: it succeeds, reports the artifact path, and audits every sample.
    captured = capsys.readouterr()
    artifact = tmp_path / "artifacts" / "t1.decisions.jsonl"
    assert exit_code == 0
    assert str(artifact) in captured.out
    lines = artifact.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    decisions = [json.loads(line) for line in lines]
    assert decisions[0]["decision"] == "login-update-lure"
    assert decisions[1]["decision"] == "pdf-delivery"
    assert decisions[2]["decision"] == "unmatched"
    assert decisions[3]["decision"] == "unmatched"
    assert decisions[0]["registry_sha256"] == decisions[1]["registry_sha256"]

    summary_path = tmp_path / "artifacts" / "t1.summary.json"
    summary: dict[str, object] = cast(
        "dict[str, object]", json.loads(summary_path.read_text(encoding="utf-8"))
    )
    assert summary["total"] == 4
    counts = cast("dict[str, int]", summary["counts"])
    assert counts["login-update-lure"] == 1
    assert counts["pdf-delivery"] == 1
    assert counts["unmatched"] == 2


def test_classify_cli_rejects_acceptance_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given: a registry whose acceptance sample lands in a different bucket.
    exit_code = _run(
        tmp_path,
        "classify",
        "--registry",
        str(BAD_ACCEPTANCE_REGISTRY),
        "--run-id",
        "t2",
    )

    # Then: the failure is reported explicitly with a distinct exit code.
    captured = capsys.readouterr()
    assert exit_code == 3
    payload = cast(
        "dict[str, object]", json.loads(captured.err.strip().splitlines()[0])
    )
    assert payload["error"] == "acceptance_failure"


def test_classify_cli_reports_missing_registry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given: a registry path that does not exist.
    exit_code = _run(
        tmp_path,
        "classify",
        "--registry",
        str(FIXTURES / "categories" / "absent.toml"),
        "--run-id",
        "t3",
    )

    # Then: the CLI reports a registry error with exit code 2.
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err.startswith('{"detail"')
    assert "not found" in captured.err


def test_discover_cli_writes_dossiers_for_unmatched(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given: a corpus where two samples are unmatched.
    exit_code = _run(
        tmp_path,
        "discover",
        "--registry",
        str(REGISTRY),
        "--run-id",
        "t4",
        "--threshold",
        "0.1",
        "--min-size",
        "1",
    )

    # Then: the dossier artifact reports the unmatched population.
    captured = capsys.readouterr()
    artifact = tmp_path / "artifacts" / "t4.dossiers.json"
    assert exit_code == 0
    assert str(artifact) in captured.out
    payload = cast(
        "dict[str, object]", json.loads(artifact.read_text(encoding="utf-8"))
    )
    assert payload["total_unmatched"] == 2
    assert payload["threshold"] == 0.1
    assert payload["min_cluster_size"] == 1


def test_diff_cli_reports_reflow_between_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given: two decision runs where one sample reclassified.
    before = Decision(
        sample_id=1,
        relative_path="sample-1.eml",
        decision="brand-generic",
        action=None,
        matched_rules=(),
        rejected_candidates=(),
        fallback_reason=None,
        registry_sha256="a",
        source_sha256="s1",
    )
    after = Decision(
        sample_id=1,
        relative_path="sample-1.eml",
        decision="login-lure",
        action="quarantine",
        matched_rules=(),
        rejected_candidates=(),
        fallback_reason=None,
        registry_sha256="b",
        source_sha256="s1",
    )
    before_path = tmp_path / "before.jsonl"
    after_path = tmp_path / "after.jsonl"
    _ = before_path.write_text(serialize_decision(before), encoding="utf-8")
    _ = after_path.write_text(serialize_decision(after), encoding="utf-8")

    # When: the diff CLI compares the two runs.
    exit_code = run(
        (
            "diff",
            "--before",
            str(before_path),
            "--after",
            str(after_path),
        )
    )

    # Then: the reflow is reported as canonical JSON on stdout.
    captured = capsys.readouterr()
    assert exit_code == 0
    payload = cast(
        "dict[str, object]", json.loads(captured.out.strip().splitlines()[0])
    )
    assert payload["stable_count"] == 0
    moves = cast("list[dict[str, object]]", payload["moves"])
    assert moves[0]["from_decision"] == "brand-generic"
    assert moves[0]["to_decision"] == "login-lure"
    assert moves[0]["count"] == 1


def test_load_decisions_round_trips(tmp_path: Path) -> None:
    # Given: serialized decisions written to disk.
    decision = Decision(
        sample_id=7,
        relative_path="sample-7.eml",
        decision="unmatched",
        action=None,
        matched_rules=(),
        rejected_candidates=(),
        fallback_reason="no_rules_matched",
        registry_sha256="a",
        source_sha256="s7",
    )
    path = tmp_path / "run.jsonl"
    _ = path.write_text(serialize_decision(decision), encoding="utf-8")

    # When: the decisions are loaded back.
    loaded = load_decisions(path)

    # Then: they round-trip to the same typed records.
    assert loaded == (decision,)
