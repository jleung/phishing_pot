from pathlib import Path

import pytest

from phishing_contract.cli import run

FIXTURES = Path(__file__).parent / "fixtures" / "corpus-contract"


def test_manifest_cli_writes_stable_json_artifact(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given: a contract fixture corpus and an explicit deterministic run ID.
    output_directory = tmp_path / "artifacts" / "manifests"

    # When: the manifest CLI is invoked with an approved model route.
    exit_code = run(
        (
            "manifest",
            "--corpus",
            str(FIXTURES / "valid"),
            "--output-dir",
            str(output_directory),
            "--run-id",
            "fixture-run",
            "--source-commit",
            "test-commit",
        )
    )

    # Then: it writes a stable metadata-only manifest and reports its path.
    captured = capsys.readouterr()
    artifact = output_directory / "fixture-run.json"
    artifact_text = artifact.read_text(encoding="utf-8")
    assert exit_code == 0
    assert str(artifact) in captured.out
    assert '"eligible_record_count": 3' in artifact_text
    assert '"model_identifier": "openai/gpt-5.6-terra"' in artifact_text
    assert "excluded fixture bytes" not in artifact_text


def test_manifest_cli_rejects_non_gpt_route_before_discovery(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: a model outside the required route and a nonexistent corpus path.
    # When: the manifest CLI validates the requested model route.
    exit_code = run(
        (
            "manifest",
            "--corpus",
            "does-not-exist",
            "--run-id",
            "blocked-run",
            "--model",
            "other/model",
        )
    )

    # Then: policy rejection is explicit and occurs before corpus access.
    captured = capsys.readouterr()
    assert exit_code == 2
    assert (
        captured.err == '{"error": "model_policy", "model_identifier": "other/model"}\n'
    )
