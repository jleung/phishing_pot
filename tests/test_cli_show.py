import json
from pathlib import Path
from typing import cast

import pytest

from phishing_contract.cli import run

FIXTURES = Path(__file__).parent / "fixtures"
FEATURE_CORPUS = FIXTURES / "features"


def test_show_prints_raw_headers_and_sanitized_features(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # When: a reviewer asks for one sample from the fixture corpus.
    exit_code = run(
        (
            "show",
            "--corpus",
            str(FEATURE_CORPUS),
            "--sample",
            "1",
        )
    )

    # Then: the raw header block prints verbatim, followed by safe features.
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "# sample-1" in captured.out
    assert "From:" in captured.out
    feature_line = captured.out.splitlines()[-1]
    payload = cast("dict[str, object]", json.loads(feature_line))
    assert payload["sample_id"] == 1
    assert "body_evidence" in payload


def test_show_missing_sample_reports_not_found(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # When: the requested sample does not exist in the corpus.
    exit_code = run(
        (
            "show",
            "--corpus",
            str(FEATURE_CORPUS),
            "--sample",
            "9999",
        )
    )

    # Then: a machine-readable not-found error is reported.
    captured = capsys.readouterr()
    assert exit_code == 2
    payload = cast(
        "dict[str, object]", json.loads(captured.err.strip().splitlines()[0])
    )
    assert payload["error"] == "not_found"


def test_show_rejects_non_numeric_sample(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # When: the sample argument is not an integer.
    exit_code = run(
        (
            "show",
            "--corpus",
            str(FEATURE_CORPUS),
            "--sample",
            "abc",
        )
    )

    # Then: a usage error is reported.
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "usage" in captured.err
