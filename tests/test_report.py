import pytest

from phishing_contract.classify import Decision
from phishing_contract.registry import Category, CategoryRegistry, Rule
from phishing_contract.report import (
    AcceptanceError,
    check_acceptance,
    diff_decisions,
    serialize_diff,
    summarize_decisions,
)


def _decision(sample_id: int, decision: str) -> Decision:
    return Decision(
        sample_id=sample_id,
        relative_path=f"sample-{sample_id}.eml",
        decision=decision,
        action=None,
        matched_rules=(),
        rejected_candidates=(),
        fallback_reason=None,
        registry_sha256="registry-digest",
        source_sha256=f"digest-{sample_id}",
    )


def test_diff_reports_moves_additions_and_removals() -> None:
    # Given: two runs where one email reclassified, one new, one missing.
    before = [
        _decision(1, "login-lure"),
        _decision(2, "brand-generic"),
        _decision(3, "unmatched"),
        _decision(4, "brand-generic"),
    ]
    after = [
        _decision(1, "login-lure"),
        _decision(2, "login-lure"),
        _decision(3, "unmatched"),
        _decision(5, "brand-generic"),
    ]

    # When: the two decision runs are diffed.
    diff = diff_decisions(before, after)

    # Then: stable, moved, added, and removed samples are all accounted for.
    assert diff.stable_count == 2
    assert len(diff.moves) == 1
    move = diff.moves[0]
    assert move.from_decision == "brand-generic"
    assert move.to_decision == "login-lure"
    assert move.count == 1
    assert move.sample_ids == (2,)
    assert diff.added_sample_ids == (5,)
    assert diff.removed_sample_ids == (4,)


def test_diff_of_identical_runs_is_empty() -> None:
    # Given: two byte-identical decision runs.
    before = [_decision(1, "login-lure"), _decision(2, "unmatched")]
    after = [_decision(1, "login-lure"), _decision(2, "unmatched")]

    # When: the runs are diffed.
    diff = diff_decisions(before, after)

    # Then: nothing moved, was added, or was removed.
    assert diff.stable_count == 2
    assert diff.moves == ()
    assert diff.added_sample_ids == ()
    assert diff.removed_sample_ids == ()


def test_serialize_diff_is_stable_canonical_json() -> None:
    # Given: a diff with a move.
    before = [_decision(1, "brand-generic")]
    after = [_decision(1, "login-lure")]
    diff = diff_decisions(before, after)

    # When: the diff is serialized twice.
    first = serialize_diff(diff)
    second = serialize_diff(diff)

    # Then: serialization is deterministic canonical JSON.
    assert first == second
    assert first.startswith("{")
    assert first.endswith("\n")


def test_summary_counts_every_bucket_sorted() -> None:
    # Given: decisions spread across several buckets.
    decisions = (
        _decision(1, "unmatched"),
        _decision(2, "login-lure"),
        _decision(3, "unmatched"),
        _decision(4, "needs_review"),
        _decision(5, "login-lure"),
    )

    # When: the decisions are summarized.
    summary = summarize_decisions(decisions)

    # Then: totals and per-bucket counts are reported deterministically.
    assert summary.total == 5
    assert summary.counts == (
        ("login-lure", 2),
        ("needs_review", 1),
        ("unmatched", 2),
    )


def test_acceptance_passes_when_samples_match_their_category() -> None:
    # Given: a category claiming sample 1, and sample 1 decided accordingly.
    category = Category(
        id="login-lure",
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
        acceptance=(1,),
    )
    registry = CategoryRegistry(
        schema_version=1, categories=(category,), source_sha256="digest"
    )
    decisions = [_decision(1, "login-lure"), _decision(2, "unmatched")]

    # When: acceptance is checked against the decisions.
    # Then: no error is raised.
    assert check_acceptance(registry, decisions) is None


def test_acceptance_fails_when_sample_lands_elsewhere() -> None:
    # Given: a category claiming sample 1, but sample 1 is unmatched.
    category = Category(
        id="login-lure",
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
        acceptance=(1,),
    )
    registry = CategoryRegistry(
        schema_version=1, categories=(category,), source_sha256="digest"
    )
    decisions = [_decision(1, "unmatched")]

    # When: acceptance is checked.
    # Then: the failure names the category, sample, and actual decision.
    with pytest.raises(
        AcceptanceError, match=r"login-lure.*1.*unmatched"
    ) as exc_info:
        check_acceptance(registry, decisions)
    assert exc_info.value.category == "login-lure"
    assert exc_info.value.sample_id == 1
    assert exc_info.value.actual == "unmatched"


def test_acceptance_fails_when_sample_is_absent_from_decisions() -> None:
    # Given: a category claiming sample 9, absent from the decisions.
    category = Category(
        id="login-lure",
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
        acceptance=(9,),
    )
    registry = CategoryRegistry(
        schema_version=1, categories=(category,), source_sha256="digest"
    )

    # When: acceptance is checked against a run missing that sample.
    # Then: the absence is reported explicitly.
    with pytest.raises(AcceptanceError, match=r"login-lure.*9"):
        check_acceptance(registry, [])
