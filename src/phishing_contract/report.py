"""Deterministic summaries and version-to-version diffs of decision runs."""

import json
from dataclasses import dataclass
from typing import override

from phishing_contract.classify import Decision
from phishing_contract.registry import CategoryRegistry


@dataclass(frozen=True, slots=True)
class AcceptanceError(Exception):
    """Raised when a category's acceptance sample did not classify as claimed."""

    category: str
    sample_id: int
    actual: str | None

    @override
    def __str__(self) -> str:
        """Name the category, sample, and the decision it actually received."""
        return (
            f"Acceptance failure: category {self.category} expected sample "
            f"{self.sample_id} to be decided {self.category!r}, "
            f"got {self.actual!r}"
        )


@dataclass(frozen=True, slots=True)
class MoveCount:
    """Emails that moved between two decision buckets across two runs."""

    from_decision: str
    to_decision: str
    count: int
    sample_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DiffReport:
    """The stable set of changes between two decision audit trails."""

    stable_count: int
    moves: tuple[MoveCount, ...]
    added_sample_ids: tuple[int, ...]
    removed_sample_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Summary:
    """Per-category and per-bucket decision counts for one run."""

    total: int
    counts: tuple[tuple[str, int], ...]
    bucket_counts: tuple[tuple[str, int], ...]


def summarize_decisions(decisions: tuple[Decision, ...]) -> Summary:
    """Count categories and buckets in deterministic sorted order."""
    tally: dict[str, int] = {}
    bucket_tally: dict[str, int] = {}
    for decision in decisions:
        tally[decision.decision] = tally.get(decision.decision, 0) + 1
        bucket_tally[decision.bucket] = bucket_tally.get(decision.bucket, 0) + 1
    counts = tuple(sorted(tally.items()))
    bucket_counts = tuple(sorted(bucket_tally.items()))
    return Summary(total=len(decisions), counts=counts, bucket_counts=bucket_counts)


def diff_decisions(
    before: list[Decision] | tuple[Decision, ...],
    after: list[Decision] | tuple[Decision, ...],
) -> DiffReport:
    """Compare two decision runs and report every reflow by sample ID."""
    before_by_id = {decision.sample_id: decision.decision for decision in before}
    after_by_id = {decision.sample_id: decision.decision for decision in after}

    stable_count = 0
    grouped_moves: dict[tuple[str, str], list[int]] = {}
    for sample_id in sorted(set(before_by_id) & set(after_by_id)):
        previous = before_by_id[sample_id]
        current = after_by_id[sample_id]
        if previous == current:
            stable_count += 1
            continue
        move_key = (previous, current)
        grouped_moves.setdefault(move_key, []).append(sample_id)

    moves = tuple(
        MoveCount(
            from_decision=from_decision,
            to_decision=to_decision,
            count=len(sample_ids),
            sample_ids=tuple(sorted(sample_ids)),
        )
        for (from_decision, to_decision), sample_ids in sorted(grouped_moves.items())
    )
    return DiffReport(
        stable_count=stable_count,
        moves=moves,
        added_sample_ids=tuple(sorted(set(after_by_id) - set(before_by_id))),
        removed_sample_ids=tuple(sorted(set(before_by_id) - set(after_by_id))),
    )


def serialize_diff(diff: DiffReport) -> str:
    """Serialize a diff as canonical, newline-terminated JSON."""
    payload = {
        "stable_count": diff.stable_count,
        "moves": [
            {
                "from_decision": move.from_decision,
                "to_decision": move.to_decision,
                "count": move.count,
                "sample_ids": list(move.sample_ids),
            }
            for move in diff.moves
        ],
        "added_sample_ids": list(diff.added_sample_ids),
        "removed_sample_ids": list(diff.removed_sample_ids),
    }
    return json.dumps(payload, sort_keys=True) + "\n"


def serialize_summary(summary: Summary) -> str:
    """Serialize a summary as canonical, newline-terminated JSON."""
    payload = {
        "total": summary.total,
        "counts": dict(summary.counts),
        "bucket_counts": dict(summary.bucket_counts),
    }
    return json.dumps(payload, sort_keys=True) + "\n"


def check_acceptance(
    registry: CategoryRegistry, decisions: list[Decision] | tuple[Decision, ...]
) -> None:
    """Verify every acceptance sample landed in the category that claims it."""
    decided: dict[int, str] = {
        decision.sample_id: decision.decision for decision in decisions
    }
    for category in registry.categories:
        for sample_id in category.acceptance:
            actual = decided.get(sample_id)
            if actual != category.id:
                raise AcceptanceError(
                    category=category.id,
                    sample_id=sample_id,
                    actual=actual,
                )
