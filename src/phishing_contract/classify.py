"""Deterministic rule classification with an auditable decision trail."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast, override

from phishing_contract.models import FeatureRecord
from phishing_contract.registry import Category, CategoryRegistry, Rule

UNMATCHED: Final = "unmatched"
NEEDS_REVIEW: Final = "needs_review"
EVIDENCE_EXCERPT_LIMIT: Final = 80


@dataclass(frozen=True, slots=True)
class MatchedRule:
    """One rule that matched, with the evidence that satisfied it."""

    field: str
    op: str
    matched_evidence: str


@dataclass(frozen=True, slots=True)
class RejectedCandidate:
    """A category that matched but did not win, and why it lost."""

    category: str
    bucket: str
    priority: int
    matched_rules: tuple[MatchedRule, ...]
    matched_signals: tuple[MatchedRule, ...]
    signal_score: int
    lost_to: str


@dataclass(frozen=True, slots=True)
class Decision:
    """The complete, explainable resolution of one email to one bucket."""

    sample_id: int
    relative_path: str
    decision: str
    bucket: str
    action: str | None
    matched_rules: tuple[MatchedRule, ...]
    matched_signals: tuple[MatchedRule, ...]
    signal_score: int
    rejected_candidates: tuple[RejectedCandidate, ...]
    fallback_reason: str | None
    registry_sha256: str
    source_sha256: str


@dataclass(frozen=True, slots=True)
class _CandidateMatch:
    """A registry category that passed its hard rules and signal threshold."""

    category: Category
    matched_rules: tuple[MatchedRule, ...]
    matched_signals: tuple[MatchedRule, ...]
    signal_score: int


@dataclass(frozen=True, slots=True)
class ClassificationError(Exception):
    """Raised when a rule cannot be evaluated against a feature record."""

    message: str

    @override
    def __str__(self) -> str:
        """Report the invalid rule/field pair without email content."""
        return self.message


def classify_record(record: FeatureRecord, registry: CategoryRegistry) -> Decision:
    """Resolve one feature record to exactly one decision bucket."""
    matches: list[_CandidateMatch] = []
    for category in registry.categories:
        matched_rules = tuple(
            rule_match
            for rule_match in (
                _evaluate_rule(rule, record) for rule in category.rules
            )
            if rule_match is not None
        )
        if len(matched_rules) != len(category.rules):
            continue

        matched_signals = tuple(
            signal_match
            for signal_match in (
                _evaluate_rule(signal, record) for signal in category.signals
            )
            if signal_match is not None
        )
        if len(matched_signals) < category.min_signals:
            continue

        matches.append(
            _CandidateMatch(
                category=category,
                matched_rules=matched_rules,
                matched_signals=matched_signals,
                signal_score=len(matched_signals),
            )
        )

    if not matches:
        return Decision(
            sample_id=int(record.source.sample_id),
            relative_path=record.source.relative_path,
            decision=UNMATCHED,
            bucket=UNMATCHED,
            action=None,
            matched_rules=(),
            matched_signals=(),
            signal_score=0,
            rejected_candidates=(),
            fallback_reason="no_rules_matched",
            registry_sha256=registry.source_sha256,
            source_sha256=record.source.sha256,
        )

    ranked = sorted(
        matches, key=lambda match: (-match.category.priority, match.category.id)
    )
    top_priority = ranked[0].category.priority
    tied = [match for match in ranked if match.category.priority == top_priority]

    if len(tied) > 1:
        tie_ids = "|".join(match.category.id for match in tied)
        return Decision(
            sample_id=int(record.source.sample_id),
            relative_path=record.source.relative_path,
            decision=NEEDS_REVIEW,
            bucket=NEEDS_REVIEW,
            action=None,
            matched_rules=(),
            matched_signals=(),
            signal_score=0,
            rejected_candidates=tuple(
                _rejected_candidate(match, NEEDS_REVIEW) for match in tied
            ),
            fallback_reason=f"priority_tie:{tie_ids}",
            registry_sha256=registry.source_sha256,
            source_sha256=record.source.sha256,
        )

    winner = ranked[0]
    rejected = tuple(
        _rejected_candidate(match, winner.category.id) for match in ranked[1:]
    )
    return Decision(
        sample_id=int(record.source.sample_id),
        relative_path=record.source.relative_path,
        decision=winner.category.id,
        bucket=winner.category.bucket,
        action=winner.category.action,
        matched_rules=winner.matched_rules,
        matched_signals=winner.matched_signals,
        signal_score=winner.signal_score,
        rejected_candidates=rejected,
        fallback_reason=None,
        registry_sha256=registry.source_sha256,
        source_sha256=record.source.sha256,
    )


def _rejected_candidate(match: _CandidateMatch, lost_to: str) -> RejectedCandidate:
    return RejectedCandidate(
        category=match.category.id,
        bucket=match.category.bucket,
        priority=match.category.priority,
        matched_rules=match.matched_rules,
        matched_signals=match.matched_signals,
        signal_score=match.signal_score,
        lost_to=lost_to,
    )


def serialize_decision(decision: Decision) -> str:
    """Serialize one decision as canonical newline-terminated JSONL."""
    payload = {
        "sample_id": decision.sample_id,
        "relative_path": decision.relative_path,
        "decision": decision.decision,
        "bucket": decision.bucket,
        "action": decision.action,
        "matched_rules": [_matched_rule_json(rule) for rule in decision.matched_rules],
        "matched_signals": [
            _matched_rule_json(signal) for signal in decision.matched_signals
        ],
        "signal_score": decision.signal_score,
        "rejected_candidates": [
            {
                "category": candidate.category,
                "bucket": candidate.bucket,
                "priority": candidate.priority,
                "matched_rules": [
                    _matched_rule_json(rule) for rule in candidate.matched_rules
                ],
                "matched_signals": [
                    _matched_rule_json(signal)
                    for signal in candidate.matched_signals
                ],
                "signal_score": candidate.signal_score,
                "lost_to": candidate.lost_to,
            }
            for candidate in decision.rejected_candidates
        ],
        "fallback_reason": decision.fallback_reason,
        "registry_sha256": decision.registry_sha256,
        "source_sha256": decision.source_sha256,
    }
    return json.dumps(payload, sort_keys=True) + "\n"


def _matched_rule_json(rule: MatchedRule) -> dict[str, str]:
    return {
        "field": rule.field,
        "op": rule.op,
        "matched_evidence": rule.matched_evidence,
    }


def write_decisions(decisions: tuple[Decision, ...], output_path: Path) -> None:
    """Write the decision audit trail in the caller's deterministic order."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _ = output_path.write_text(
        "".join(serialize_decision(decision) for decision in decisions),
        encoding="utf-8",
    )


def load_decisions(path: Path) -> tuple[Decision, ...]:
    """Load a decision audit trail written by serialize_decision."""
    decisions: list[Decision] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        payload = cast("dict[str, object]", json.loads(line))
        decisions.append(
            Decision(
                sample_id=_int_field(payload, "sample_id"),
                relative_path=str(payload["relative_path"]),
                decision=str(payload["decision"]),
                bucket=str(payload.get("bucket", payload["decision"])),
                action=None
                if payload.get("action") is None
                else str(payload["action"]),
                matched_rules=_matched_rule_tuple(payload, "matched_rules"),
                matched_signals=_matched_rule_tuple(payload, "matched_signals"),
                signal_score=_optional_int_field(payload, "signal_score", 0),
                rejected_candidates=tuple(
                    _rejected_candidate_from_json(raw)
                    for raw in _list_field(payload, "rejected_candidates")
                ),
                fallback_reason=(
                    None
                    if payload.get("fallback_reason") is None
                    else str(payload["fallback_reason"])
                ),
                registry_sha256=str(payload["registry_sha256"]),
                source_sha256=str(payload["source_sha256"]),
            )
        )
    return tuple(decisions)


def _int_field(payload: dict[str, object], key: str) -> int:
    """Read a required integer field, rejecting non-integer JSON values."""
    value = payload[key]
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = f"Expected an integer for {key!r}, got {value!r}."
    raise ValueError(msg)


def _optional_int_field(
    payload: dict[str, object], key: str, default: int
) -> int:
    """Read an optional integer field, defaulting old decision artifacts."""
    if key not in payload:
        return default
    return _int_field(payload, key)


def _list_field(payload: dict[str, object], key: str) -> list[object]:
    """Read an optional list field, defaulting old decision artifacts."""
    value = payload.get(key, [])
    if isinstance(value, list):
        return cast("list[object]", value)
    msg = f"Expected a list for {key!r}, got {value!r}."
    raise ValueError(msg)


def _matched_rule_tuple(
    payload: dict[str, object], key: str
) -> tuple[MatchedRule, ...]:
    return tuple(_matched_rule_from_json(raw) for raw in _list_field(payload, key))


def _matched_rule_from_json(raw: object) -> MatchedRule:
    entry = cast("dict[str, object]", raw)
    return MatchedRule(
        field=str(entry["field"]),
        op=str(entry["op"]),
        matched_evidence=str(entry["matched_evidence"]),
    )


def _rejected_candidate_from_json(raw: object) -> RejectedCandidate:
    entry = cast("dict[str, object]", raw)
    return RejectedCandidate(
        category=str(entry["category"]),
        bucket=str(entry.get("bucket", entry["category"])),
        priority=_int_field(entry, "priority"),
        matched_rules=_matched_rule_tuple(entry, "matched_rules"),
        matched_signals=_matched_rule_tuple(entry, "matched_signals"),
        signal_score=_optional_int_field(entry, "signal_score", 0),
        lost_to=str(entry["lost_to"]),
    )


def _evaluate_rule(rule: Rule, record: FeatureRecord) -> MatchedRule | None:
    if rule.op == "regex":
        return _regex_match(rule, record)
    if rule.op == "eq":
        return _eq_match(rule, record)
    if rule.op == "in":
        return _in_match(rule, record)
    if rule.op == "extension_in":
        return _extension_in_match(rule, record)
    message = f"Unsupported op: {rule.op}"
    raise ClassificationError(message=message)


def _field_value(record: FeatureRecord, field: str) -> object:
    lookup: dict[str, object] = {
        "subject": record.subject,
        "body_evidence": record.body_evidence,
        "from_domain": record.from_domain,
        "reply_to_domain": record.reply_to_domain,
        "envelope_domain": record.envelope_domain,
        "mime_form": record.mime_form,
        "unicode_obfuscation": record.unicode_obfuscation,
        "sender_reply_agree": record.sender_reply_agree,
        "sender_envelope_agree": record.sender_envelope_agree,
        "url_count": record.url_count,
        "from_display_name": record.from_display_name,
        "message_id_domain": record.message_id_domain,
        "spf_result": record.spf_result,
        "dkim_result": record.dkim_result,
        "dmarc_result": record.dmarc_result,
        "header_encoding_anomaly": record.header_encoding_anomaly,
        "url_host_matches_from": record.url_host_matches_from,
        "quality_flags": record.quality_flags,
        "languages": record.languages,
        "charsets": record.charsets,
    }
    if field not in lookup:
        raise ClassificationError(message=f"Unsupported field: {field}")
    return lookup[field]


def _regex_match(rule: Rule, record: FeatureRecord) -> MatchedRule | None:
    raw = _field_value(record, rule.field)
    if not isinstance(raw, str):
        message = f"Field {rule.field} is not text"
        raise ClassificationError(message=message)
    pattern = re.compile(str(rule.value))
    match = pattern.search(raw)
    if match is None:
        return None
    excerpt = match.group(0)
    if len(excerpt) > EVIDENCE_EXCERPT_LIMIT:
        excerpt = excerpt[:EVIDENCE_EXCERPT_LIMIT]
    return MatchedRule(field=rule.field, op=rule.op, matched_evidence=excerpt)


def _eq_match(rule: Rule, record: FeatureRecord) -> MatchedRule | None:
    value = _field_value(record, rule.field)
    if value != rule.value:
        return None
    return MatchedRule(field=rule.field, op=rule.op, matched_evidence=str(value))


def _in_match(rule: Rule, record: FeatureRecord) -> MatchedRule | None:
    raw_value = rule.value
    if not isinstance(raw_value, tuple):
        raw_value = (str(raw_value),)
    allowed = set(raw_value)
    field_value = _field_value(record, rule.field)
    if isinstance(field_value, str):
        if field_value not in allowed:
            return None
        return MatchedRule(field=rule.field, op=rule.op, matched_evidence=field_value)
    if isinstance(field_value, tuple):
        present = sorted(
            item
            for item in cast("tuple[str, ...]", field_value)
            if item in allowed
        )
        if not present:
            return None
        return MatchedRule(
            field=rule.field, op=rule.op, matched_evidence=",".join(present)
        )
    message = f"Field {rule.field} is not a text or list field"
    raise ClassificationError(message=message)


def _extension_in_match(rule: Rule, record: FeatureRecord) -> MatchedRule | None:
    raw_value = rule.value
    if not isinstance(raw_value, tuple):
        raw_value = (str(raw_value),)
    allowed = set(raw_value)
    extensions = tuple(attachment.extension for attachment in record.attachments)
    present = sorted({ext for ext in extensions if ext in allowed})
    if not present:
        return None
    return MatchedRule(
        field=rule.field, op=rule.op, matched_evidence=",".join(present)
    )
