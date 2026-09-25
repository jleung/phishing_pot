from pathlib import Path

from phishing_contract.classify import (
    Decision,
    classify_record,
    serialize_decision,
)
from phishing_contract.features import extract_feature_record
from phishing_contract.models import (
    AttachmentMetadata,
    FeatureRecord,
    Provenance,
    SampleId,
    SourceRecord,
)
from phishing_contract.registry import (
    Category,
    CategoryRegistry,
    Rule,
    load_registry,
)


def _feature(
    sample_id: int = 1,
    subject: str = "subject text",
    body: str = "body text",
    from_domain: str = "sender.example",
    attachments: tuple[str, ...] = (),
    url_count: int = 0,
    url_host_matches_from: bool = False,
    unicode_obfuscation: bool = False,
    quality_flags: tuple[str, ...] = (),
    languages: tuple[str, ...] = ("ascii",),
    from_display_name: str = "",
    message_id_domain: str = "",
    spf_result: str = "none",
    dkim_result: str = "none",
    dmarc_result: str = "none",
    header_encoding_anomaly: bool = False,
    subject_math_stylized: bool = False,
    body_encoded: bool = False,
) -> FeatureRecord:
    source = SourceRecord(SampleId(sample_id), f"sample-{sample_id}.eml", 0, "fixture")
    return FeatureRecord(
        source=source,
        subject=subject,
        body_evidence=body,
        from_domain=from_domain,
        reply_to_domain=from_domain,
        envelope_domain=from_domain,
        sender_reply_agree=True,
        sender_envelope_agree=True,
        mime_form="text/plain",
        url_count=url_count,
        url_host_hashes=(),
        url_host_matches_from=url_host_matches_from,
        attachments=tuple(
            AttachmentMetadata(
                name=f"file.{extension}",
                extension=extension,
                byte_size=1,
                sha256="fixture",
            )
            for extension in attachments
        ),
        languages=languages,
        charsets=("utf-8",),
        unicode_obfuscation=unicode_obfuscation,
        from_display_name=from_display_name,
        message_id_domain=message_id_domain,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        header_encoding_anomaly=header_encoding_anomaly,
        subject_math_stylized=subject_math_stylized,
        body_encoded=body_encoded,
        quality_flags=quality_flags,
        provenance=Provenance("test-commit", "digest", "model"),
    )


def test_forwarding_prefixes_do_not_hide_prize_subjects() -> None:
    # Given: the live taxonomy and a prize subject with an RE:/address prefix,
    # plus a purely stylized-unicode subject with no intent wording.
    registry = load_registry(
        Path(__file__).parent.parent / "categories" / "taxonomy-v5.toml"
    )
    forwarded = classify_record(
        _feature(
            sample_id=3273,
            subject="RE:phishing@pot, You have won an Makita 6-pc Combo Kit",
        ),
        registry,
    )
    stylized = classify_record(
        _feature(
            sample_id=3130,
            # Deliberate: the subject is a stylized unicode lure sample; its
            # non-latin characters are the signal under test.
            subject="#𝘿𝙄𝙔: 𝙃𝙊𝙒 𝙏𝙊 𝙏𝘼𝙆𝙀 𝙔𝙀𝘼𝙍𝙎 𝙊𝙁𝙁 𝙔𝙊𝙐𝙍 𝙉𝙀𝘾𝙆'𝙎 𝘼𝙋𝙋𝙀𝘼𝙍𝘼𝙉𝘾𝙀",  # noqa: RUF001
            subject_math_stylized=True,
        ),
        registry,
    )

    # Then: the intent category wins over the technique category, and the
    # technique category still owns subjects with no intent wording.
    assert forwarded.decision == "prize-won"
    assert stylized.decision == "stylized-unicode-subject"


def test_header_derived_fields_are_matchable_from_a_registry() -> None:
    # Given: a registry that rules over header-derived fields.
    registry = load_registry(
        Path(__file__).parent / "fixtures" / "categories" / "header-fields.toml"
    )
    record = _feature(
        sample_id=50,
        from_display_name="Microsoft account team",
        dkim_result="fail",
        header_encoding_anomaly=True,
    )

    # When: the record is classified against the registry.
    decision = classify_record(record, registry)

    # Then: the header-derived fields drive the match.
    assert decision.decision == "spoofed-brand-alert"
    assert {rule.field for rule in decision.matched_rules} == {
        "from_display_name",
        "dkim_result",
        "header_encoding_anomaly",
    }


def _registry(*categories: Category) -> CategoryRegistry:
    return CategoryRegistry(
        schema_version=1,
        categories=categories,
        source_sha256="registry-digest",
    )


def test_single_matching_rule_produces_category_decision_with_evidence() -> None:
    # Given: a category with a regex rule that matches the record body.
    category = Category(
        id="login-lure",
        bucket="login-lure",
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)account update"),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    record = _feature(body="Please complete your account update now.")

    # When: the record is classified against the one-category registry.
    decision = classify_record(record, _registry(category))

    # Then: the decision names the category, its action, and the matched text.
    assert decision.decision == "login-lure"
    assert decision.action == "quarantine"
    assert decision.fallback_reason is None
    assert decision.sample_id == 1
    assert decision.matched_rules[0].field == "body_evidence"
    assert decision.matched_rules[0].matched_evidence == "account update"
    assert decision.rejected_candidates == ()


def test_category_requires_all_rules_to_match() -> None:
    # Given: a category whose two rules cannot both match one record.
    category = Category(
        id="strict",
        bucket="strict",
        description="d",
        action="quarantine",
        priority=10,
        rules=(
            Rule(field="subject", op="regex", value="(?i)invoice"),
            Rule(field="body_evidence", op="regex", value="(?i)wire transfer"),
        ),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    record = _feature(subject="Invoice 991", body="please review the invoice")

    # When: only one of the two rules matches.
    decision = classify_record(record, _registry(category))

    # Then: the record is unmatched with an explicit fallback reason.
    assert decision.decision == "unmatched"
    assert decision.action is None
    assert decision.fallback_reason == "no_rules_matched"


def test_higher_priority_category_wins_and_loser_is_rejected() -> None:
    # Given: two categories that both match, at different priorities.
    low = Category(
        id="brand-generic",
        bucket="brand-generic",
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    high = Category(
        id="login-lure",
        bucket="login-lure",
        description="d",
        action="quarantine",
        priority=20,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)account update"),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    record = _feature(body="your account update")

    # When: the record is classified against both categories.
    decision = classify_record(record, _registry(low, high))

    # Then: the higher priority wins and the loser is recorded as rejected.
    assert decision.decision == "login-lure"
    assert len(decision.rejected_candidates) == 1
    rejected = decision.rejected_candidates[0]
    assert rejected.category == "brand-generic"
    assert rejected.lost_to == "login-lure"
    assert rejected.matched_rules[0].matched_evidence == "update"


def test_signal_threshold_matches_candidate_and_is_observational() -> None:
    # Given: a residual category with no hard rules and three soft signals.
    category = Category(
        id="account-residual",
        bucket="account-security",
        description="d",
        action="flag",
        priority=10,
        rules=(),
        signals=(
            Rule(field="subject", op="regex", value="(?i)account"),
            Rule(field="body_evidence", op="regex", value="(?i)verify"),
            Rule(field="url_host_matches_from", op="eq", value=False),
        ),
        min_signals=2,
        acceptance=(),
    )
    record = _feature(
        subject="Account notice",
        body="Please verify today",
        url_host_matches_from=False,
    )

    # When: enough signals match.
    decision = classify_record(record, _registry(category))
    serialized = serialize_decision(decision)

    # Then: the category matches and the signal evidence is reported separately.
    assert decision.decision == "account-residual"
    assert decision.bucket == "account-security"
    assert decision.matched_rules == ()
    assert [signal.field for signal in decision.matched_signals] == [
        "subject",
        "body_evidence",
        "url_host_matches_from",
    ]
    assert decision.signal_score == 3
    assert '"matched_signals"' in serialized
    assert '"signal_score": 3' in serialized


def test_signal_score_does_not_break_priority_ties() -> None:
    # Given: two equal-priority categories, one with more matching signals.
    first = Category(
        id="alpha",
        bucket="alpha",
        description="d",
        action="a1",
        priority=10,
        rules=(),
        signals=(
            Rule(field="subject", op="regex", value="(?i)account"),
            Rule(field="body_evidence", op="regex", value="(?i)verify"),
        ),
        min_signals=1,
        acceptance=(),
    )
    second = Category(
        id="beta",
        bucket="beta",
        description="d",
        action="a2",
        priority=10,
        rules=(),
        signals=(Rule(field="subject", op="regex", value="(?i)account"),),
        min_signals=1,
        acceptance=(),
    )
    record = _feature(subject="Account notice", body="Please verify")

    # When: both categories match but have different signal scores.
    decision = classify_record(record, _registry(first, second))

    # Then: priority ties still go to review instead of being score-ranked.
    assert decision.decision == "needs_review"
    scores = {
        candidate.category: candidate.signal_score
        for candidate in decision.rejected_candidates
    }
    assert scores == {"alpha": 2, "beta": 1}


def test_priority_tie_resolves_to_needs_review() -> None:
    # Given: two categories with equal priority that both match.
    first = Category(
        id="alpha",
        bucket="alpha",
        description="d",
        action="a1",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    second = Category(
        id="beta",
        bucket="beta",
        description="d",
        action="a2",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)account"),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    record = _feature(body="account update")

    # When: both categories match with equal priority.
    decision = classify_record(record, _registry(first, second))

    # Then: no silent winner; the tie is surfaced for review.
    assert decision.decision == "needs_review"
    assert decision.action is None
    assert decision.fallback_reason is not None
    assert "alpha" in decision.fallback_reason
    assert "beta" in decision.fallback_reason
    assert {c.category for c in decision.rejected_candidates} == {"alpha", "beta"}


def test_more_matched_rules_wins_a_priority_tie() -> None:
    # Given: two equal-priority rule-based categories that both match.
    first = Category(
        id="alpha",
        bucket="alpha",
        description="d",
        action="a1",
        priority=10,
        rules=(
            Rule(field="body_evidence", op="regex", value="(?i)account"),
            Rule(field="body_evidence", op="regex", value="(?i)update"),
        ),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    second = Category(
        id="beta",
        bucket="beta",
        description="d",
        action="a2",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)account"),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    record = _feature(body="account update")

    # When: both categories match with equal priority.
    decision = classify_record(record, _registry(first, second))

    # Then: the category with more matched rules wins the tie.
    assert decision.decision == "alpha"
    assert [c.category for c in decision.rejected_candidates] == ["beta"]


def test_eq_in_and_extension_ops_match_feature_fields() -> None:
    # Given: categories exercising eq, in, and extension_in ops.
    exact = Category(
        id="exact-domain",
        bucket="exact-domain",
        description="d",
        action="a",
        priority=30,
        rules=(Rule(field="from_domain", op="eq", value="bad.example"),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    flagged = Category(
        id="malformed-mail",
        bucket="malformed-mail",
        description="d",
        action="a",
        priority=20,
        rules=(Rule(field="quality_flags", op="in", value=("malformed",)),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    attached = Category(
        id="exe-attachment",
        bucket="exe-attachment",
        description="d",
        action="a",
        priority=10,
        rules=(
            Rule(field="attachments", op="extension_in", value=("exe", "scr")),
        ),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    registry = _registry(exact, flagged, attached)

    # When: records matching exactly one op each are classified.
    eq_decision = classify_record(_feature(from_domain="bad.example"), registry)
    in_decision = classify_record(
        _feature(quality_flags=("malformed",)), registry
    )
    ext_decision = classify_record(
        _feature(attachments=("exe",)), registry
    )

    # Then: each op resolves to its category.
    assert eq_decision.decision == "exact-domain"
    assert in_decision.decision == "malformed-mail"
    assert ext_decision.decision == "exe-attachment"


def test_gt_op_matches_integer_field_above_threshold() -> None:
    # Given: a category requiring at least one URL.
    category = Category(
        id="url-bearing",
        bucket="url-bearing",
        description="d",
        action="a",
        priority=30,
        rules=(Rule(field="url_count", op="gt", value=0),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    registry = _registry(category)

    # When: one record carries a URL and one does not.
    linked = classify_record(_feature(url_count=2), registry)
    bare = classify_record(_feature(url_count=0), registry)

    # Then: only the URL-bearing record resolves to the category.
    assert linked.decision == "url-bearing"
    assert linked.matched_rules[0].matched_evidence == "2"
    assert bare.decision == "unmatched"
    assert bare.fallback_reason == "no_rules_matched"


def test_serialize_decision_is_stable_sorted_jsonl() -> None:
    # Given: a decision with matched and rejected rules.
    category = Category(
        id="login-lure",
        bucket="login-lure",
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    record = _feature(body="your account update")
    decision = classify_record(record, _registry(category))

    # When: the decision is serialized twice.
    first = serialize_decision(decision)
    second = serialize_decision(decision)

    # Then: serialization is deterministic, single-line JSON with a newline.
    assert first == second
    assert first.endswith("\n")
    assert first.count("\n") == 1
    assert '"registry_sha256": "registry-digest"' in first
    assert '"sample_id": 1' in first
    assert '"source_sha256": "fixture"' in first


def test_decision_type_is_decision() -> None:
    # Given: any classified record.
    category = Category(
        id="login-lure",
        bucket="login-lure",
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
        signals=(),
        min_signals=0,
        acceptance=(),
    )
    decision = classify_record(_feature(body="update"), _registry(category))

    # Then: the classifier returns the typed Decision interface.
    assert isinstance(decision, Decision)


def test_registry_fixtures_are_consistent_with_feature_fixtures() -> None:
    # Given: the fixture registry and the fixture EML corpus.
    corpus = Path(__file__).parent / "fixtures" / "features"
    registry = load_registry(
        Path(__file__).parent / "fixtures" / "categories" / "valid.toml"
    )
    records: dict[int, FeatureRecord] = {}
    for sample_id, name in ((1, "sample-1.eml"), (2, "sample-2.eml")):
        source = SourceRecord(SampleId(sample_id), name, 0, "fixture")
        records[sample_id] = extract_feature_record(corpus, source)

    # When: the fixture emails are classified against the fixture registry.
    decisions = {
        sample_id: classify_record(record, registry)
        for sample_id, record in records.items()
    }

    # Then: the registry's acceptance expectations hold.
    assert decisions[1].decision == "login-update-lure"
    assert decisions[2].decision == "pdf-delivery"
