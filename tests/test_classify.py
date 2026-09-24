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
    unicode_obfuscation: bool = False,
    quality_flags: tuple[str, ...] = (),
    languages: tuple[str, ...] = ("ascii",),
    from_display_name: str = "",
    message_id_domain: str = "",
    spf_result: str = "none",
    dkim_result: str = "none",
    dmarc_result: str = "none",
    header_encoding_anomaly: bool = False,
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
        quality_flags=quality_flags,
        provenance=Provenance("test-commit", "digest", "model"),
    )


def test_forwarding_prefixes_do_not_hide_prize_subjects() -> None:
    # Given: the live taxonomy and a prize subject with an RE:/address prefix,
    # plus a purely stylized-unicode subject with no intent wording.
    registry = load_registry(
        Path(__file__).parent.parent / "categories" / "taxonomy-v3.toml"
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
            subject="#𝘿𝙄𝙔: 𝙃𝙊𝙒 𝙏𝙊 𝙏𝘼𝙆𝙀 𝙔𝙀𝘼𝙍𝙎 𝙊𝙁𝙁 𝙔𝙊𝙐𝙍 𝙉𝙀𝘾𝙆'𝙎 𝘼𝙋𝙋𝙀𝘼𝙍𝘼𝙉𝘾𝙀",
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
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)account update"),),
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
        description="d",
        action="quarantine",
        priority=10,
        rules=(
            Rule(field="subject", op="regex", value="(?i)invoice"),
            Rule(field="body_evidence", op="regex", value="(?i)wire transfer"),
        ),
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
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
        acceptance=(),
    )
    high = Category(
        id="login-lure",
        description="d",
        action="quarantine",
        priority=20,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)account update"),),
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


def test_priority_tie_resolves_to_needs_review() -> None:
    # Given: two categories with equal priority that both match.
    first = Category(
        id="alpha",
        description="d",
        action="a1",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
        acceptance=(),
    )
    second = Category(
        id="beta",
        description="d",
        action="a2",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)account"),),
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


def test_eq_in_and_extension_ops_match_feature_fields() -> None:
    # Given: categories exercising eq, in, and extension_in ops.
    exact = Category(
        id="exact-domain",
        description="d",
        action="a",
        priority=30,
        rules=(Rule(field="from_domain", op="eq", value="bad.example"),),
        acceptance=(),
    )
    flagged = Category(
        id="malformed-mail",
        description="d",
        action="a",
        priority=20,
        rules=(Rule(field="quality_flags", op="in", value=("malformed",)),),
        acceptance=(),
    )
    attached = Category(
        id="exe-attachment",
        description="d",
        action="a",
        priority=10,
        rules=(
            Rule(field="attachments", op="extension_in", value=("exe", "scr")),
        ),
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


def test_serialize_decision_is_stable_sorted_jsonl() -> None:
    # Given: a decision with matched and rejected rules.
    category = Category(
        id="login-lure",
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
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
        description="d",
        action="quarantine",
        priority=10,
        rules=(Rule(field="body_evidence", op="regex", value="(?i)update"),),
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
