import json
from pathlib import Path
from typing import cast

from phishing_contract.discover import (
    ClusterDossier,
    discover_clusters,
    write_dossiers,
)
from phishing_contract.models import (
    FeatureRecord,
    Provenance,
    SampleId,
    SourceRecord,
)


def _feature(
    sample_id: int,
    subject: str = "subject",
    body: str = "body",
    from_domain: str = "sender.example",
    languages: tuple[str, ...] = ("ascii",),
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
        attachments=(),
        url_count=0,
        url_host_hashes=(),
        url_host_matches_from=False,
        languages=languages,
        charsets=("utf-8",),
        unicode_obfuscation=False,
        from_display_name="",
        message_id_domain="",
        spf_result="none",
        dkim_result="none",
        dmarc_result="none",
        header_encoding_anomaly=False,
        quality_flags=(),
        provenance=Provenance("test-commit", "digest", "model"),
    )


def test_similar_unmatched_records_form_a_cluster() -> None:
    # Given: three near-identical credential lures and one unrelated email.
    records = (
        _feature(10, "Reset", "your password was reset click the link below"),
        _feature(11, "Reset", "your password was reset click the link below now"),
        _feature(12, "Reset", "your password was reset click the link immediately"),
        _feature(
            13,
            "Invoice",
            "please find the invoice attached for payment",
            from_domain="other.example",
        ),
    )

    # When: discovery groups the unmatched records at a moderate threshold.
    dossiers = discover_clusters(records, threshold=0.2, min_cluster_size=3)

    # Then: the three similar lures cluster and the outlier does not.
    assert len(dossiers) == 1
    dossier = dossiers[0]
    assert isinstance(dossier, ClusterDossier)
    assert dossier.seed_sample_id == 10
    assert dossier.sample_ids == (10, 11, 12)


def test_dossiers_surface_dominant_tokens_and_domains() -> None:
    # Given: records sharing a distinctive token and a sender domain.
    records = tuple(
        _feature(
            i,
            "Wire",
            "approve the wire transfer authorization today",
            from_domain="finance-mail.example",
        )
        for i in (1, 2, 3)
    )

    # When: the records are clustered.
    dossiers = discover_clusters(records, threshold=0.1, min_cluster_size=2)

    # Then: the dossier names the shared token and the shared domain.
    assert len(dossiers) == 1
    dossier = dossiers[0]
    seen_terms = {top_term.token for top_term in dossier.top_tokens}
    assert "wire" in seen_terms
    assert "transfer" in seen_terms
    dossier_domains = {entry.token for entry in dossier.domains}
    assert "finance-mail.example" in dossier_domains
    assert dossier.example_subjects == ("Wire",)


def test_singleton_clusters_below_min_size_are_dropped() -> None:
    # Given: two unrelated records.
    records = (
        _feature(1, "A", "alpha beta gamma delta", from_domain="alpha.example"),
        _feature(2, "B", "epsilon zeta eta theta", from_domain="beta.example"),
    )

    # When: discovery requires clusters of at least two.
    dossiers = discover_clusters(records, threshold=0.1, min_cluster_size=2)

    # Then: nothing is reported.
    assert dossiers == ()


def test_discovery_is_deterministic() -> None:
    # Given: a mixed population of unmatched records.
    records = tuple(
        _feature(
            i,
            "Points",
            f"your loyalty points balance expires redeem now batch {i}",
        )
        for i in range(1, 7)
    )

    # When: discovery runs twice over the same records.
    first = discover_clusters(records, threshold=0.1, min_cluster_size=2)
    second = discover_clusters(records, threshold=0.1, min_cluster_size=2)

    # Then: the dossiers are identical.
    assert first == second


def test_write_dossiers_emits_stable_json(tmp_path: Path) -> None:
    # Given: a discovery result.
    records = tuple(
        _feature(
            i,
            "Points",
            "your loyalty points balance expires redeem now",
        )
        for i in (1, 2, 3)
    )
    dossiers = discover_clusters(records, threshold=0.1, min_cluster_size=2)
    output = tmp_path / "dossiers.json"

    # When: the dossiers are written twice.
    write_dossiers(
        dossiers,
        total_unmatched=3,
        output_path=output,
        threshold=0.1,
        min_cluster_size=2,
    )
    first = output.read_text(encoding="utf-8")
    write_dossiers(
        dossiers,
        total_unmatched=3,
        output_path=output,
        threshold=0.1,
        min_cluster_size=2,
    )
    second = output.read_text(encoding="utf-8")

    # Then: the artifact is valid, stable JSON with the run parameters.
    assert first == second
    payload = cast("dict[str, object]", json.loads(first))
    assert payload["threshold"] == 0.1
    assert payload["total_unmatched"] == 3
    clusters = cast("list[dict[str, object]]", payload["clusters"])
    assert len(clusters) == 1
    assert clusters[0]["sample_ids"] == [1, 2, 3]
