"""Similarity-based discovery of candidate categories among unmatched emails."""

import json
import math
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

from phishing_contract.models import FeatureRecord

TOKEN_PATTERN: Final = re.compile(r"[a-z0-9]{3,}")
SUBJECT_WEIGHT: Final = 3.0
DOMAIN_WEIGHT: Final = 2.0
ATTACHMENT_WEIGHT: Final = 3.0
LANGUAGE_WEIGHT: Final = 1.0
SUBCLUSTER_TRIGGER: Final = 30
TOP_TOKEN_LIMIT: Final = 15
EXAMPLE_SUBJECT_LIMIT: Final = 3
DOSSIER_SCHEMA_VERSION: Final = 1


@dataclass(frozen=True, slots=True)
class TokenCount:
    """One token (or domain/language) with its weight inside a dossier."""

    token: str
    weight: float


@dataclass(frozen=True, slots=True)
class ClusterDossier:
    """A reviewable dossier for one candidate category of unmatched emails."""

    seed_sample_id: int
    sample_ids: tuple[int, ...]
    top_tokens: tuple[TokenCount, ...]
    domains: tuple[TokenCount, ...]
    languages: tuple[TokenCount, ...]
    example_subjects: tuple[str, ...]
    stratum: str = ""
    subclusters: tuple["ClusterDossier", ...] = ()


def discover_clusters(
    records: tuple[FeatureRecord, ...],
    *,
    threshold: float,
    min_cluster_size: int,
    subcluster_threshold: float = 0.55,
    min_subcluster_size: int = 5,
) -> tuple[ClusterDossier, ...]:
    """Group unmatched records by TF-IDF similarity via deterministic seeding.

    Records are clustered within mechanism/language strata, host and tone tokens
    are added to the vector, and oversized clusters are re-clustered a second
    time so that dossiers stay under review size.
    """
    ordered: tuple[FeatureRecord, ...] = tuple(
        sorted(records, key=lambda record: int(record.source.sample_id))
    )
    frequencies = _document_frequencies(ordered)
    corpus_size = len(ordered)
    vectors = [
        _normalized_vector(_weighted_terms(record, frequencies, corpus_size))
        for record in ordered
    ]

    strata: dict[str, list[int]] = {}
    for index, record in enumerate(ordered):
        strata.setdefault(_stratum(record), []).append(index)

    dossiers: list[ClusterDossier] = []
    for stratum_name in sorted(strata):
        stratum_indices = strata[stratum_name]
        sub_vectors = [vectors[i] for i in stratum_indices]
        clusters = _incremental_cluster(sub_vectors, threshold)
        for indices in clusters:
            if len(indices) < min_cluster_size:
                continue
            global_indices = [stratum_indices[i] for i in indices]
            dossier = _dossier(ordered, global_indices, frequencies, corpus_size)
            if len(indices) >= SUBCLUSTER_TRIGGER:
                sub_clusters = _incremental_cluster(
                    [sub_vectors[i] for i in indices], subcluster_threshold
                )
                dossier = replace(
                    dossier,
                    stratum=stratum_name,
                    subclusters=tuple(
                        _dossier(
                            ordered,
                            [global_indices[i] for i in members],
                            frequencies,
                            corpus_size,
                        )
                        for members in sub_clusters
                        if len(members) >= min_subcluster_size
                    ),
                )
            else:
                dossier = replace(dossier, stratum=stratum_name)
            dossiers.append(dossier)
    return tuple(sorted(dossiers, key=_dossier_sort_key))


def stability_sweep(
    records: tuple[FeatureRecord, ...],
    *,
    min_cluster_size: int,
    thresholds: tuple[float, ...] = (
        0.60, 0.65, 0.70, 0.75, 0.80
    ),
) -> list[dict[str, object]]:
    """Report clustered volume per threshold to show where clusters stabilize."""
    results: list[dict[str, object]] = []
    for value in thresholds:
        dossiers = discover_clusters(
            records, threshold=value, min_cluster_size=min_cluster_size
        )
        results.append(
            {
                "threshold": value,
                "clustered": sum(len(d.sample_ids) for d in dossiers),
                "clusters": len(dossiers),
            }
        )
    return results


def _stratum(record: FeatureRecord) -> str:
    """Return the mechanism/language stratum that one record is clustered in."""
    if record.attachments:
        return f"attach:{record.attachments[0].extension}"
    if record.body_encoded:
        return "encoded"
    if record.subject_math_stylized:
        return "obfuscated"
    if record.url_count > 0:
        return "link"
    return "plain"


def _incremental_cluster(
    vectors: list[dict[str, float]], threshold: float
) -> list[list[int]]:
    clusters: list[list[int]] = []
    centroids: list[dict[str, float]] = []
    for index, vector in enumerate(vectors):
        best_cluster: int | None = None
        best_score = threshold
        for cluster_index, centroid in enumerate(centroids):
            score = _cosine(vector, centroid)
            if score > best_score:
                best_score = score
                best_cluster = cluster_index
        if best_cluster is None:
            best_cluster = len(clusters)
            clusters.append([])
            centroids.append({})
        cluster = clusters[best_cluster]
        cluster.append(index)
        centroids[best_cluster] = _mean_vector(tuple(vectors[i] for i in cluster))
    return clusters


def write_dossiers(  # noqa: PLR0913
    dossiers: tuple[ClusterDossier, ...],
    *,
    total_unmatched: int,
    output_path: Path,
    threshold: float,
    min_cluster_size: int,
    stability: list[dict[str, object]] | None = None,
) -> None:
    """Write the dossier artifact as stable, newline-terminated JSON."""
    payload = {
        "schema_version": DOSSIER_SCHEMA_VERSION,
        "threshold": threshold,
        "min_cluster_size": min_cluster_size,
        "total_unmatched": total_unmatched,
        "clustered": sum(len(dossier.sample_ids) for dossier in dossiers),
        "clusters": [_dossier_json(dossier) for dossier in dossiers],
    }
    if stability is not None:
        payload["stability"] = stability
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _ = output_path.write_text(
        json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
    )


def _dossier_sort_key(dossier: ClusterDossier) -> tuple[int, int]:
    return (-len(dossier.sample_ids), dossier.seed_sample_id)


def _dossier_json(dossier: ClusterDossier) -> dict[str, object]:
    return {
        "seed_sample_id": dossier.seed_sample_id,
        "sample_ids": list(dossier.sample_ids),
        "stratum": dossier.stratum,
        "subclusters": [_dossier_json(sub) for sub in dossier.subclusters],
        "top_tokens": [
            {"token": token.token, "weight": token.weight}
            for token in dossier.top_tokens
        ],
        "domains": [
            {"token": token.token, "weight": token.weight} for token in dossier.domains
        ],
        "languages": [
            {"token": token.token, "weight": token.weight}
            for token in dossier.languages
        ],
        "example_subjects": list(dossier.example_subjects),
    }


def _dossier(
    ordered: tuple[FeatureRecord, ...],
    indices: list[int],
    frequencies: dict[str, int],
    corpus_size: int,
) -> ClusterDossier:
    members = [ordered[index] for index in indices]
    token_weights: dict[str, float] = {}
    domain_weights: dict[str, float] = {}
    language_weights: dict[str, float] = {}
    for record in members:
        for token, weight in _weighted_terms(record, frequencies, corpus_size).items():
            if token.startswith(("domain:", "ext:", "lang:")):
                continue
            token_weights[token] = token_weights.get(token, 0.0) + weight
        if record.from_domain:
            domain_weights[record.from_domain] = (
                domain_weights.get(record.from_domain, 0.0) + 1.0
            )
        for language in record.languages:
            language_weights[language] = language_weights.get(language, 0.0) + 1.0

    examples: list[str] = []
    for record in members:
        if record.subject and record.subject not in examples:
            examples.append(record.subject)
            if len(examples) == EXAMPLE_SUBJECT_LIMIT:
                break

    return ClusterDossier(
        seed_sample_id=int(members[0].source.sample_id),
        sample_ids=tuple(int(record.source.sample_id) for record in members),
        top_tokens=_ranked(token_weights, TOP_TOKEN_LIMIT),
        domains=_ranked(domain_weights, 10),
        languages=_ranked(language_weights, 10),
        example_subjects=tuple(examples),
    )


def _ranked(weights: dict[str, float], limit: int) -> tuple[TokenCount, ...]:
    ranked = sorted(
        ((token, round(weight, 6)) for token, weight in weights.items()),
        key=lambda item: (-item[1], item[0]),
    )
    return tuple(
        TokenCount(token=token, weight=weight) for token, weight in ranked[:limit]
    )


def _document_frequencies(
    corpus: tuple[FeatureRecord, ...]
) -> dict[str, int]:
    frequencies: dict[str, int] = {}
    for record in corpus:
        for token in _raw_terms(record):
            frequencies[token] = frequencies.get(token, 0) + 1
    return frequencies


def _aux_terms(record: FeatureRecord, raw: dict[str, float]) -> None:
    """Add host, host-class, salutation, and urgency tokens to the raw vector."""
    for host in record.url_hosts:
        raw[f"host2:{host}"] = raw.get(f"host2:{host}", 0.0) + DOMAIN_WEIGHT
    for host_class in record.url_host_classes:
        raw[f"hclass:{host_class}"] = raw.get(f"hclass:{host_class}", 0.0) + 1.0
    if record.salutation != "none":
        raw[f"salut:{record.salutation}"] = (
            raw.get(f"salut:{record.salutation}", 0.0) + 1.0
        )
    if record.urgency:
        raw[f"urg:{record.urgency}"] = raw.get(f"urg:{record.urgency}", 0.0) + 1.0


def _weighted_terms(
    record: FeatureRecord, frequencies: dict[str, int], corpus_size: int
) -> dict[str, float]:
    raw: dict[str, float] = {}
    subject_tokens: list[str] = TOKEN_PATTERN.findall(record.subject.lower())
    body_tokens: list[str] = TOKEN_PATTERN.findall(record.body_evidence.lower())
    for token in subject_tokens:
        raw[token] = raw.get(token, 0.0) + SUBJECT_WEIGHT
    for token in body_tokens:
        raw[token] = raw.get(token, 0.0) + 1.0
    if record.from_domain:
        token = f"domain:{record.from_domain}"
        raw[token] = raw.get(token, 0.0) + DOMAIN_WEIGHT
    _aux_terms(record, raw)
    for attachment in record.attachments:
        if attachment.extension:
            token = f"ext:{attachment.extension}"
            raw[token] = raw.get(token, 0.0) + ATTACHMENT_WEIGHT
    for language in record.languages:
        token = f"lang:{language}"
        raw[token] = raw.get(token, 0.0) + LANGUAGE_WEIGHT
    return {
        token: tf * _idf(token, frequencies, corpus_size)
        for token, tf in raw.items()
    }


def _idf(token: str, frequencies: dict[str, int], corpus_size: int) -> float:
    document_frequency = frequencies.get(token, 0)
    return math.log((1 + corpus_size) / (1 + document_frequency)) + 1.0


def _raw_terms(record: FeatureRecord) -> set[str]:
    terms: set[str] = set()
    terms.update(TOKEN_PATTERN.findall(record.subject.lower()))
    terms.update(TOKEN_PATTERN.findall(record.body_evidence.lower()))
    if record.from_domain:
        terms.add(f"domain:{record.from_domain}")
    for host in record.url_hosts:
        terms.add(f"host2:{host}")
    for host_class in record.url_host_classes:
        terms.add(f"hclass:{host_class}")
    if record.salutation != "none":
        terms.add(f"salut:{record.salutation}")
    if record.urgency:
        terms.add(f"urg:{record.urgency}")
    for attachment in record.attachments:
        if attachment.extension:
            terms.add(f"ext:{attachment.extension}")
    for language in record.languages:
        terms.add(f"lang:{language}")
    return terms


def _normalized_vector(terms: dict[str, float]) -> dict[str, float]:
    norm = math.sqrt(sum(weight * weight for weight in terms.values()))
    if norm == 0.0:
        return {}
    return {token: weight / norm for token, weight in terms.items()}


def _mean_vector(vectors: tuple[dict[str, float], ...]) -> dict[str, float]:
    total: dict[str, float] = {}
    for vector in vectors:
        for token, weight in vector.items():
            total[token] = total.get(token, 0.0) + weight
    if not vectors:
        return {}
    return {token: weight / len(vectors) for token, weight in total.items()}


def _cosine(first: dict[str, float], second: dict[str, float]) -> float:
    if not first or not second:
        return 0.0
    dot = sum(weight * second.get(token, 0.0) for token, weight in first.items())
    first_norm = math.sqrt(sum(weight * weight for weight in first.values()))
    second_norm = math.sqrt(sum(weight * weight for weight in second.values()))
    if first_norm == 0.0 or second_norm == 0.0:
        return 0.0
    return dot / (first_norm * second_norm)
