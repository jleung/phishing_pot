import hashlib
from pathlib import Path

import pytest

from phishing_contract.registry import (
    CategoryRegistry,
    RegistryError,
    load_registry,
)

FIXTURES = Path(__file__).parent / "fixtures" / "categories"
PROJECT_ROOT = Path(__file__).parent.parent


def test_registry_accepts_header_derived_fields() -> None:
    # Given: a registry that rules over the new header-derived fields.
    registry = load_registry(FIXTURES / "header-fields.toml")

    # Then: every field validates against the supported field sets.
    category, = registry.categories
    assert category.id == "spoofed-brand-alert"
    fields = {rule.field for rule in category.rules}
    assert fields == {"from_display_name", "dkim_result", "header_encoding_anomaly"}


def test_registry_accepts_signal_thresholds() -> None:
    # Given: a registry that uses signals without hard rules.
    registry = load_registry(FIXTURES / "signals.toml")

    # Then: the signal threshold and signal rules are validated and exposed.
    category, = registry.categories
    assert category.id == "account-risk-residual"
    assert category.bucket == "account-security"
    assert category.rules == ()
    assert category.min_signals == 2
    assert [signal.field for signal in category.signals] == [
        "subject",
        "url_host_matches_from",
        "body_evidence",
    ]


def test_load_registry_parses_categories_rules_and_metadata() -> None:
    # Given: a valid TOML registry with two categories and mixed rule ops.
    registry = load_registry(FIXTURES / "valid.toml")

    # When: the registry is inspected through its typed interface.
    # Then: every declared value round-trips without loss.
    assert isinstance(registry, CategoryRegistry)
    assert registry.schema_version == 1
    assert registry.source_sha256 == hashlib.sha256(
        (FIXTURES / "valid.toml").read_bytes()
    ).hexdigest()
    login, pdf = registry.categories
    assert login.id == "login-update-lure"
    assert login.bucket == "login-update-lure"
    assert login.action == "quarantine"
    assert login.priority == 20
    assert login.acceptance == (1,)
    assert login.rules[0].field == "body_evidence"
    assert login.rules[0].op == "regex"
    assert login.rules[0].value == "(?i)account update"
    assert login.signals == ()
    assert login.min_signals == 0
    assert pdf.id == "pdf-delivery"
    assert pdf.bucket == "pdf-delivery"
    assert pdf.rules[0].op == "extension_in"
    assert pdf.rules[0].value == ("pdf",)


def test_taxonomy_v4_has_bucket_residual_priority_tiers() -> None:
    # Given: the round-4 taxonomy.
    registry = load_registry(PROJECT_ROOT / "categories" / "taxonomy-v4.toml")

    # Then: every category declares one bucket, and residuals sit below subtypes.
    residuals = {
        category.id: category for category in registry.categories
        if category.id.endswith("-residual")
    }
    assert len(residuals) == 7
    assert all(category.bucket for category in registry.categories)
    assert {category.priority for category in residuals.values()} == {20}
    subtype_priorities = {
        category.id: category.priority for category in registry.categories
        if not category.id.endswith("-residual")
    }
    assert subtype_priorities.pop("stylized-unicode-subject") == 10
    assert set(subtype_priorities.values()) == {30}


def test_load_registry_rejects_duplicate_category_ids() -> None:
    # Given: a registry defining the same category id twice.
    # When: the registry is loaded.
    # Then: the error names the duplicated id.
    with pytest.raises(RegistryError, match="login-update-lure"):
        _ = load_registry(FIXTURES / "duplicate-id.toml")


def test_load_registry_rejects_unknown_rule_op() -> None:
    # Given: a registry whose rule uses an unsupported op.
    # When: the registry is loaded.
    # Then: the error names the unsupported op.
    with pytest.raises(RegistryError, match="startswith"):
        _ = load_registry(FIXTURES / "bad-op.toml")


def test_registry_accepts_gt_on_int_field() -> None:
    # Given: a registry whose rule compares an integer field with gt.
    registry = load_registry(FIXTURES / "gt-op.toml")

    # Then: the op and threshold survive validation.
    category, = registry.categories
    assert category.rules[0].op == "gt"
    assert category.rules[0].field == "url_count"
    assert category.rules[0].value == 0


def test_registry_rejects_gt_on_bool_field() -> None:
    # Given: a registry applying gt to a boolean field.
    # When: the registry is loaded.
    # Then: the field/op mismatch is rejected.
    with pytest.raises(RegistryError, match="op 'gt' cannot be applied"):
        _ = load_registry(FIXTURES / "gt-bool-field.toml")


def test_registry_rejects_gt_with_non_integer_value() -> None:
    # Given: a registry whose gt rule carries a string value.
    # When: the registry is loaded.
    # Then: the value type is rejected.
    with pytest.raises(RegistryError, match="integer"):
        _ = load_registry(FIXTURES / "gt-string-value.toml")


def test_load_registry_rejects_unknown_rule_field() -> None:
    # Given: a registry whose rule references a field outside the contract.
    # When: the registry is loaded.
    # Then: the error names the unsupported field.
    with pytest.raises(RegistryError, match="raw_headers"):
        _ = load_registry(FIXTURES / "bad-field.toml")


def test_load_registry_rejects_uncompilable_regex() -> None:
    # Given: a registry whose regex value does not compile.
    # When: the registry is loaded.
    # Then: the failure is reported before any record is ever matched.
    with pytest.raises(RegistryError, match="regex"):
        _ = load_registry(FIXTURES / "bad-regex.toml")


def test_load_registry_rejects_op_field_mismatch() -> None:
    # Given: a registry applying a text op to the attachment field.
    # When: the registry is loaded.
    # Then: the incompatibility is reported.
    with pytest.raises(RegistryError):
        _ = load_registry(FIXTURES / "op-field-mismatch.toml")


def test_load_registry_requires_declared_schema_version() -> None:
    # Given: a registry without the schema_version contract key.
    # When: the registry is loaded.
    # Then: the error reports the missing schema version.
    with pytest.raises(RegistryError, match="schema_version"):
        _ = load_registry(FIXTURES / "missing-schema.toml")


def test_load_registry_missing_file_is_a_registry_error() -> None:
    # Given: a registry path that does not exist.
    # When: the registry is loaded.
    # Then: the failure is a RegistryError, not an unhandled OSError.
    with pytest.raises(RegistryError, match="not found"):
        _ = load_registry(FIXTURES / "absent.toml")
