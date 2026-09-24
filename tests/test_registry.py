import hashlib
from pathlib import Path

import pytest

from phishing_contract.registry import (
    CategoryRegistry,
    RegistryError,
    load_registry,
)

FIXTURES = Path(__file__).parent / "fixtures" / "categories"


def test_registry_accepts_header_derived_fields() -> None:
    # Given: a registry that rules over the new header-derived fields.
    registry = load_registry(FIXTURES / "header-fields.toml")

    # Then: every field validates against the supported field sets.
    category, = registry.categories
    assert category.id == "spoofed-brand-alert"
    fields = {rule.field for rule in category.rules}
    assert fields == {"from_display_name", "dkim_result", "header_encoding_anomaly"}


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
    assert login.action == "quarantine"
    assert login.priority == 20
    assert login.acceptance == (1,)
    assert login.rules[0].field == "body_evidence"
    assert login.rules[0].op == "regex"
    assert login.rules[0].value == "(?i)account update"
    assert pdf.id == "pdf-delivery"
    assert pdf.rules[0].op == "extension_in"
    assert pdf.rules[0].value == ("pdf",)


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
