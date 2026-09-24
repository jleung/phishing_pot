"""Versioned category registry: the declarative taxonomy for email triage."""

import hashlib
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast, override

SUPPORTED_SCHEMA_VERSION: Final = 1
CATEGORY_ID_PATTERN: Final = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
TEXT_FIELDS: Final = frozenset(
    {
        "subject",
        "body_evidence",
        "from_domain",
        "reply_to_domain",
        "envelope_domain",
        "mime_form",
        "from_display_name",
        "message_id_domain",
        "spf_result",
        "dkim_result",
        "dmarc_result",
    }
)
BOOL_FIELDS: Final = frozenset(
    {
        "unicode_obfuscation",
        "sender_reply_agree",
        "sender_envelope_agree",
        "header_encoding_anomaly",
    }
)
INT_FIELDS: Final = frozenset({"url_count"})
LIST_FIELDS: Final = frozenset({"quality_flags", "languages", "charsets"})
ATTACHMENT_FIELDS: Final = frozenset({"attachments"})
TEXT_OPS: Final = frozenset({"regex", "eq", "in"})
SCALAR_OPS: Final = frozenset({"eq"})
SUPPORTED_OPS: Final = TEXT_OPS | frozenset({"in", "extension_in"})
RuleValue = str | bool | int | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RegistryError(Exception):
    """Raised when a category registry file cannot form a valid taxonomy."""

    message: str

    @override
    def __str__(self) -> str:
        """Report the invalid registry value without email content."""
        return self.message


@dataclass(frozen=True, slots=True)
class Rule:
    """One testable condition over a feature record field."""

    field: str
    op: str
    value: RuleValue


@dataclass(frozen=True, slots=True)
class Category:
    """A named phishing subtype with an action and deterministic match rules."""

    id: str
    description: str
    action: str
    priority: int
    rules: tuple[Rule, ...]
    acceptance: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CategoryRegistry:
    """The complete, validated taxonomy for one classification run."""

    schema_version: int
    categories: tuple[Category, ...]
    source_sha256: str


def load_registry(path: Path) -> CategoryRegistry:
    """Parse and validate a TOML category registry from disk."""
    if not path.is_file():
        raise RegistryError(message=f"Registry file not found: {path}")
    raw = path.read_bytes()
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise RegistryError(message=f"Registry is not valid TOML: {error}") from error

    table = _table(document, "registry root")
    schema_value = table.get("schema_version")
    if schema_value != SUPPORTED_SCHEMA_VERSION:
        raise RegistryError(
            message=(
                f"Unsupported schema_version: {schema_value!r}; "
                f"expected {SUPPORTED_SCHEMA_VERSION}"
            )
        )

    categories: list[Category] = []
    seen_ids: set[str] = set()
    for entry in _array(table.get("category"), "category entries"):
        category = _category_from_entry(entry)
        if category.id in seen_ids:
            raise RegistryError(message=f"Duplicate category id: {category.id}")
        seen_ids.add(category.id)
        categories.append(category)

    return CategoryRegistry(
        schema_version=SUPPORTED_SCHEMA_VERSION,
        categories=tuple(categories),
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _category_from_entry(entry: object) -> Category:
    table = _table(entry, "category entry")
    category_id = _string(table.get("id"), "category id")
    if CATEGORY_ID_PATTERN.fullmatch(category_id) is None:
        raise RegistryError(
            message=f"Category id must be a lowercase slug: {category_id!r}"
        )

    description = _string(table.get("description"), "category description")
    action = _string(table.get("action"), "category action")

    priority_value = table.get("priority")
    if (
        isinstance(priority_value, bool)
        or not isinstance(priority_value, int)
    ):
        raise RegistryError(
            message=f"Category {category_id} priority must be an integer"
        )

    acceptance = tuple(
        _integer(sample_id, f"category {category_id} acceptance sample")
        for sample_id in _array(
            table.get("acceptance", []), f"category {category_id} acceptance"
        )
    )

    rules = tuple(
        _rule_from_entry(category_id, rule_entry)
        for rule_entry in _array(
            table.get("rules", []), f"category {category_id} rules"
        )
    )
    if not rules:
        raise RegistryError(
            message=f"Category {category_id} requires at least one rule"
        )

    return Category(
        id=category_id,
        description=description,
        action=action,
        priority=priority_value,
        rules=rules,
        acceptance=acceptance,
    )


def _rule_from_entry(category_id: str, entry: object) -> Rule:
    table = _table(entry, f"category {category_id} rule")

    field = _string(table.get("field"), f"category {category_id} rule field")
    if field not in (
        TEXT_FIELDS | BOOL_FIELDS | INT_FIELDS | LIST_FIELDS | ATTACHMENT_FIELDS
    ):
        raise RegistryError(
            message=f"Category {category_id} rule uses unsupported field: {field!r}"
        )

    op = _string(table.get("op"), f"category {category_id} rule op")
    if op not in SUPPORTED_OPS:
        raise RegistryError(
            message=f"Category {category_id} rule uses unsupported op: {op!r}"
        )

    value = table.get("value")
    value_as_object: object = value
    if op == "regex":
        if not isinstance(value, str):
            raise RegistryError(
                message=f"Category {category_id} regex op requires a string value"
            )
        try:
            _ = re.compile(value)
        except re.error as error:
            raise RegistryError(
                message=f"Category {category_id} rule has invalid regex: {error}"
            ) from error
    elif op == "eq":
        if not isinstance(value, str | bool | int):
            raise RegistryError(
                message=f"Category {category_id} eq op requires a scalar value"
            )
    elif op in {"in", "extension_in"}:
        if not isinstance(value, list):
            raise RegistryError(
                message=(
                    f"Category {category_id} {op} op requires an array of strings"
                )
            )
        _ = _string_list(
            cast("list[object]", value), f"category {category_id} {op} value"
        )

    _validate_op_field_fit(category_id, field, op)
    return Rule(field=field, op=op, value=_rule_value(value_as_object))


def _validate_op_field_fit(category_id: str, field: str, op: str) -> None:
    if field in TEXT_FIELDS:
        allowed_ops = TEXT_OPS
    elif field in BOOL_FIELDS | INT_FIELDS:
        allowed_ops = SCALAR_OPS
    elif field in LIST_FIELDS:
        allowed_ops = frozenset({"in"})
    else:
        allowed_ops = frozenset({"extension_in"})
    if op not in allowed_ops:
        raise RegistryError(
            message=(
                f"Category {category_id}: op {op!r} cannot be applied to "
                f"field {field!r}"
            )
        )


def _rule_value(value: object) -> RuleValue:
    if isinstance(value, list):
        return _string_list(cast("list[object]", value), "rule value")
    if isinstance(value, str | bool | int):
        return value
    raise RegistryError(message="Rule value must be a scalar or an array of strings")


def _string_list(raw: object, context: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise RegistryError(message=f"{context} must be an array of strings")
    items: list[str] = []
    for item in cast("list[object]", raw):
        if not isinstance(item, str):
            raise RegistryError(message=f"{context} must contain only strings")
        items.append(item)
    return tuple(items)


def _table(raw: object, context: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise RegistryError(message=f"{context} must be a TOML table")
    return cast("dict[str, object]", raw)


def _array(raw: object, context: str) -> list[object]:
    if not isinstance(raw, list):
        raise RegistryError(message=f"{context} must be a TOML array")
    return cast("list[object]", raw)


def _string(raw: object, context: str) -> str:
    if raw is None:
        raise RegistryError(message=f"{context} is missing")
    if not isinstance(raw, str) or raw == "":
        raise RegistryError(message=f"{context} must be a non-empty string")
    return raw


def _integer(raw: object, context: str) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise RegistryError(message=f"{context} must be an integer")
    return raw
