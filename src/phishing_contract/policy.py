"""Structural model-routing policy for all model-assisted workflow roles."""

from dataclasses import dataclass
from typing import Final, override

DEFAULT_MODEL_ID: Final = "openai/gpt-5.6-terra"
GPT_5_6_PREFIX: Final = "openai/gpt-5.6"


@dataclass(frozen=True, slots=True)
class ModelPolicyError(Exception):
    """Raised when a routed model is outside the approved GPT-5.6 family."""

    model_id: str

    @override
    def __str__(self) -> str:
        """Describe the rejected route without exposing any corpus content."""
        return (
            "Model policy requires an identifier beginning with "
            f"{GPT_5_6_PREFIX!r}; received {self.model_id!r}."
        )


def ensure_model_allowed(model_id: str) -> None:
    """Reject a model route that is not in the approved GPT-5.6 family."""
    if not model_id.startswith(GPT_5_6_PREFIX):
        raise ModelPolicyError(model_id=model_id)
