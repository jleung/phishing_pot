import pytest

from phishing_contract.policy import ModelPolicyError, ensure_model_allowed


def test_model_policy_allows_gpt_5_6_identifier() -> None:
    # Given: a routed GPT-5.6 model identifier.
    model_id = "openai/gpt-5.6-terra"

    # When: the manifest command validates the model policy.
    ensure_model_allowed(model_id)

    # Then: validation completes without a policy error.


def test_model_policy_rejects_non_gpt_5_6_identifier() -> None:
    # Given: a model identifier outside the approved route.
    model_id = "anthropic/claude-sonnet"

    # When: the manifest command validates the model policy.
    # Then: it returns an explicit routing policy error.
    with pytest.raises(ModelPolicyError, match="anthropic/claude-sonnet"):
        ensure_model_allowed(model_id)
