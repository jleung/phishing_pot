# Problems

## 2026-09-23
- Open blocker: confirm a GPT-5.6-only worker/reviewer route before code or test delegation.

## 2026-09-23 Confirmed routing failure
- `category=deep` routed Task 1 to Qwen (`omlx-studio/Qwen3.8-27B-oQ4e-mtp`). The API has no model selector. A verified `openai/gpt-5.6-*` implementation-worker route is required to resume.

## 2026-09-23 Capability mismatch
- Confirmed `openai/gpt-5.6-luna-fast` route via `explore`, but it is read-only. The only discovered write-capable route is Qwen. Configure a write-capable GPT-5.6 worker to unblock code changes while preserving the model constraint.
