# Issues

## 2026-09-23 Session start
- Worker routing cannot currently be pinned through the available `task()` schema. Previous subagents routed to non-GPT-5.6 models, so do not dispatch implementation until GPT-5.6 routing can be verified.

## 2026-09-23 Task 1 model-policy gate
- The attempted `deep` implementation worker routed to `omlx-studio/Qwen3.8-27B-oQ4e-mtp`, not `openai/gpt-5.6-*`. It stopped before edits as instructed. Git verification found no product changes; Task 1 remains blocked.

## 2026-09-23 GPT-5.6 capability gate
- `explore` routed to allowed `openai/gpt-5.6-luna-fast`, but its session is read-only and returned `BLOCKED` before edits. The available write-capable `Sisyphus-Junior` route is Qwen; no verified GPT-5.6 write route is exposed.
