# Agent notes

This repo builds a deterministic phishing-email classifier over the Phishing
Pot corpus. Before modifying the classifier, feature extraction, taxonomy
(`categories/`), CLI, or before running or interpreting pipeline runs, read
`docs/DESIGN.md` — it holds the invariants, the gotchas hit on the real
corpus, current state, and implementation handoff notes.

- Gates before commit: `uv run pytest tests -q`, `uv run ruff check src tests`,
  `uv run basedpyright` — all must be clean.
- `README.md` is the upstream Phishing Pot corpus readme. Do not edit it.
- `email/` is the upstream corpus (8,614 EMLs). Treat it as read-only input.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
