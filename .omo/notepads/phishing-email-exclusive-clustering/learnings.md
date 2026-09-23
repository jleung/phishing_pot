# Learnings

## 2026-09-23 Session start
- The repository is data-only; create all pipeline code and tests from scratch.
- Eligible inputs are only `email/sample-<numeric-id>.eml`; `sample-3989.csv` is out of contract and must never be ingested.
- Safety boundary: offline only; never traverse/render URLs, execute/read attachment bodies, or expose raw sensitive URL queries/recipient values.
- Primary taxonomy is exclusive; precedence is operational objective, requested action, then delivery mechanism. Campaign/infrastructure are facets only.
- GPT-5.6 routing is mandatory for every model-assisted worker, evaluator, or reviewer. The task tool exposes no model-selection argument, so unverified routing is a hard visible block, not a fallback.
