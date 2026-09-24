# Phishing classifier — design decisions and handoff

A deterministic, offline email classifier. It resolves each email to exactly
one named taxonomy bucket, with every decision auditable and the unmatched
tail discoverable. The 8,614-email Phishing Pot corpus in `email/` is the
**development and evaluation set** — the tool is designed for arbitrary email
streams, and the corpus is the sandbox where the taxonomy gets tuned.
Everything exists to be **tunable**: the taxonomy is data, every decision is
auditable, and the unmatched tail is discoverable.

If you are modifying the classifier, features, registry, or CLI — or running the
pipeline — start here. The code is the source of truth for *how*; this document
records *why* and the traps.

## Invariants (hard constraints — do not break)

1. **Deterministic.** Same corpus + registry → byte-identical artifacts. No
   timestamps, no dict-order luck; everything sorted, manifest-ordered.
2. **Raw content never enters artifacts.** `body_evidence` is sanitized text
   (URLs → `[url]`, emails → `[email]`, HTML → readable text). Attachments are
   name/size/sha256 only. Raw headers appear only on **stdout** via `show`.
3. **One bucket per email, never a silent pick.** Highest-priority match wins;
   equal priority is a **tie → `needs_review`** with both candidates recorded.
4. **Stdlib only** (`email`, `tomllib`, `re`, `hashlib`, `json`, `html.parser`).
   Zero runtime dependencies.
5. **TDD + clean gates** on every change: `uv run pytest tests -q`,
   `uv run ruff check src tests`, `uv run basedpyright` — all must be green
   before commit.

## Pipeline (one line each — read the modules for detail)

`manifest.py` sorts/hashes the corpus → `features.py` extracts the fixed
feature contract (HTML→text, URL/email redaction, header derivations) →
`registry.py` loads+validates the TOML taxonomy → `classify.py` resolves each
record to a `Decision` → `report.py` summarizes/diffs/acceptance-gates →
`discover.py` TF-IDF + greedy seed-and-absorb clusters over the unmatched tail.
CLI (`cli.py`): `classify`, `discover`, `diff`, `show`, `manifest`, `features`.

Artifacts land in `artifacts/` (gitignored): `<run>.decisions.jsonl`,
`<run>.summary.json`, `<run>.dossiers.json`.

## Decisions and the reasoning behind them

- **Named taxonomy over clustering.** Categories are the product; clusters are
  only *proposals* for new categories, surfaced in dossiers.
- **Registry is TOML data, not code.** Adding a category = TOML block +
  acceptance samples + re-run. The **acceptance gate** (exit 3) requires every
  acceptance sample to resolve to its own category — it is the regression test
  for the taxonomy. Verify acceptance candidates with `show` before wiring.
- **Tiny boolean DSL.** Ops: `regex` (search; records the matched excerpt ≤80
  chars), `eq`, `in`, `extension_in`. Bool fields use `eq`. All hard `rules`
  in a category must match (AND). Optional soft `signals` record extra evidence;
  `min_signals` can require N of those signals for broad residual categories.
- **Observability = the decision JSONL.** Per sample: winning `matched_rules`
  with evidence excerpts, *ranked* `rejected_candidates` (runner-up first, with
  its own evidence), `fallback_reason` (`no_rules_matched` | `priority_tie:a|b`),
  `registry_sha256` + `source_sha256`. `diff --before a.jsonl --after b.jsonl`
  shows stable count + from→to moves between runs.
- **Scores are observational only** (round 4). Resolution stays priority-based;
  a numeric score never breaks a tie.
- **Raw headers → typed derived features + `show` drill-down**, never raw text
  in the contract. Privacy, determinism, and the rule DSL all argued against
  embedding raw bytes.
- **HTML parts are collapsed to visible text** (script/style skipped; href
  targets feed `url_count`/`url_host_hashes` without entering evidence).
  Raw-markup evidence diluted discovery 10× (2,537-sample smear cluster vs.
  163 max after the fix).
- **Priority tiers (round 4):** specific subtypes 30, bucket-level residual
  categories 20, and the broad technique-only unicode category remains 10, so
  intent categories catch new phrasings without tying with subtypes.
- **Dev-set framing.** The tuning loop (dossier → new category → acceptance →
  re-run → diff) is a *development* workflow; what ships for arbitrary mail is
  the feature contract + registry + classifier. Acceptance samples are
  dev-set validation anchors, not production logic. Anything that only makes
  sense for this corpus belongs in docs, not in code.

## Generalization debt (fix when targeting live mail, not before)

- `sample_id` and `show --sample` key off the `sample-N.eml` filename
  convention. Replace with stable content-hash keys so arbitrary directories
  and single files work.
- The CLI requires a corpus directory + manifest; there is no single-file or
  batch-of-arbitrary-paths entry point yet.
- `provenance.model_identifier` still carries the leftover
  `openai/gpt-5.6-terra` policy string; for general use, provenance should be
  tool version + registry hash (the registry hash is already in decisions).

## Gotchas (all hit in production on this corpus)

- **TOML escapes: `\b` is a backspace (U+0008), not a word boundary.** Regex
  escapes in the registry must be double-escaped: `"\\b"`, `"\\d"`. A silent
  backspace in a regex means the category never matches; the acceptance gate is
  the catch. Validate with `tomllib.loads` + `re.compile` after editing.
- **`^`-anchored subject regexes hide forwarded variants.** Real subjects carry
  `RE:`/`Fw:`/`address, ` prefixes. Prefer word boundaries or bare phrases.
  (This bug cost 167 prize-won samples until fixed.)
- **`urlsplit` raises `ValueError` on malformed IPv6-style URLs.** Guard any
  URL parsing (see `_host_hash`).
- **`FeatureRecord` has no field defaults.** Adding a field breaks every
  construction site: `features.py` (`extract_feature_record`,
  `_empty_feature`) and the `_feature` helpers in `tests/test_classify.py` and
  `tests/test_discover.py`.
- **basedpyright strictness:** `EmailMessage.raw_items()` yields `Any` → cast
  the item; `HTMLParser` subclasses need `@override` on handlers and annotated
  attributes (`reportUnannotatedClassAttribute`).
- **`phishing@pot` and domain `pot` are anonymization artifacts** of the corpus,
  not a real sender. Don't build categories around them; ignore their presence
  in subjects/bodies.
- **Fixtures are tame; the corpus is not.** The 4+ fixture EMLs won't surface
  encoding chaos. Smoke-test changes with `show` on real samples and a full
  `classify` run (≈3 min; `discover` ≈5–9 min — use generous timeouts).
- **ruff S105** fires on `== "literal"` assertions over domain tokens;
  restructure to set-membership checks.

## State of the work

- Taxonomy: `categories/taxonomy-v4.toml` — 35 categories: 28 named subtypes
  plus 7 bucket-level residual categories. Earlier rounds: `seed.toml` (4),
  `taxonomy-v2.toml` (17), `taxonomy-v3.toml` (28).
- Latest run **v6**: 2,817 matched (32.7%), 131 needs_review, 5,666 unmatched.
  Curve: 242 → 523 → 1,183 → 1,344 → 2,817 matched across rounds.
- The unmatched tail remains a **power-law of hundreds of campaigns** (v6:
  427 clusters, 3,938 clustered of 5,666 unmatched). Single-regex categories
  hit diminishing returns; the plan is breadth, not count.
- Round 4 completed locally: `url_host_matches_from` is in the feature contract;
  the registry supports `signals` and `min_signals`; decisions carry
  `matched_signals` and `signal_score` without using scores for tie-breaking;
  categories carry `bucket`; summaries include `bucket_counts`; v4 adds 7
  residual bucket categories below subtype priority. Corpus run commands used:
  `classify` v5/v6, `diff` v5→v6, and `discover` v6 under `artifacts/round4/`
  (artifacts remain gitignored). Movement: 1,473 additional matched emails,
  1,593 fewer unmatched, 120 additional review ties; biggest new residuals are
  rewards-promotions (627), crypto (269), account-security (190), logistics
  (181), commerce-spam (105), financial (86), and government-legal (15).
  Discovery on the v6 unmatched tail found 427 clusters covering 3,938 of the
  5,666 unmatched samples; largest clusters point at portable-jump-starter/
  antivirus offers, German reminders, sextortion, McAfee renewals, and health
  plan promotions.

## Conventions

- **Adding a category:** TOML block → pick acceptance samples from the dossier
  clusters → verify each with `show` (and grep the EML — dossier subjects and
  sample IDs are *not* paired) → `classify` (acceptance gate) → `diff` against
  the previous run.
- Run IDs are lowercase round tags (`v5`, `v6`); registry files are versioned
  per round. Keep old registry files — `diff` needs comparable baselines.
- Commit style: imperative subject + short body naming the effect (counts moved).
- Tests: public-API-level, fixtures under `tests/fixtures/`, no network, no
  new runtime deps.

## Repository map

| Path | Role |
|---|---|
| `src/phishing_contract/` | `models` (contracts), `features` (extraction), `manifest`, `registry` (TOML loader), `classify` (matching + decisions), `report` (summary/diff/acceptance), `discover` (TF-IDF clusters), `cli` |
| `tests/` | one test module per module + fixtures (`features/`, `features-headers/`, `categories/`) |
| `categories/` | taxonomy versions (data) |
| `email/` | the 8,614-sample dev corpus (`sample-N.eml` → sample_id N), read-only |
| `artifacts/` | run outputs (gitignored) |
| `AGENTS.md` | pointer for coding agents → this document |
