# phishing-email-exclusive-clustering - Work Plan

## TL;DR (For humans)

Build a reproducible email-security analysis pipeline that assigns every parseable `.eml` sample exactly one stable, analyst-facing primary category, while separately exposing campaign and infrastructure evidence. The plan prioritizes a transparent rule-and-evidence assignment path over opaque clustering so an analyst can inspect every decision.

It creates the new processing, taxonomy, evaluation, and reporting surface the data-only repository currently lacks. It does not execute attachments, render or visit message links, ingest the CSV outlier, or make campaign identity the exclusive primary label.

The work is organized in four dependency-ordered waves: corpus contracts; feature/evidence extraction; exclusive classification plus review artifacts; then gold-set, robustness, and drift evaluation. Main risks are corpus duplication, multilingual/encoded content, and taxonomic ambiguity; the evaluation gates explicitly test each.

## Scope

### In

- Parse and validate `/Users/jeff/dev/aegis/interview/email/sample-*.eml`, preserving source sample IDs and never following URLs or opening attachment payloads.
- Exclude `sample-3989.csv` from email ingestion and surface it in an exclusion report.
- Create a mutually exclusive, fixed primary taxonomy:
  1. credential/account access;
  2. financial/tax/reward;
  3. attachment-led delivery;
  4. advance-fee/impersonation;
  5. cryptocurrency/investment;
  6. commercial promotion/spam-like abuse;
  7. other social engineering;
  8. malformed/insufficient-content.
- Resolve ambiguity deterministically in this precedence order: operational objective, requested action, then delivery mechanism; emit the rejected alternatives and evidence.
- Retain campaign/infrastructure observations as secondary facets that cannot override the primary assignment.
- Build analyst-vettable evaluation artifacts, a frozen stratified gold set workflow, exact-one-label and fallback gates, raw/deduplicated/campaign-held-out metrics, temporal robustness, and drift monitoring.
- Require GPT-5.6 model routing for any model-based classification, annotation support, or reviewer role. Fail visibly if that constraint cannot be satisfied.

### Out

- Loading, rendering, visiting, executing, or detonating URLs, attachments, PDFs, or other payloads.
- Treating SPF/DKIM/DMARC success as a benign verdict.
- Treating campaign or sender infrastructure as the primary mutually exclusive label.
- Ingesting `sample-3989.csv`, which contains personal/financial information and is not an RFC email.
- Training a generic phishing/benign detector or making external network calls during analysis.

## Verification strategy

- **Test approach:** test-driven development for parsers, normalization, taxonomy precedence, and assignment evidence; tests-after for corpus-scale reports and manually curated gold-data integrity checks.
- Every dataset operation must be offline, deterministic, and produce versioned artifacts with command, source commit, configuration digest, record counts, exclusions, and model identifier.
- The implementation must prove: exactly one primary label per eligible record; campaign facets never change that label; inaccessible/malformed data is classified or explicitly excluded; and all reported quality metrics are computed on defined, leakage-free partitions.
- Gold-set annotator IDs must be separate from adjudicated labels; model-fitting/tuning IDs must be disjoint from blinded evaluation IDs.

## Execution strategy

1. Establish a safe package layout, reproducibility contract, schemas, fixtures, and corpus manifest.
2. Implement read-only MIME/header/body/URL/attachment-metadata extraction with normalized evidence and quality flags.
3. Encode the taxonomy definitions and precedence resolver; generate per-email decision cards and aggregate security/campaign-facet reports.
4. Add curated-data contracts and evaluation runners: exclusivity, inter-annotator agreement, external agreement, deduplication/campaign holdout, temporal holdout, stability, and drift gates.
5. Run corpus-scale offline evaluation, publish artifacts, and enforce final reviewer/quality checks with GPT-5.6-only model metadata validation.

## Todos

- [ ] 1. Establish the offline project, reproducibility, and corpus-contract foundation
  - **References:** `/Users/jeff/dev/aegis/interview/README.md:7,12,18`; `/Users/jeff/dev/aegis/interview/email/`; `/Users/jeff/dev/aegis/interview/email/sample-3989.csv`; `.omo/drafts/phishing-email-exclusive-clustering.md`.
  - **Work:** Create the Python package/tooling layout, locked dependency specification, CLI entry points, typed record schemas, configuration schema, source-commit/config/model provenance schema, and deterministic output directories. Implement discovery limited to `sample-<numeric-id>.eml`; create a manifest that counts eligible records, empty records, parse failures, and excluded non-EML files. Set the default model policy to `openai/gpt-5.6-terra` (or a configured GPT-5.6 equivalent) and fail any model-assisted invocation whose resolved model identifier does not match the GPT-5.6 allowlist.
  - **Must NOT:** read `sample-3989.csv` into any email-processing table or make network requests.
  - **Acceptance:** a clean checkout can produce a manifest whose eligible-record count equals the discovered `.eml` count, includes a reasoned `sample-3989.csv` exclusion, and persists source/config/model provenance; a non-GPT-5.6 configured model causes a nonzero, explicit policy error before processing.
  - **QA (happy):** run the manifest CLI against `email/`; assert all discovered EML IDs are unique and the exclusion report names only non-EML/out-of-contract files.
  - **QA (failure):** fixture directory with duplicate IDs, a CSV, and a bad filename exits with structured validation diagnostics; configure a non-GPT-5.6 model and assert policy rejection.
  - **Evidence:** `artifacts/manifests/<run-id>.json`, `tests/fixtures/corpus-contract/`, test report.
  - **Commit:** `feat: establish reproducible email corpus contract`.

- [ ] 2. Implement safe, normalized email feature and quality extraction
  - **References:** `/Users/jeff/dev/aegis/interview/email/sample-1.eml`; `sample-10.eml`; `sample-1000.eml`; `sample-1006.eml`; `sample-1014.eml`; `sample-1022.eml`; README anonymization guidance at `README.md:12`.
  - **Work:** Parse EML files without rendering HTML, resolving links, or extracting attachment bodies. Normalize encoded headers; decode displayable text safely; retain source-independent header fields; derive sender/reply/envelope agreement, MIME form, attachment names/extensions/hashes/size only, URL count and hashed/domain-normalized hosts only, language/charset/Unicode-obfuscation indicators, and SPF/DKIM/DMARC as non-dispositive fields. Separate attacker-authored body/header evidence from transport/filter headers; record malformed/empty/low-text/encoding quality flags.
  - **Must NOT:** emit raw sensitive URL query strings, attachment content, raw recipient values, or execute/render message content.
  - **Acceptance:** fixtures cover plain text, HTML, multipart/alternative, multipart/mixed/PDF metadata, encoded headers, malformed/empty data, and anonymized values; every parsed record has schema-valid features or a machine-readable quality failure.
  - **QA (happy):** run fixture parser and assert expected MIME, URL-domain count, attachment metadata, and decoded subject/body evidence without raw URLs or payload bytes.
  - **QA (failure):** corrupt MIME boundary, invalid transfer encoding, and zero-byte fixture yield quality flags without crashing or emitting unsafe content.
  - **Evidence:** `artifacts/features/<run-id>.jsonl`, parser test snapshots with redacted fields.
  - **Commit:** `feat: extract safe normalized email evidence`.

- [ ] 3. Define the exclusive taxonomy and deterministic assignment contract
  - **References:** `.omo/drafts/phishing-email-exclusive-clustering.md:24-30`; representative samples listed in Todo 2; research summary in draft `Evidence`.
  - **Work:** Publish category definitions, inclusion/exclusion examples, and precedence: first operational objective, then requested action, then delivery mechanism. Implement a typed resolver that assigns every eligible record exactly one of the eight approved categories, including malformed/insufficient-content. Preserve ranked candidate categories, triggering evidence, tie-break stage, and an assignment confidence/borderline indicator. Treat campaign/infrastructure/brand/authentication/attachment details as facets only.
  - **Must NOT:** use a multi-label primary output, hide alternatives for borderline cases, or classify an email as benign because authentication passes.
  - **Acceptance:** taxonomy documentation contains one semantic definition and explicit boundary example per category; resolver output has exactly one primary label for every fixture and carries a rationale; crafted overlaps demonstrate the approved precedence.
  - **QA (happy):** fixtures representing account verification, tax/reward, attachment-led lure, advance fee, crypto, and commercial promotion receive their intended single category with evidence.
  - **QA (failure):** ambiguous account-lock-with-PDF and authenticated attacker-domain fixtures prove objective/action outrank delivery/authentication; empty fixture lands in malformed/insufficient-content.
  - **Evidence:** `docs/taxonomy.md`, `artifacts/assignments/<run-id>.jsonl`, taxonomy precedence test report.
  - **Commit:** `feat: add exclusive email security taxonomy`.

- [ ] 4. Produce analyst decision cards and non-exclusive campaign/infrastructure facets
  - **References:** taxonomy resolver from Todo 3; corpus feature artifacts from Todo 2; sample campaign repetition and anonymization requirements from README.
  - **Work:** Generate one reviewable decision card per email containing stable ID, primary category, concise redacted rationale, evidence fields, ranked alternatives, quality flags, and model/provenance metadata. Compute campaign/infrastructure facets from normalized, privacy-preserving subject/template, sender/reply, URL-host, and attachment-name signals; explicitly record facets separately from `primary_category`. Produce aggregate views for category volume, brand claims, actions, URL/attachment profiles, and facets.
  - **Must NOT:** expose raw phishing URLs, overwrite primary labels from facet membership, or use time-only grouping as a campaign definition.
  - **Acceptance:** each decision card is independently understandable; all eligible records have one primary label, all facet fields are optional/many-valued, and automated validation proves no facet changes `primary_category`.
  - **QA (happy):** generate cards for representative fixture messages and assert evidence/rationale/redaction/provenance; campaign-like fixtures share a facet while retaining differing primary categories where appropriate.
  - **QA (failure):** a record with no facet evidence retains a valid primary label; an attempted facet-to-primary overwrite is rejected by schema/validation.
  - **Evidence:** `artifacts/reviews/<run-id>/`, aggregate report, facet-separation test output.
  - **Commit:** `feat: generate auditable assignment and campaign evidence`.

- [ ] 5. Create the human annotation, adjudication, and frozen-gold-set workflow
  - **References:** Artstein & Poesio (2008), https://doi.org/10.1162/coli.07-034-r2; Krippendorff (2011), https://doi.org/10.1080/19312458.2011.568376; taxonomy in Todo 3; decision cards in Todo 4.
  - **Work:** Define a blinded annotation export/import format and instructions that expose only the approved taxonomy/evidence needed for independent review. Create stratified sampling that includes all approved categories where available, multilingual content, malformed/encoded cases, attachment and URL variants, rare categories, and documented ambiguous cases. Require at least two independent annotation columns, record adjudication separately, freeze IDs and taxonomy version, and enforce no overlap with tuning/development IDs.
  - **Must NOT:** use model output as an annotator identity, overwrite independent labels during import, or let gold IDs enter tuning/model-selection data.
  - **Acceptance:** the workflow validates at least 300 frozen gold records (or reports an explicit corpus-availability failure by category), ≥2 independent labels per item, annotation provenance, language/boundary strata, and gold/tuning disjointness; it computes raw agreement and Krippendorff’s alpha with a target of ≥0.667.
  - **QA (happy):** import a complete synthetic two-annotator gold set; assert stratification, frozen versioning, agreement calculation, and disjoint IDs.
  - **QA (failure):** duplicate annotator identity, invalid category, missing second label, altered frozen row, or tuning-ID overlap is rejected with a clear report.
  - **Evidence:** `data/gold/<version>/manifest.json`, annotation-guide documentation, agreement report.
  - **Commit:** `feat: add independent gold-set evaluation workflow`.

- [ ] 6. Implement exclusive-assignment and external-quality evaluation gates
  - **References:** scikit-learn clustering metrics documentation, https://scikit-learn.org/stable/modules/clustering.html#homogeneity-completeness-and-v-measure; gold artifacts from Todo 5; assignments from Todo 3.
  - **Work:** Compute coverage, exactly-one-label violations, malformed/fallback rate, per-category support/confusion, and gold-set comparison metrics: homogeneity, completeness, V-measure, adjusted Rand index, plus category-level agreement. Enforce that `other social engineering` and `malformed/insufficient-content` rates are shown separately; set `other social engineering` target ≤20% pending final governance approval. Render reviewer-friendly tables that link only to redacted decision-card IDs.
  - **Must NOT:** report only a single aggregate score, conflate malformed records with semantic fallback, or claim category quality without a held-out gold partition.
  - **Acceptance:** evaluation fails if any eligible record has zero/multiple labels, gold/tuning leakage occurs, required metrics are absent, or fallback rate exceeds its configured gate; it emits numerator/denominator and per-category breakdowns.
  - **QA (happy):** known fixture/gold partition produces expected counts and metric values; exact-one-label gate passes.
  - **QA (failure):** inject duplicate/missing label, leaked gold ID, and excessive fallback records; each produces a targeted failure with no misleading summary.
  - **Evidence:** `artifacts/evaluations/<run-id>/external-quality.json` and rendered report.
  - **Commit:** `feat: add exclusive classification quality gates`.

- [ ] 7. Add deduplication, campaign-held-out, temporal, and perturbation stability evaluations
  - **References:** Monti et al. (2003), https://doi.org/10.1023/A:1023949509487; corpus date/header features from Todo 2; campaign facets from Todo 4.
  - **Work:** Define deterministic content/template near-duplicate groups using normalized, redacted features. Report metrics both raw and deduplicated; create a leave-top-10-campaign-facets-out partition so repeated templates cannot inflate results. Validate dates, isolate missing/implausible future dates from temporal evaluation with logged reasons, and evaluate earlier-to-later time splits. Run feature-configuration/resample/seed perturbations and compare assignments with partition-stability measures plus per-category retention. Declare metric thresholds/configuration in versioned policy, not source literals.
  - **Must NOT:** deduplicate by raw recipient fields, discard invalid dates silently, use temporal data from the evaluation window for tuning, or call a result stable without showing perturbation evidence.
  - **Acceptance:** every corpus-scale run publishes raw, deduplicated, campaign-held-out, temporal, and perturbation reports; invalid/missing dates have explicit dispositions; any configured stability or temporal-degradation breach makes the run non-passing rather than silently successful.
  - **QA (happy):** synthetic duplicate/campaign/time-split fixtures generate each partition and expected membership; stable fixture assignments meet a configured threshold.
  - **QA (failure):** date leakage, duplicate group split across held-out boundaries, missing campaign facet, and intentionally unstable assignments trigger failure artifacts.
  - **Evidence:** `artifacts/evaluations/<run-id>/robustness.json`, partition manifests, threshold policy.
  - **Commit:** `feat: evaluate robustness against campaigns and drift`.

- [ ] 8. Create drift monitoring, governance documentation, and an offline end-to-end runbook
  - **References:** all artifacts from Todos 1-7; corpus licensing/provenance at `/Users/jeff/dev/aegis/interview/README.md`; GPT-5.6 constraint in `.omo/drafts/phishing-email-exclusive-clustering.md:29`.
  - **Work:** Implement baseline-versus-current comparison for category mix, fallback/quality flags, language/MIME/URL/attachment profiles, campaign-facet volume, confidence/borderline distribution, and held-out quality where labels exist. Define review triggers, an analyst triage queue, taxonomy-version migration/re-evaluation rules, and an offline runbook that documents safety boundaries, model-policy verification, reproducibility commands, limitations, and honeypot selection bias.
  - **Must NOT:** automatically change taxonomy labels on drift, conceal selection bias, or mark a report healthy when model provenance is missing/non-GPT-5.6.
  - **Acceptance:** an end-to-end local run from a clean checkout creates manifest, features, assignments, cards, evaluation, robustness, and drift artifacts; a synthetic distribution shift triggers a review-required status; documentation states BEC/targeted-sample underrepresentation and raw-content safety limits.
  - **QA (happy):** run a small fixture corpus end-to-end offline and assert all artifact types, GPT-5.6 provenance, and no-network guard; inject a category/fallback-shift fixture and assert review trigger.
  - **QA (failure):** missing baseline, missing model provenance, non-GPT-5.6 identifier, or incompatible taxonomy version produces an explicit non-passing governance result.
  - **Evidence:** `docs/runbook.md`, `docs/governance.md`, `artifacts/drift/<run-id>.json`, end-to-end test report.
  - **Commit:** `docs: add clustering governance and operational runbook`.

## Final verification wave

- [ ] F1. Audit plan and implementation compliance against the exclusive-taxonomy, safety, and GPT-5.6-only requirements
  - **References:** `docs/taxonomy.md`, `docs/governance.md`, source model-policy validation, all run manifests.
  - **Acceptance:** independently verify every eligible EML has exactly one primary label, no campaign facet overrides it, no raw URLs/payloads appear in output artifacts, the CSV is excluded, and every model-assisted artifact declares a GPT-5.6 identifier.
  - **QA:** execute the full compliance audit CLI on fixture and corpus-scale artifacts; intentionally supply an unsafe/non-GPT model artifact and require rejection.
  - **Evidence:** `artifacts/final-verification/compliance.json`.

- [ ] F2. Run code-quality and reproducibility verification
  - **References:** package/tooling from Todo 1; deterministic artifacts from Todos 2-8.
  - **Acceptance:** formatting, linting, typing, unit/integration tests, and deterministic repeat-run comparison all pass; dependency lock and offline mode are enforced.
  - **QA:** run the documented format/lint/type/test commands and two identical fixture runs; inject an undeclared network/model configuration and require failure.
  - **Evidence:** `artifacts/final-verification/quality.json` and CI logs.

- [ ] F3. Execute analyst-facing decision-card and evaluation-artifact QA
  - **References:** decision cards from Todo 4; gold/evaluation reports from Todos 5-7.
  - **Acceptance:** a fixed review sample includes one card from every available category and borderline/quality cases; each card exposes a single label, rationale, alternatives, and redacted evidence; all required metric partition tables are present and interpretable.
  - **QA:** render the offline review report and validate required fields/links structurally; feed a fixture with a missing rationale/alternative and require the report build to fail.
  - **Evidence:** `artifacts/final-verification/analyst-review.json` and redacted review bundle.

- [ ] F4. Verify scope fidelity and corpus-risk handling
  - **References:** README safety/anonymization guidance; plan Scope; corpus manifest and exclusion/quality reports.
  - **Acceptance:** confirm the system performs no URL traversal/payload execution, no CSV ingestion, no benign verdict from authentication alone, and documents data-selection bias, date anomalies, duplicates, and language/encoding limitations.
  - **QA:** inspect code paths/configuration with safety tests and audit generated provenance/exclusion reports; a fixture that attempts a disallowed operation fails before processing.
  - **Evidence:** `artifacts/final-verification/scope-fidelity.json`.

## Commit strategy

Create one focused commit per numbered todo, pairing code with its direct tests and documentation. Keep corpus samples, generated full-corpus artifacts, raw message content, and annotation answers out of commits; commit only deterministic fixtures, schemas, policy/configuration, implementation, tests, and concise report manifests.

## Success criteria

- The repository has a reproducible, offline analysis path for the `.eml` corpus and an explicit exclusion record for the CSV outlier.
- Each eligible email has exactly one stable primary security category, a reviewable rationale, quality flags, and non-overriding campaign/infrastructure facets.
- Analysts can inspect an immutable gold-set workflow, inter-annotator agreement, category-level metrics, raw/deduplicated/campaign-held-out/temporal/stability results, and drift status.
- All model-assisted work is provably GPT-5.6-only or fails visibly before use.
- Safety controls prevent link traversal, payload execution, attachment-body extraction, and unsafe sensitive-output leakage.
