---
slug: phishing-email-exclusive-clustering
intent: clear
review_required: false
classification: architecture
status: approved-for-plan-writing
---

## Components

- `corpus-ingestion`: Parse the 8,614 local `.eml` records while excluding the CSV outlier and retaining quality flags.
- `exclusive-taxonomy`: Assign every eligible email to exactly one primary security category with deterministic fallback behavior.
- `assignment-evidence`: Produce human-readable assignment evidence and contrasting alternatives for analyst review.
- `evaluation-governance`: Establish a frozen, independently reviewed gold set and measurable quality gates.
- `operational-monitoring`: Measure stability and drift as new email data or taxonomy revisions arrive.

## Evidence

- `/Users/jeff/dev/aegis/interview/README.md`: corpus provenance and `.eml` format convention.
- `/Users/jeff/dev/aegis/interview/email/`: 8,614 raw `.eml` samples; no label manifest or existing implementation/test surface.
- Representative reviewed messages span account verification, financial/tax claims, attachments, advance-fee fraud, cryptocurrency lures, and commercial promotion.
- Research: Artstein & Poesio (2008), Krippendorff (2011), scikit-learn clustering evaluation, and Monti et al. (2003), retrieved 2026-09-23.

## Decisions

- Approved primary partition: stable security taxonomy as the exclusive primary assignment; derive campaign/infrastructure as non-exclusive, queryable evidence.
- Approved taxonomy default: credential/account access; financial/tax/reward; attachment-led delivery; advance-fee/impersonation; cryptocurrency/investment; commercial promotion/spam-like abuse; other social engineering; malformed/insufficient-content. Resolve overlaps by operational objective, then requested action, then delivery mechanism.
- Evaluation must be transparent and analyst-vettable: adjudicated gold set, independent annotations, assignment rationales, coverage/exclusivity, class-aware external metrics, stability tests, and drift/review triggers.
- Hard model constraint: every implementation, evaluation, and review role must use a GPT-5.6 model. The workflow must reject or visibly report unavailable GPT-5.6 routing; it must not silently fall back to another model.

## Next action

Create the decision-complete work plan. The user approved the recommended stable-taxonomy approach and requested GPT-5.6-only routing.
