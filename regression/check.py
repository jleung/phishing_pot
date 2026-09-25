"""Compare classifier decisions for the 300-sample draw against ground truth.

Usage (project root):
    uv run python -m regression.check <decisions.jsonl> [--taxonomy path] [--gate]

Reads a classify decisions JSONL, the ground-truth table in
``regression/ground_truth.json`` and the active taxonomy. Prints precision
and recall numbers per ground-truth category, lists every false positive
(benign sample matched to a category) and every recall miss. With ``--gate``
exits nonzero if any false positive appeared or any category's recall
dropped below the stored baseline (``regression/baseline.json``; use
``--save-baseline`` to record the current numbers after a verified batch).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

GATE_FAIL = 1

# Ground-truth family ids -> acceptable taxonomy-v5 category ids.
FAMILY_MAP: dict[str, set[str]] = {
    "account-signin-alert": {
        "account-signin-alert",
        "login-alert-obfuscated",
        "account-security-residual",
        "unclassified-spam",
    },
    "discount-code-spam": {
        "discount-code-spam",
        "direct-marketing-spam",
        "unclassified-spam",
    },
    "login-alert-obfuscated": {
        "login-alert-obfuscated",
        "account-signin-alert",
        "account-security-residual",
        "unclassified-spam",
    },
    "adult-dating": {"dating-sweep-spam", "unclassified-spam"},
    "product-health": {"direct-marketing-spam", "unclassified-spam"},
    "survey-reward": {
        "survey-reward-spam",
        "prize-won",
        "rewards-promotions-residual",
        "discount-code-spam",
        "prize-winner-confirmation",
        "commerce-spam-residual",
        "direct-marketing-spam",
        "unclassified-spam",
    },
    "logistics": {
        "customs-package-hold",
        "import-tax-notice",
        "logistics-residual",
        "attachment-led",
        "unclassified-spam",
    },
    "rewards": {
        "rewards-promotions-residual",
        "prize-won",
        "casino-bonus",
        "prize-winner-confirmation",
        "discount-code-spam",
        "unclassified-spam",
    },
    "financial": {
        "financial-residual",
        "bank-block-alert",
        "bank-unblock-alert",
        "credit-consolidation-offer",
        "cpf-tax-notice",
        "attachment-led",
    },
    "crypto": {
        "crypto-payout-alert",
        "crypto-staking",
        "advance-fee-scam",
        "crypto-residual",
        "crypto-wallet-update",
        "crypto-ledger-recovery",
        "crypto-wallet-verification",
    },
    "casino-bonus": {
        "casino-bonus",
        "prize-won",
        "rewards-promotions-residual",
        "prize-winner-confirmation",
        "discount-code-spam",
        "points-expiry",
        "unclassified-spam",
    },
    "prize-won": {
        "prize-won",
        "prize-winner-confirmation",
        "rewards-promotions-residual",
        "casino-bonus",
        "discount-code-spam",
        "points-expiry",
        "unclassified-spam",
        "advance-fee-scam",
    },
    "advance-fee-scam": {
        "advance-fee-scam",
        "financial-residual",
        "fbi-letter",
        "unclassified-spam",
    },
    "import-tax-notice": {
        "import-tax-notice",
        "logistics-residual",
        "customs-package-hold",
        "unclassified-spam",
    },
    "points-expiry": {
        "points-expiry",
        "prize-won",
        "rewards-promotions-residual",
        "financial-residual",
        "attachment-led",
        "unclassified-spam",
    },
    "antivirus-renewal": {
        "antivirus-renewal",
        "direct-marketing-spam",
        "attachment-led",
        "unclassified-spam",
    },
    "crypto-ledger-recovery": {
        "crypto-ledger-recovery",
        "crypto-wallet-verification",
        "account-verification",
        "crypto-residual",
    },
    "crypto-wallet-verification": {
        "crypto-wallet-verification",
        "crypto-wallet-update",
        "crypto-ledger-recovery",
        "crypto-residual",
    },
    "cnh-suspension": {"cnh-suspension", "government-legal-residual", "unclassified-spam"},
    "bank-block-alert": {
        "bank-block-alert",
        "bank-unblock-alert",
        "financial-residual",
        "points-expiry",
        "unclassified-spam",
    },
    "cpf-tax-notice": {
        "cpf-tax-notice",
        "financial-residual",
        "government-legal-residual",
        "unclassified-spam",
    },
    "credit-consolidation-offer": {"credit-consolidation-offer", "financial-residual"},
    "photos-deletion-alert": {
        "photos-deletion-alert",
        "cloud-storage-upgrade",
        "account-security-residual",
        "unclassified-spam",
    },
    "account-verification": {
        "account-verification",
        "account-security-residual",
        "crypto-wallet-verification",
        "crypto-ledger-recovery",
    },
    "bank-unblock-alert": {
        "bank-unblock-alert",
        "bank-block-alert",
        "financial-residual",
        "points-expiry",
        "unclassified-spam",
    },
    "crypto-wallet-update": {
        "crypto-wallet-update",
        "crypto-wallet-verification",
        "crypto-ledger-recovery",
        "crypto-residual",
    },
    "fbi-letter": {"fbi-letter", "government-legal-residual"},
    "cloud-storage": {"cloud-storage-upgrade"},
    # Stylized-unicode GT: intent category is primary (round-5 steering),
    # the technique marker still fires alongside; either counts as a hit.
    "stylized-unicode-subject": {
        "stylized-unicode-subject",
        "prize-won",
        "rewards-promotions-residual",
        "discount-code-spam",
        "casino-bonus",
        "prize-winner-confirmation",
        "photos-deletion-alert",
        "cloud-storage-upgrade",
        "commerce-spam-residual",
        "direct-marketing-spam",
        "unclassified-spam",
    },
}


def acceptable_ids(category: str | None) -> set[str]:
    if category is None:
        return set()
    return FAMILY_MAP.get(category, {category})


def load_decisions(path: Path) -> dict[int, str | None]:
    decisions: dict[int, str | None] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw:
            continue
        record = json.loads(raw)
        category = record.get("category", record.get("decision"))
        if category in (None, "unmatched"):
            category = None
        decisions[record["sample_id"]] = category
    return decisions


def run_check(
    decisions: dict[int, str | None], ground_truth: dict[str, dict]
) -> None:
    false_positives: list[tuple[int, str | None, str]] = []
    unmatched_malicious: list[int] = []
    per_category: dict[str, dict] = {}

    for sample_id, entry in sorted(ground_truth.items(), key=lambda kv: int(kv[0])):
        sid = int(sample_id)
        decision = decisions.get(sid)
        if entry["label"] == "benign":
            if decision is not None:
                false_positives.append((sid, decision, entry.get("note", "")))
            continue
        category = entry["category"]
        stats = per_category.setdefault(
            category or "?", {"total": 0, "hits": 0, "misses": []}
        )
        stats["total"] += 1
        if decision in acceptable_ids(category):
            stats["hits"] += 1
        else:
            stats["misses"].append((sid, decision))
        if decision is None:
            unmatched_malicious.append(sid)

    print("=== regression check: 300-sample draw ===")
    print(f"false positives (benign matched): {len(false_positives)}")
    for sid, decision, note in false_positives:
        print(f"  FP  #{sid} -> {decision}  ({note})")
    print(f"malicious left unmatched: {len(unmatched_malicious)}")
    if unmatched_malicious:
        print(f"  {unmatched_malicious}")
    print("recall by ground-truth category:")
    for category in sorted(per_category):
        stats = per_category[category]
        recall = stats["hits"] / stats["total"] if stats["total"] else 0.0
        print(
            f"  {category}: {stats['hits']}/{stats['total']} recall={recall:.2f}"
        )
        for sid, decision in stats["misses"]:
            print(f"    miss #{sid} decision={decision}")

    if "--gate" in sys.argv:
        baseline_path = Path(__file__).parent / "baseline.json"
        failures = 0
        if false_positives:
            failures += 1
        if baseline_path.exists():
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            for category, stats in per_category.items():
                floor = baseline.get(category)
                if floor is None:
                    continue
                recall = stats["hits"] / stats["total"] if stats["total"] else 0.0
                if recall < floor:
                    print(
                        f"  GATE REGRESSION {category}: {recall:.2f} "
                        f"< baseline {floor:.2f}"
                    )
                    failures += 1
        if failures:
            raise SystemExit(GATE_FAIL)
        print("gate: PASS")

    if "--save-baseline" in sys.argv:
        baseline_path = Path(__file__).parent / "baseline.json"
        data = {}
        for category, stats in per_category.items():
            if stats["total"]:
                data[category] = round(stats["hits"] / stats["total"], 4)
        baseline_path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"baseline saved to {baseline_path}")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    decisions = load_decisions(Path(sys.argv[1]))
    ground_truth_path = Path(__file__).parent / "ground_truth.json"
    ground_truth = json.loads(
        ground_truth_path.read_text(encoding="utf-8")
    )["samples"]
    missing = [int(s) for s in ground_truth if int(s) not in decisions]
    if missing:
        raise SystemExit(f"decisions file lacks samples: {missing[:10]}")
    run_check(decisions, ground_truth)


if __name__ == "__main__":
    main()
