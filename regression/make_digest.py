"""Build a redacted digest of the regression sample from feature artifacts.

Stdlib only. Reads ``artifacts/<dir>/<run>.jsonl`` feature output (URLs and
email addresses are already redacted at extraction time) and writes one
compact line per sampled email so the 300-sample draw can be read and
labelled offline.
"""

import json
from pathlib import Path

from regression.sampler import sample_ids


def make_digest(
    features_path: Path, output_path: Path, body_limit: int = 260
) -> None:
    wanted = set(sample_ids())
    lines: list[str] = []
    seen: set[int] = set()
    for raw in features_path.read_text(encoding="utf-8").splitlines():
        if not raw:
            continue
        record = json.loads(raw)
        sample_id = record["sample_id"]
        if sample_id not in wanted:
            continue
        seen.add(sample_id)
        subject = record["subject"][:120]
        display = record["from_display_name"][:60]
        body = record["body_evidence"][:body_limit].replace("\n", " ")
        attachments = ",".join(a["name"][:30] for a in record["attachments"])
        lines.append(
            f"#{sample_id} | subj={subject!r} | from={display}@"
            f"{record['from_domain'][:40]} | urls={record['url_count']} "
            f"mime={record['mime_form'][:16]} atts=[{attachments}] | "
            f"body={body!r}"
        )
    missing = sorted(wanted - seen)
    if missing:
        raise SystemExit(f"digest missing samples: {missing}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    output_path.with_suffix(".txt.ok").write_text(
        f"{len(seen)} samples digested\n", encoding="utf-8"
    )


if __name__ == "__main__":
    make_digest(
        Path("artifacts/round5/v7-features.jsonl"),
        Path("regression/digest.txt"),
    )
