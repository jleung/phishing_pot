"""Deterministic 300-sample regression draw (rebuilt from the heuristic vet report).

Method: ``random.Random(20260224).sample`` over corpus sample IDs 1..8615
excluding 3989 (a CSV file in the corpus directory), N=300. Stdlib only.
"""

import random

SEED = 20260224
SAMPLE_SIZE = 300
ID_MIN = 1
ID_MAX = 8615
EXCLUDED_IDS = frozenset({3989})


def sample_ids() -> list[int]:
    """Return the deterministic regression sample as sorted sample IDs."""
    population = [
        sample_id
        for sample_id in range(ID_MIN, ID_MAX + 1)
        if sample_id not in EXCLUDED_IDS
    ]
    draw = random.Random(SEED).sample(population, SAMPLE_SIZE)
    return sorted(draw)


if __name__ == "__main__":  # pragma: no cover
    ids = sample_ids()
    assert len(ids) == SAMPLE_SIZE and len(set(ids)) == SAMPLE_SIZE
    print(len(ids), ids[:10])
