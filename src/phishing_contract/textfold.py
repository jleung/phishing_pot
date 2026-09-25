"""Deterministic text normalization shared by every rule match.

Round-5 steering (firstmate, 2026-02-24; heuristic vet
``data/interview-heuristic-vet/report.md``) requires that rules match on
normalized text, not raw bytes: casefold first, then map math-alphanumeric
(U+1D000-U+1DFFF) and Cyrillic/Greek lookalike characters to their ASCII
twins, NFKC-normalize, and collapse whitespace. Raw features remain stored
for audit; the stylized-unicode-subject marker reads the raw subject via
the ``subject_math_stylized`` boolean so it survives normalization.
"""

import re
import unicodedata
from typing import Final

_MATH_BLOCK: Final = range(0x1D000, 0x1E000)

# Lookalike twins applied after casefold (lowercase only).
_LOOKALIKES: Final = {
    # Cyrillic
    "\u0430": "a",
    "\u0431": "b",
    "\u0432": "v",
    "\u0434": "d",
    "\u0435": "e",
    "\u0437": "z",
    "\u043a": "k",
    "\u043c": "m",
    "\u043d": "n",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "s",
    "\u0442": "t",
    "\u0443": "y",
    "\u0444": "f",
    "\u0445": "x",
    "\u0456": "i",
    "\u0458": "j",
    # Greek
    "\u03b1": "a",
    "\u03b2": "b",
    "\u03b4": "d",
    "\u03b5": "e",
    "\u03b7": "h",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bb": "l",
    "\u03bc": "m",
    "\u03bd": "n",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c3": "s",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u03c7": "x",
    # Ligatures
    "\ufb00": "ff",
    "\ufb01": "fi",
    "\ufb02": "fl",
    "\ufb03": "ffi",
    "\ufb04": "ffl",
    # Circled digits
    "\u2460": "1",
    "\u2461": "2",
    "\u2462": "3",
    "\u2463": "4",
    "\u2464": "5",
    "\u2465": "6",
    "\u2466": "7",
    "\u2467": "8",
    "\u2468": "9",
    "\u2469": "10",
    # Canadian syllabics used as L lookalikes
    "\u14de": "l",
    "\u14dd": "l",
}

_DIGIT_WORDS: Final = {
    "ZERO": "0",
    "ONE": "1",
    "TWO": "2",
    "THREE": "3",
    "FOUR": "4",
    "FIVE": "5",
    "SIX": "6",
    "SEVEN": "7",
    "EIGHT": "8",
    "NINE": "9",
}

_WS_PATTERN: Final = re.compile(r"[\u00a0\u1680\u2000-\u200b\u202f\u205f\u3000]+")
_STYLED_PATTERN: Final = re.compile(r"[\U0001D000-\U0001DFFF\U0001E000-\U0001EFFF]")
_ENCODED_MIN_LEN: Final = 40
_LOW_LETTER_RATIO: Final = 0.1
_HIGH_DIGIT_RATIO: Final = 0.2


def fold(text: str) -> str:
    """Return the canonical normalized form of *text* used by every rule."""
    folded = text.casefold()
    out: list[str] = []
    for char in folded:
        if ord(char) in _MATH_BLOCK:
            out.append(_math_alphanumeric_base(char))
        elif char in _LOOKALIKES:
            out.append(_LOOKALIKES[char])
        else:
            out.append(char)
    result = unicodedata.normalize("NFKC", "".join(out))
    return _WS_PATTERN.sub(" ", result)


def has_math_stylization(text: str) -> bool:
    """True when *text* uses math-alphanumerics or stylized blocks.

    The marker is computed on the raw subject so it survives normalization.
    """
    return bool(_STYLED_PATTERN.search(text))


def is_encoded_body(text: str) -> bool:
    """True for bodies that are machine-generated hex/base64 noise.

    Encoded-bodies family (round-5 steering item 6f): the body carries
    little readable text, only hex fragments, checksum-looking digit runs,
    or pure symbol noise.
    """
    if len(text) < _ENCODED_MIN_LEN:
        return False
    letters = sum(1 for char in text if char.isalpha())
    digits = sum(1 for char in text if char.isdigit())
    if letters / len(text) < _LOW_LETTER_RATIO:
        return True
    return digits / len(text) > _HIGH_DIGIT_RATIO


def _math_alphanumeric_base(char: str) -> str:
    name = unicodedata.name(char, "")
    if not name.startswith("MATHEMATICAL "):
        return ""
    base = name.rsplit(" ", 1)[-1]
    if base in _DIGIT_WORDS:
        return _DIGIT_WORDS[base]
    if len(base) == 1 and base.isalpha():
        return base
    return ""
