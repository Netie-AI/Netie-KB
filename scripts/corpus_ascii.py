"""Laptop-ASCII policy for Netie KB corpus (R-0012)."""

from __future__ import annotations

# Characters agents paste from word processors; not on a US keyboard.
FORBIDDEN: dict[str, str] = {
    "\u2014": "em dash; use ` - ` or `--`",
    "\u2013": "en dash; use `-`",
    "\u2265": ">=; use `>=`",
    "\u2264": "<=; use `<=`",
    "\u2192": "arrow; use `->`",
    "\u2190": "arrow; use `<-`",
    "\u2026": "ellipsis; use `...`",
    "\u2018": "curly quote; use `'`",
    "\u2019": "curly quote; use `'`",
    "\u201c": "curly quote; use `\"`",
    "\u201d": "curly quote; use `\"`",
}


def corpus_ascii_errors(text: str, label: str) -> list[str]:
    errors: list[str] = []
    for index, char in enumerate(text):
        if char in FORBIDDEN:
            errors.append(f"{label}: forbidden {FORBIDDEN[char]} (U+{ord(char):04X}) at col {index + 1}")
    return errors


def check_corpus_text(text: str, label: str) -> list[str]:
    return corpus_ascii_errors(text, label)
