"""Small, deterministic helpers for measuring extraction against ground truth."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class TextQualityMetrics:
    token_precision: float
    token_recall: float
    exact_normalized_match: bool


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.casefold())


def measure_text_quality(expected: str, actual: str) -> TextQualityMetrics:
    """Measure case-insensitive token overlap without fuzzy or invented matches."""

    expected_tokens = Counter(_tokens(expected))
    actual_tokens = Counter(_tokens(actual))
    matches = sum((expected_tokens & actual_tokens).values())
    expected_count = sum(expected_tokens.values())
    actual_count = sum(actual_tokens.values())
    precision = matches / actual_count if actual_count else 1.0 if not expected_count else 0.0
    recall = matches / expected_count if expected_count else 1.0
    return TextQualityMetrics(
        token_precision=precision,
        token_recall=recall,
        exact_normalized_match=_tokens(expected) == _tokens(actual),
    )

