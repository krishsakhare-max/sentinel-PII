"""Exact entity/span evaluation for synthetic PII ground truth."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from privacy.pii_model import PIIFinding


@dataclass(frozen=True, slots=True)
class ExpectedFinding:
    entity_type: str
    block_id: str
    start_offset: int
    end_offset: int


@dataclass(slots=True)
class EvaluationMetrics:
    expected: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    per_entity_recall: dict[str, float] = field(default_factory=dict)
    missed: list[ExpectedFinding] = field(default_factory=list)


def evaluate_findings(predicted: list[PIIFinding], expected: list[ExpectedFinding]) -> EvaluationMetrics:
    """Match on entity type, block ID, and exact original-text boundaries."""

    predicted_keys = Counter((p.entity_type, p.block_id, p.start_offset, p.end_offset) for p in predicted)
    expected_keys = Counter((e.entity_type, e.block_id, e.start_offset, e.end_offset) for e in expected)
    true_positives = sum((predicted_keys & expected_keys).values())
    false_positives = sum((predicted_keys - expected_keys).values())
    false_negatives = sum((expected_keys - predicted_keys).values())
    precision = true_positives / (true_positives + false_positives) if true_positives + false_positives else 1.0
    recall = true_positives / (true_positives + false_negatives) if true_positives + false_negatives else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    entity_totals = Counter(item.entity_type for item in expected)
    entity_hits = Counter()
    missed: list[ExpectedFinding] = []
    available = predicted_keys.copy()
    for item in expected:
        key = (item.entity_type, item.block_id, item.start_offset, item.end_offset)
        if available[key]:
            entity_hits[item.entity_type] += 1
            available[key] -= 1
        else:
            missed.append(item)
    return EvaluationMetrics(
        expected=len(expected), true_positives=true_positives,
        false_positives=false_positives, false_negatives=false_negatives,
        precision=precision, recall=recall, f1=f1,
        per_entity_recall={entity: entity_hits[entity] / total for entity, total in sorted(entity_totals.items())},
        missed=missed,
    )

