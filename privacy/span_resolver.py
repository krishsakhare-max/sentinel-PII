"""Deterministic duplicate and overlap resolution for PII findings."""

from __future__ import annotations

from privacy.pii_model import PIIFinding


PRECEDENCE = {
    "GOVERNMENT_ID": 90,
    "BANK_ACCOUNT": 85,
    "EMPLOYEE_ID": 80,
    "EMAIL_ADDRESS": 75,
    "PHONE_NUMBER": 70,
    "DATE_OF_BIRTH": 65,
    "PERSON": 50,
    "ADDRESS": 45,
    "LOCATION": 40,
}


def _overlaps(first: PIIFinding, second: PIIFinding) -> bool:
    return first.block_id == second.block_id and first.start_offset < second.end_offset and second.start_offset < first.end_offset


def resolve_findings(findings: list[PIIFinding]) -> list[PIIFinding]:
    """Collapse duplicate/ambiguous spans while preserving distinct occurrences.

    Exact or overlapping candidates compete by entity precedence, recognizer
    score, span length, and method name. Non-overlapping occurrences always stay.
    """

    ranked = sorted(
        findings,
        key=lambda item: (
            -PRECEDENCE.get(item.entity_type, 0),
            -item.confidence_score,
            -(item.end_offset - item.start_offset),
            item.detection_method,
            item.block_id,
            item.start_offset,
        ),
    )
    kept: list[PIIFinding] = []
    for candidate in ranked:
        if any(_overlaps(candidate, existing) for existing in kept):
            continue
        kept.append(candidate)
    return sorted(kept, key=lambda item: (item.block_id, item.start_offset, item.end_offset, item.entity_type))

