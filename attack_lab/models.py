"""Typed, synthetic-only models for Privacy Attack Lab execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Outcome = Literal["SUCCESS", "PARTIAL", "FAILED", "PASS", "FAIL", "ERROR", "INCONCLUSIVE"]


@dataclass(frozen=True, slots=True)
class GroundTruthEntity:
    entity_type: str
    value: str
    source_context: str
    composite_parts: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AttackScenario:
    scenario_id: str
    name: str
    objective: str
    document_format: str
    difficulty: str
    filename: str
    data: bytes
    ground_truth: tuple[GroundTruthEntity, ...]
    safe_content: tuple[str, ...]
    expected_extraction: str
    security_constraints: tuple[str, ...]
    simulated_extraction_failure: bool = False


@dataclass(slots=True)
class AttackResult:
    scenario_id: str
    scenario_name: str
    document_format: str
    detection_outcome: Outcome = "INCONCLUSIVE"
    containment_outcome: Outcome = "INCONCLUSIVE"
    usability_outcome: Outcome = "INCONCLUSIVE"
    release_decision: str = "PENDING"
    expected_entity_count: int = 0
    detected_ground_truth_count: int = 0
    missed_entity_types: list[str] = field(default_factory=list)
    false_positive_count: int = 0
    redacted_ground_truth_count: int = 0
    approved_payload_leakage: bool = False
    over_redaction_count: int = 0
    extraction_status: str = "NOT_RUN"
    ocr_average_confidence: float | None = None
    runtime_seconds: float = 0.0
    error_category: str | None = None
    verification_reasons: list[str] = field(default_factory=list)
    lessons: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AttackSummary:
    scenarios_executed: int
    detection_successes: int
    containment_passes: int
    containment_failures: int
    inconclusive_tests: int
    errors: int
