"""Typed, export-safe models for explainable original-data exposure risk."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal


AssessmentStatus = Literal["AVAILABLE", "UNAVAILABLE"]
Priority = Literal["Critical", "High", "Standard"]


@dataclass(frozen=True, slots=True)
class RiskRecommendation:
    priority: Priority
    title: str
    action: str
    rationale: str


@dataclass(slots=True)
class RiskAssessment:
    document_id: str
    status: AssessmentStatus
    score: int | None = None
    risk_level: str = "Unavailable"
    maximum_sensitivity_weight: int | None = None
    distinct_pii_count: int | None = None
    linkage_indicator: bool | None = None
    calculation_explanation: str = ""
    category_counts: dict[str, int] = field(default_factory=dict)
    top_contributing_categories: list[str] = field(default_factory=list)
    assessment_warnings: list[str] = field(default_factory=list)


def export_risk_report(
    assessment: RiskAssessment,
    recommendations: list[RiskRecommendation],
    *,
    extraction_status: str,
    verification_status: str,
    release_decision: str,
) -> dict:
    """Build a report containing aggregate controls only—never raw findings."""

    return {
        "document_id": assessment.document_id,
        "assessment_status": assessment.status,
        "original_exposure": {
            "score": assessment.score,
            "risk_level": assessment.risk_level,
            "maximum_sensitivity_weight": assessment.maximum_sensitivity_weight,
            "distinct_pii_count": assessment.distinct_pii_count,
            "linkage_indicator": assessment.linkage_indicator,
            "calculation": assessment.calculation_explanation,
            "category_counts": dict(assessment.category_counts),
            "top_contributing_categories": list(assessment.top_contributing_categories),
            "warnings": list(assessment.assessment_warnings),
        },
        "security_controls": {
            "extraction_status": extraction_status,
            "verification_status": verification_status,
            "release_decision": release_decision,
        },
        "recommendations": [asdict(item) for item in recommendations],
    }
