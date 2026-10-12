"""Deterministic recommendations derived only from observed processing evidence."""

from __future__ import annotations

from core.document_model import DocumentResult
from core.security_gate import GateDecision
from intelligence.risk_model import RiskAssessment, RiskRecommendation
from privacy.verifier import VerificationResult


CATEGORY_RULES = {
    "GOVERNMENT_ID": ("Critical", "Protect government identifiers",
        "Redact government identifiers, restrict original-record access, and require additional approval before external sharing."),
    "BANK_ACCOUNT": ("Critical", "Protect financial identifiers",
        "Mask financial identifiers and restrict access to the original file."),
    "DATE_OF_BIRTH": ("High", "Minimize birth-date exposure",
        "Remove birth dates unless an authorized business purpose requires them."),
    "EMPLOYEE_ID": ("High", "Protect workforce identifiers",
        "Redact employee identifiers and limit original-file access to authorized personnel."),
    "PHONE_NUMBER": ("High", "Protect direct contact data",
        "Redact phone numbers while preserving nonsensitive operational context."),
    "PERSON": ("Standard", "Minimize direct identifiers",
        "Redact personal names while preserving nonsensitive operational context."),
    "EMAIL_ADDRESS": ("Standard", "Protect email addresses",
        "Redact email addresses before content is provided to an AI system."),
    "LOCATION": ("Standard", "Review location context",
        "Review location findings and redact those that identify a private or sensitive address."),
}
PRIORITY_ORDER = {"Critical": 0, "High": 1, "Standard": 2}


def build_recommendations(
    assessment: RiskAssessment,
    document: DocumentResult | None,
    verification: VerificationResult | None,
    decision: GateDecision | None,
) -> list[RiskRecommendation]:
    recommendations: list[RiskRecommendation] = []
    categories = sorted(
        assessment.category_counts,
        key=lambda category: (PRIORITY_ORDER[CATEGORY_RULES[category][0]],
                              -assessment.category_counts[category], category),
    )
    for category in categories:
        priority, title, action = CATEGORY_RULES[category]
        recommendations.append(RiskRecommendation(
            priority, title, action,
            f"Triggered by {assessment.category_counts[category]} detected {category} occurrence(s).",
        ))
    if document and (not document.extraction_complete or document.extraction_warnings):
        recommendations.append(RiskRecommendation(
            "Critical", "Resolve incomplete extraction",
            "Keep downstream AI processing blocked and manually review every unresolved element.",
            "Extraction is PARTIAL or contains unresolved warnings.",
        ))
    if verification and verification.residual_findings:
        recommendations.append(RiskRecommendation(
            "Critical", "Resolve residual sensitive data",
            "Keep the document blocked and investigate each remaining sensitive span.",
            f"Verification found {len(verification.residual_findings)} residual occurrence(s).",
        ))
    if decision and decision.decision == "APPROVED" and decision.verification_status == "PASSED":
        recommendations.append(RiskRecommendation(
            "Standard", "Use only the verified payload",
            "Permit only the gate-approved sanitized payload to the local mock AI endpoint.",
            "Verification passed and the security gate approved this exact payload.",
        ))
    elif decision and decision.decision == "BLOCKED":
        recommendations.append(RiskRecommendation(
            "High", "Maintain the release block",
            "Review the stated gate failures; do not send the candidate payload to AI.",
            "The fail-closed security gate denied release.",
        ))
    return sorted(recommendations, key=lambda item: (PRIORITY_ORDER[item.priority], item.title))
