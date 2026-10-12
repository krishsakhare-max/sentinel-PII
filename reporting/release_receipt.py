"""Safe, explainable release receipts without raw PII."""

from __future__ import annotations

from core.security_gate import GateDecision


def build_release_receipt(decision: GateDecision) -> dict[str, str | int]:
    return {
        "Document": decision.document_id,
        "Extraction": decision.extraction_status,
        "PII detected": decision.detected_pii_count,
        "PII redacted": decision.redacted_pii_count,
        "Residual recognized PII": decision.residual_pii_count,
        "Payload verification": decision.verification_status,
        "Release decision": decision.decision,
        "Destination": "LOCAL MOCK AI",
        "Reason": " ".join(decision.reasons),
        "Timestamp": decision.timestamp,
    }

