"""Explicit fail-closed release decision for sanitized payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib

from core.document_model import DocumentResult
from privacy.pii_model import DetectionResult
from privacy.redactor import RedactionResult
from privacy.verifier import VerificationResult


@dataclass(frozen=True, slots=True)
class ApprovedPayload:
    text: str
    document_id: str
    payload_hash: str
    verification_id: str


@dataclass(slots=True)
class GateDecision:
    decision: str
    reasons: list[str]
    verification_status: str
    extraction_status: str
    detected_pii_count: int
    redacted_pii_count: int
    residual_pii_count: int
    timestamp: str
    document_id: str
    payload_hash: str
    verification_id: str = ""
    approved_payload: ApprovedPayload | None = None


def evaluate_release(
    *,
    validation_succeeded: bool,
    document: DocumentResult,
    detection: DetectionResult,
    redaction: RedactionResult,
    verification: VerificationResult,
    payload: str,
    selected_pages_demo: bool = False,
) -> GateDecision:
    """Approve only when every independent prerequisite is satisfied."""

    reasons: list[str] = []
    if not validation_succeeded:
        reasons.append("Original file validation did not succeed.")
    if selected_pages_demo:
        reasons.append("Selected-page demonstrations cannot release the full document.")
    if not document.extraction_complete or document.extraction_warnings:
        reasons.append("Document extraction is incomplete or has unresolved warnings.")
    nonempty = sum(bool(block.text.strip()) for block in document.blocks)
    if detection.failed_blocks or detection.analyzed_blocks != nonempty:
        reasons.append("PII analysis did not complete for every applicable block.")
    if not redaction.succeeded:
        reasons.append("Redaction failed validation.")
    if redaction.redacted_count != len(detection.findings):
        reasons.append("Not every detected PII occurrence was redacted.")
    if not verification.passed:
        reasons.append("Independent payload verification failed.")
    if verification.residual_findings:
        reasons.append("Residual recognized PII remains in the sanitized payload.")
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if verification.payload_hash != payload_hash:
        reasons.append("Payload content does not match the verified payload.")

    decision = "BLOCKED" if reasons else "APPROVED"
    approved = None
    if decision == "APPROVED":
        approved = ApprovedPayload(payload, document.document_id, payload_hash, verification.verification_id)
        reasons.append("All required validation, coverage, redaction, residual-scan, and payload checks passed.")
    return GateDecision(
        decision=decision,
        reasons=reasons,
        verification_status="PASSED" if verification.passed else "FAILED",
        extraction_status="COMPLETE" if document.extraction_complete and not document.extraction_warnings else "PARTIAL",
        detected_pii_count=len(detection.findings),
        redacted_pii_count=redaction.redacted_count,
        residual_pii_count=len(verification.residual_findings),
        timestamp=datetime.now(timezone.utc).isoformat(),
        document_id=document.document_id,
        payload_hash=payload_hash,
        verification_id=verification.verification_id,
        approved_payload=approved,
    )
