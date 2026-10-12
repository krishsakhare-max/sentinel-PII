"""Local demonstration boundary accepting only gate-approved sanitized payloads."""

from __future__ import annotations

import hashlib

from core.security_gate import ApprovedPayload, GateDecision


def mock_ai_process(approved_payload: ApprovedPayload, release_decision: GateDecision) -> dict[str, str | int]:
    """Process verified sanitized text and retain safe metadata only."""

    if not isinstance(approved_payload, ApprovedPayload):
        raise PermissionError("The mock AI accepts only an ApprovedPayload from the security gate.")
    if release_decision.decision != "APPROVED" or release_decision.verification_status != "PASSED":
        raise PermissionError("The release decision is not approved and verified.")
    actual_hash = hashlib.sha256(approved_payload.text.encode("utf-8")).hexdigest()
    if actual_hash != approved_payload.payload_hash or actual_hash != release_decision.payload_hash:
        raise PermissionError("The approved payload was modified after verification.")
    if approved_payload.document_id != release_decision.document_id:
        raise PermissionError("The approved payload belongs to a different document.")
    if (not approved_payload.verification_id
            or approved_payload.verification_id != release_decision.verification_id):
        raise PermissionError("Verification metadata is missing or does not match the release decision.")
    return {
        "message": f"Sanitized document received. {len(approved_payload.text)} characters processed.",
        "document_id": approved_payload.document_id,
        "character_count": len(approved_payload.text),
    }
