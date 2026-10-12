"""Single fail-closed orchestration path for document privacy analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from core.document_model import DocumentResult
from core.security_gate import GateDecision, evaluate_release
from core.validator import ValidationResult, validate_file
from extraction.extractor import extract_document
from extraction.ocr import OCRStatus
from privacy.detector import detect_pii
from privacy.pii_model import DetectionResult
from privacy.redactor import RedactionResult, redact_document, serialize_sanitized
from privacy.verifier import VerificationResult, verify_redaction


ProgressCallback = Callable[[int, int, str], None]
STAGE_COUNT = 6
STAGES = ("Validation", "Extraction", "Detection", "Redaction", "Verification", "Security gate")


@dataclass(slots=True)
class AnalysisResult:
    """All evidence produced by one immutable input and processing scope."""

    filename: str
    validation: ValidationResult
    document: DocumentResult | None = None
    detection: DetectionResult | None = None
    redaction: RedactionResult | None = None
    payload: str = ""
    verification: VerificationResult | None = None
    decision: GateDecision | None = None
    completed_stage: str = "Validation"
    errors: list[str] = field(default_factory=list)
    stage_statuses: dict[str, str] = field(
        default_factory=lambda: {stage: "Pending" for stage in STAGES}
    )

    @property
    def completed(self) -> bool:
        return self.decision is not None and not self.errors


def _progress(callback: ProgressCallback | None, stage: int, message: str) -> None:
    if callback:
        callback(stage, STAGE_COUNT, message)


def run_secure_analysis(
    data: bytes,
    filename: str,
    *,
    ocr_status: OCRStatus | None = None,
    selected_pages: list[int] | None = None,
    progress_callback: ProgressCallback | None = None,
    extraction_progress: Callable[[int, int], None] | None = None,
) -> AnalysisResult:
    """Run Validate → Extract → Detect → Redact → Verify → Gate once.

    Invalid input and stage failures stop the sequence. No result without a
    completed gate decision can be treated as releasable.
    """

    _progress(progress_callback, 0, "Validating file structure")
    validation = validate_file(data, filename)
    result = AnalysisResult(filename, validation)
    result.stage_statuses["Validation"] = "Processing"
    if not validation.is_valid:
        result.stage_statuses["Validation"] = "Failed"
        result.errors.append(validation.reason)
        return result
    result.stage_statuses["Validation"] = "Completed"

    current_stage = "Extraction"
    try:
        result.stage_statuses[current_stage] = "Processing"
        _progress(progress_callback, 1, "Extracting document content locally")
        result.document = extract_document(
            data, filename, ocr_status, selected_pages, extraction_progress
        )
        result.completed_stage = "Extraction"
        result.stage_statuses[current_stage] = "Completed"

        current_stage = "Detection"
        result.stage_statuses[current_stage] = "Processing"
        _progress(progress_callback, 2, "Detecting sensitive data")
        result.detection = detect_pii(result.document)
        result.completed_stage = "Detection"
        if result.detection.failed_blocks:
            result.stage_statuses[current_stage] = "Failed"
            result.errors.append("PII detection did not analyze every applicable block.")
            return result
        result.stage_statuses[current_stage] = "Completed"

        current_stage = "Redaction"
        result.stage_statuses[current_stage] = "Processing"
        _progress(progress_callback, 3, "Redacting exact source spans")
        result.redaction = redact_document(result.document, result.detection.findings)
        result.completed_stage = "Redaction"
        if not result.redaction.succeeded:
            result.stage_statuses[current_stage] = "Failed"
            result.errors.extend(result.redaction.errors)
            return result
        result.payload = serialize_sanitized(result.redaction)
        result.stage_statuses[current_stage] = "Completed"

        current_stage = "Verification"
        result.stage_statuses[current_stage] = "Processing"
        _progress(progress_callback, 4, "Verifying the sanitized payload")
        result.verification = verify_redaction(
            result.document,
            result.detection,
            result.redaction,
            result.payload,
            selected_pages_demo=selected_pages is not None,
        )
        result.completed_stage = "Verification"
        result.stage_statuses[current_stage] = "Completed"

        current_stage = "Security gate"
        result.stage_statuses[current_stage] = "Processing"
        _progress(progress_callback, 5, "Applying the fail-closed release gate")
        result.decision = evaluate_release(
            validation_succeeded=validation.is_valid,
            document=result.document,
            detection=result.detection,
            redaction=result.redaction,
            verification=result.verification,
            payload=result.payload,
            selected_pages_demo=selected_pages is not None,
        )
        result.completed_stage = "Gate"
        result.stage_statuses[current_stage] = (
            "Completed" if result.decision.decision == "APPROVED" else "Blocked"
        )
        _progress(progress_callback, 6, "Analysis complete")
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        result.stage_statuses[current_stage] = "Failed"
        result.errors.append(f"{current_stage} failed safely: {type(exc).__name__}.")
    return result
