"""Fail-closed gate, mock boundary, receipt, and cross-format workflow tests."""

from io import BytesIO

import fitz
import pytest
from docx import Document
from pptx import Presentation
from pptx.util import Inches

from core.document_model import DocumentResult
from core.mock_ai import mock_ai_process
from core.security_gate import evaluate_release
from core.validator import validate_file
from extraction.extractor import extract_document
from privacy.detector import detect_pii
from privacy.redactor import redact_document, serialize_sanitized
from privacy.verifier import verify_redaction
from reporting.release_receipt import build_release_receipt


def run_pipeline(data: bytes, filename: str, *, selected_pages=None):
    validation = validate_file(data, filename)
    document = extract_document(data, filename, selected_pages=selected_pages)
    detection = detect_pii(document)
    redaction = redact_document(document, detection.findings)
    payload = serialize_sanitized(redaction)
    verification = verify_redaction(document, detection, redaction, payload,
                                    selected_pages_demo=selected_pages is not None)
    decision = evaluate_release(
        validation_succeeded=validation.is_valid, document=document, detection=detection,
        redaction=redaction, verification=verification, payload=payload,
        selected_pages_demo=selected_pages is not None,
    )
    return document, detection, redaction, verification, decision


def make_pdf() -> bytes:
    pdf = fitz.open(); page = pdf.new_page()
    page.insert_text((50, 80), "Name: Emma Parker; email emma.parker@example.com; sufficient synthetic text.")
    return pdf.tobytes()


def make_docx() -> bytes:
    document = Document(); document.add_paragraph("Employee ID: EMP-2048 and phone +1 202-555-0102")
    output = BytesIO(); document.save(output); return output.getvalue()


def make_pptx() -> bytes:
    presentation = Presentation(); slide = presentation.slides.add_slide(presentation.slide_layouts[6])
    slide.shapes.add_textbox(Inches(1), Inches(1), Inches(6), Inches(1)).text = "Contact: Anne-Marie O'Neil; email anne.oneil@example.com"
    output = BytesIO(); presentation.save(output); return output.getvalue()


@pytest.mark.parametrize("factory,filename", [(make_pdf, "test.pdf"), (make_docx, "test.docx"), (make_pptx, "test.pptx")])
def test_complete_cross_format_pipeline_is_approved(factory, filename) -> None:
    _, detection, redaction, verification, decision = run_pipeline(factory(), filename)
    assert detection.findings
    assert redaction.redacted_count == len(detection.findings)
    assert verification.passed
    assert decision.decision == "APPROVED"
    response = mock_ai_process(decision.approved_payload, decision)
    assert response["character_count"] > 0


def test_partial_selected_pages_and_unresolved_warnings_are_blocked() -> None:
    document, _, _, _, decision = run_pipeline(make_pdf(), "test.pdf", selected_pages=[1])
    assert not document.extraction_complete
    assert decision.decision == "BLOCKED"
    assert any("Selected-page" in reason for reason in decision.reasons)


def test_invalid_document_is_blocked() -> None:
    document = DocumentResult("bad", "bad.pdf", "UNKNOWN")
    from privacy.pii_model import DetectionResult
    from privacy.redactor import RedactionResult
    from privacy.verifier import VerificationResult
    decision = evaluate_release(validation_succeeded=False, document=document,
        detection=DetectionResult("bad"), redaction=RedactionResult("bad"),
        verification=VerificationResult(), payload="")
    assert decision.decision == "BLOCKED"


def test_redaction_failure_residual_and_payload_tampering_block() -> None:
    document, detection, redaction, verification, _ = run_pipeline(make_pdf(), "test.pdf")
    redaction.errors.append("synthetic failure")
    decision = evaluate_release(validation_succeeded=True, document=document, detection=detection,
        redaction=redaction, verification=verification, payload="tampered")
    assert decision.decision == "BLOCKED"
    assert any("Redaction failed" in reason for reason in decision.reasons)


def test_mock_endpoint_rejects_blocked_raw_and_missing_verification() -> None:
    _, _, _, _, approved = run_pipeline(make_pdf(), "test.pdf")
    with pytest.raises(PermissionError):
        mock_ai_process("raw document", approved)
    approved.decision = "BLOCKED"
    with pytest.raises(PermissionError):
        mock_ai_process(approved.approved_payload, approved)


def test_release_receipt_contains_only_safe_counts_and_status() -> None:
    _, _, _, _, decision = run_pipeline(make_pdf(), "test.pdf")
    receipt = build_release_receipt(decision)
    assert receipt["Release decision"] == "APPROVED"
    assert receipt["Destination"] == "LOCAL MOCK AI"
    assert "example.com" not in str(receipt)

