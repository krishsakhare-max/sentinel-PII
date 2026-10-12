"""Targeted Phase 8 regressions for verified release-candidate gaps."""

from dataclasses import replace

import fitz
import pytest

from core.document_model import DocumentBlock, DocumentResult
from core.frontend_state import analysis_cache_key, escape_display
from core.mock_ai import mock_ai_process
from core.pipeline import run_secure_analysis
from privacy.detector import detect_pii
from privacy.redactor import redact_document, serialize_sanitized


def _approved_analysis():
    pdf = fitz.open()
    page = pdf.new_page()
    page.insert_text((50, 80), "Email: audit.person@example.com")
    data = pdf.tobytes()
    pdf.close()
    analysis = run_secure_analysis(data, "audit.pdf")
    assert analysis.decision.decision == "APPROVED"
    return analysis


def test_mock_ai_binds_payload_to_document_and_verification_decision() -> None:
    analysis = _approved_analysis()
    approved = analysis.decision.approved_payload
    assert mock_ai_process(approved, analysis.decision)["character_count"] > 0
    with pytest.raises(PermissionError):
        mock_ai_process(replace(approved, document_id="different-document"), analysis.decision)
    with pytest.raises(PermissionError):
        mock_ai_process(replace(approved, verification_id="forged-verification"), analysis.decision)


def test_cache_identity_uses_full_digest_and_scope() -> None:
    full = analysis_cache_key(b"document")
    selected = analysis_cache_key(b"document", [1, 2])
    digest, scope = full.split(":", 1)
    assert len(digest) == 64
    assert scope == "full"
    assert full != selected


def test_untrusted_filename_html_is_escaped() -> None:
    rendered = escape_display('<img src=x onerror="alert(1)">.pdf')
    assert "<img" not in rendered
    assert "&lt;img" in rendered
    assert "&quot;" in rendered


def test_untrusted_metadata_never_enters_serialized_payload() -> None:
    block = DocumentBlock(
        "b", "paragraph", "Nonsensitive operational context", "paragraph 1", "native",
        {"page": 1, "unsafe_note": "metadata.secret@example.com"},
    )
    document = DocumentResult("metadata", "metadata.pdf", "PDF", [block], True, [])
    payload = serialize_sanitized(redact_document(document, []))
    assert "Nonsensitive operational context" in payload
    assert "metadata.secret@example.com" not in payload


def test_unicode_case_variant_repeated_name_preserves_offsets() -> None:
    blocks = [
        DocumentBlock("a", "paragraph", "Name: Élodie Martin", "paragraph 1", "native", {}),
        DocumentBlock("b", "paragraph", "ÉLODIE MARTIN approved the control", "paragraph 2", "native", {}),
    ]
    document = DocumentResult("unicode", "unicode.docx", "DOCX", blocks, True, [])
    detection = detect_pii(document)
    people = [item for item in detection.findings if item.entity_type == "PERSON"]
    assert {item.block_id for item in people} == {"a", "b"}
    for item in people:
        assert item.original_block_reference.text[item.start_offset:item.end_offset].casefold() == "élodie martin"
