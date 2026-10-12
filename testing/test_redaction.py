"""Deterministic redaction and independent verification tests."""

from dataclasses import replace

import pytest

from core.document_model import DocumentBlock, DocumentResult
from privacy.pii_model import DetectionResult, PIIFinding
from privacy.redactor import redact_document, serialize_sanitized
from privacy.verifier import verify_redaction


def finding(block: DocumentBlock, entity: str, value: str, occurrence: int = 0, identity: str = "f") -> PIIFinding:
    start = -1
    cursor = 0
    for _ in range(occurrence + 1):
        start = block.text.index(value, cursor)
        cursor = start + len(value)
    return PIIFinding(identity, entity, start, start + len(value), block.block_id, block.metadata.get("page"),
                      block.source_location, "test", .9, block, "masked")


def document_with(texts: list[str], *, complete: bool = True) -> DocumentResult:
    blocks = [DocumentBlock(f"b{i}", "paragraph", text, f"page {i}", "native", {"page": i})
              for i, text in enumerate(texts, start=1)]
    return DocumentResult("doc-1", "synthetic.pdf", "PDF", blocks, complete,
                          [] if complete else ["Synthetic extraction warning."])


def detection_for(document: DocumentResult, findings: list[PIIFinding]) -> DetectionResult:
    return DetectionResult(document.document_id, findings, [], document.extraction_complete,
                           list(document.extraction_warnings), len(document.blocks), [])


def test_single_entity_replacement_and_nonsensitive_preservation() -> None:
    document = document_with(["Contact Emma Parker today."])
    result = redact_document(document, [finding(document.blocks[0], "PERSON", "Emma Parker")])
    assert result.blocks[0].text == "Contact [PERSON_1] today."
    assert result.redacted_count == 1


def test_multiple_entities_right_to_left() -> None:
    document = document_with(["Emma Parker uses emma@example.com and +1 202-555-0101."])
    block = document.blocks[0]
    findings = [finding(block, "PERSON", "Emma Parker", identity="p"),
                finding(block, "EMAIL_ADDRESS", "emma@example.com", identity="e"),
                finding(block, "PHONE_NUMBER", "+1 202-555-0101", identity="t")]
    result = redact_document(document, findings)
    assert result.blocks[0].text == "[PERSON_1] uses [EMAIL_1] and [PHONE_1]."


def test_repeated_values_across_blocks_are_numbered_by_reading_order() -> None:
    document = document_with(["Emma Parker", "Emma Parker"])
    findings = [finding(document.blocks[0], "PERSON", "Emma Parker", identity="1"),
                finding(document.blocks[1], "PERSON", "Emma Parker", identity="2")]
    result = redact_document(document, findings)
    assert [block.text for block in result.blocks] == ["[PERSON_1]", "[PERSON_2]"]


def test_overlapping_findings_use_deterministic_precedence() -> None:
    document = document_with(["user@example.com"])
    block = document.blocks[0]
    broad = PIIFinding("p", "PERSON", 0, len(block.text), block.block_id, 1, block.source_location,
                       "test", .9, block, "masked")
    email = finding(block, "EMAIL_ADDRESS", "user@example.com", identity="e")
    result = redact_document(document, [broad, email])
    assert result.blocks[0].text == "[EMAIL_1]"
    assert result.redacted_count == 1


@pytest.mark.parametrize("start,end", [(-1, 3), (3, 3), (0, 100)])
def test_invalid_offsets_fail_closed(start: int, end: int) -> None:
    document = document_with(["Emma Parker"]); block = document.blocks[0]
    bad = PIIFinding("bad", "PERSON", start, end, block.block_id, 1, block.source_location,
                     "test", .9, block, "masked")
    assert not redact_document(document, [bad]).succeeded


def test_unknown_block_and_contradictory_reference_fail() -> None:
    document = document_with(["Emma Parker"]); block = document.blocks[0]
    unknown = replace(finding(block, "PERSON", "Emma Parker"), block_id="missing")
    assert not redact_document(document, [unknown]).succeeded
    other = DocumentBlock(block.block_id, block.block_type, "Different text", block.source_location, "native")
    contradiction = replace(finding(block, "PERSON", "Emma Parker"), original_block_reference=other)
    assert not redact_document(document, [contradiction]).succeeded


def test_table_metadata_and_empty_findings_are_preserved() -> None:
    block = DocumentBlock("cell", "table_cell", "Public value", "table 1, row 2, column 3", "native",
                          {"table": 1, "row": 2, "column": 3})
    document = DocumentResult("doc", "test.docx", "DOCX", [block], True, [])
    result = redact_document(document, [])
    assert result.blocks[0].text == block.text
    assert all(result.blocks[0].metadata[key] == value for key, value in block.metadata.items())
    assert "[TABLE 1 ROW 2 COLUMN 3]" in serialize_sanitized(result)


def test_verification_passes_complete_exact_redaction() -> None:
    document = document_with(["Email: emma@example.com"]); item = finding(document.blocks[0], "EMAIL_ADDRESS", "emma@example.com")
    detection = detection_for(document, [item]); redaction = redact_document(document, [item]); payload = serialize_sanitized(redaction)
    verified = verify_redaction(document, detection, redaction, payload)
    assert verified.passed
    assert not verified.residual_findings


def test_verification_detects_residual_pii_and_payload_tampering() -> None:
    document = document_with(["Emails: first@example.com and second@example.com"])
    selected = finding(document.blocks[0], "EMAIL_ADDRESS", "first@example.com")
    detection = detection_for(document, [selected]); redaction = redact_document(document, [selected])
    verified = verify_redaction(document, detection, redaction, serialize_sanitized(redaction))
    assert not verified.passed
    assert verified.residual_findings
    tampered = verify_redaction(document, detection, redaction, serialize_sanitized(redaction) + " first@example.com")
    assert not tampered.checks["payload_matches_serializer"]
    assert not tampered.checks["payload_has_no_known_raw_spans"]


def test_verification_detects_missing_blocks_and_detector_coverage() -> None:
    document = document_with(["Public content"]); detection = detection_for(document, [])
    redaction = redact_document(document, []); redaction.blocks.clear()
    verified = verify_redaction(document, detection, redaction, "")
    assert not verified.checks["block_structure"]
    redaction = redact_document(document, []); detection.analyzed_blocks = 0; detection.failed_blocks = ["b1"]
    verified = verify_redaction(document, detection, redaction, serialize_sanitized(redaction))
    assert not verified.checks["detection_coverage"]


def test_incomplete_and_selected_page_documents_fail_verification() -> None:
    document = document_with(["Public content"], complete=False); detection = detection_for(document, [])
    redaction = redact_document(document, [])
    verified = verify_redaction(document, detection, redaction, serialize_sanitized(redaction), selected_pages_demo=True)
    assert not verified.checks["extraction_complete"]
    assert not verified.checks["full_document"]


def test_failed_rescan_is_a_verification_failure(monkeypatch) -> None:
    import privacy.verifier as module
    document = document_with(["Public content"]); detection = detection_for(document, [])
    redaction = redact_document(document, [])
    failed = DetectionResult(document.document_id, [], ["failed"], True, [], 0, ["b1"])
    monkeypatch.setattr(module, "detect_pii", lambda _: failed)
    verified = module.verify_redaction(document, detection, redaction, serialize_sanitized(redaction))
    assert not verified.checks["residual_scan_completed"]

