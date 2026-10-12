"""Independent redaction, coverage, residual-PII, and payload verification."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re

from core.document_model import DocumentResult
from privacy.detector import detect_pii
from privacy.pii_model import DetectionResult, PIIFinding
from privacy.redactor import RedactionResult, serialize_sanitized


PLACEHOLDER_PATTERN = re.compile(
    r"\[(?:PERSON|EMAIL|PHONE|EMPLOYEE_ID|GOVERNMENT_ID|BANK_ACCOUNT|DOB|LOCATION)_\d+\]"
)


@dataclass(slots=True)
class VerificationResult:
    passed: bool = False
    checks: dict[str, bool] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    residual_findings: list[PIIFinding] = field(default_factory=list)
    verification_id: str = ""
    payload_hash: str = ""


def _inside_placeholder(text: str, finding: PIIFinding) -> bool:
    return any(match.start() <= finding.start_offset and finding.end_offset <= match.end()
               for match in PLACEHOLDER_PATTERN.finditer(text))


def _known_value_remains(payload: str, finding: PIIFinding) -> bool:
    """Check known raw values without substring false positives."""

    raw = finding.original_block_reference.text[finding.start_offset:finding.end_offset].strip()
    if len(raw) < 4:
        return False
    return re.search(rf"(?<!\w){re.escape(raw)}(?!\w)", payload, re.IGNORECASE) is not None


def verify_redaction(
    original: DocumentResult,
    detection: DetectionResult,
    redaction: RedactionResult,
    payload: str,
    *,
    selected_pages_demo: bool = False,
) -> VerificationResult:
    """Fail closed unless structure, replacements, coverage, rescan, and payload pass."""

    result = VerificationResult()
    result.payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    result.verification_id = hashlib.sha256(
        f"{original.document_id}:{result.payload_hash}".encode()
    ).hexdigest()[:20]

    nonempty_count = sum(bool(block.text.strip()) for block in original.blocks)
    result.checks["extraction_complete"] = original.extraction_complete and not original.extraction_warnings
    result.checks["full_document"] = not selected_pages_demo and not any(
        "Selected Pages Demo" in warning for warning in original.extraction_warnings
    )
    result.checks["detection_coverage"] = (
        not detection.failed_blocks and detection.analyzed_blocks == nonempty_count
    )
    result.checks["redaction_succeeded"] = redaction.succeeded
    result.checks["all_findings_redacted"] = redaction.redacted_count == len(detection.findings)

    original_ids = [block.block_id for block in original.blocks]
    sanitized_ids = [block.block_id for block in redaction.blocks]
    result.checks["block_structure"] = original_ids == sanitized_ids and len(original.blocks) == len(redaction.blocks)
    structure_preserved = result.checks["block_structure"] and all(
        before.block_type == after.block_type
        and before.source_location == after.source_location
        and all(after.metadata.get(key) == value for key, value in before.metadata.items())
        for before, after in zip(original.blocks, redaction.blocks)
    )
    result.checks["metadata_preserved"] = structure_preserved

    records_by_block: dict[str, list] = {}
    for record in redaction.records:
        records_by_block.setdefault(record.block_id, []).append(record)
    content_valid = result.checks["block_structure"]
    if content_valid:
        for before, after in zip(original.blocks, redaction.blocks):
            expected = before.text
            for record in sorted(records_by_block.get(before.block_id, []), key=lambda item: item.start_offset, reverse=True):
                expected = expected[:record.start_offset] + record.placeholder + expected[record.end_offset:]
            if after.text != expected:
                content_valid = False
                break
    result.checks["content_integrity"] = content_valid

    try:
        expected_payload = serialize_sanitized(redaction)
        result.checks["payload_matches_serializer"] = payload == expected_payload
    except (ValueError, TypeError):
        result.checks["payload_matches_serializer"] = False

    leakage_free = True
    for finding in detection.findings:
        # Very short values (for example a two-letter location) are not safe
        # global substring indicators because they occur inside ordinary words.
        # Exact source-span replacement is independently proven above.
        if _known_value_remains(payload, finding):
            leakage_free = False
            break
    result.checks["payload_has_no_known_raw_spans"] = leakage_free

    if redaction.succeeded and redaction.blocks:
        sanitized_document = DocumentResult(
            original.document_id, "sanitized", original.file_type,
            redaction.blocks, True, [],
        )
        residual = detect_pii(sanitized_document)
        result.residual_findings = [
            finding for finding in residual.findings
            if not _inside_placeholder(finding.original_block_reference.text, finding)
        ]
        detector_failed = bool(residual.failed_blocks) or residual.analyzed_blocks != sum(
            bool(block.text.strip()) for block in redaction.blocks
        )
        result.checks["residual_scan_completed"] = not detector_failed
        result.checks["no_residual_pii"] = not result.residual_findings
        if detector_failed:
            result.errors.append("Residual PII scan did not analyze every sanitized block.")
    else:
        result.checks["residual_scan_completed"] = False
        result.checks["no_residual_pii"] = False

    for name, passed in result.checks.items():
        if not passed:
            result.errors.append(name.replace("_", " ").capitalize() + " failed.")
    result.passed = all(result.checks.values()) and not result.errors
    return result
