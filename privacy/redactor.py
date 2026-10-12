"""Deterministic exact-offset redaction and safe payload serialization."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from core.document_model import DocumentBlock, DocumentResult
from privacy.pii_model import PIIFinding
from privacy.span_resolver import resolve_findings


PLACEHOLDER_NAMES = {
    "PERSON": "PERSON",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "EMPLOYEE_ID": "EMPLOYEE_ID",
    "GOVERNMENT_ID": "GOVERNMENT_ID",
    "BANK_ACCOUNT": "BANK_ACCOUNT",
    "DATE_OF_BIRTH": "DOB",
    "LOCATION": "LOCATION",
}


@dataclass(frozen=True, slots=True)
class RedactionRecord:
    finding_id: str
    block_id: str
    start_offset: int
    end_offset: int
    entity_type: str
    placeholder: str


@dataclass(slots=True)
class RedactionResult:
    document_id: str
    blocks: list[DocumentBlock] = field(default_factory=list)
    records: list[RedactionRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def redacted_count(self) -> int:
        return len(self.records)

    @property
    def succeeded(self) -> bool:
        return not self.errors


def redact_document(document: DocumentResult, findings: list[PIIFinding]) -> RedactionResult:
    """Replace validated spans without retaining any raw-value mapping."""

    output = RedactionResult(document.document_id)
    block_map = {block.block_id: block for block in document.blocks}
    if len(block_map) != len(document.blocks):
        output.errors.append("Document contains duplicate block identifiers.")
        return output

    for finding in findings:
        block = block_map.get(finding.block_id)
        if block is None:
            output.errors.append(f"Finding {finding.finding_id} references an unknown block.")
            continue
        if finding.start_offset < 0 or finding.end_offset > len(block.text) or finding.start_offset >= finding.end_offset:
            output.errors.append(f"Finding {finding.finding_id} has invalid offsets.")
        elif finding.original_block_reference.block_id != block.block_id or finding.original_block_reference.text != block.text:
            output.errors.append(f"Finding {finding.finding_id} contradicts its original block reference.")
        elif finding.entity_type not in PLACEHOLDER_NAMES:
            output.errors.append(f"Finding {finding.finding_id} has an unsupported entity type.")
    if output.errors:
        return output

    resolved = resolve_findings(findings)
    block_order = {block.block_id: index for index, block in enumerate(document.blocks)}
    ordered = sorted(resolved, key=lambda item: (block_order[item.block_id], item.start_offset, item.end_offset))
    counters: defaultdict[str, int] = defaultdict(int)
    per_block: defaultdict[str, list[RedactionRecord]] = defaultdict(list)
    for finding in ordered:
        counters[finding.entity_type] += 1
        placeholder = f"[{PLACEHOLDER_NAMES[finding.entity_type]}_{counters[finding.entity_type]}]"
        record = RedactionRecord(
            finding.finding_id, finding.block_id, finding.start_offset, finding.end_offset,
            finding.entity_type, placeholder,
        )
        output.records.append(record)
        per_block[finding.block_id].append(record)

    for block in document.blocks:
        text = block.text
        for record in sorted(per_block[block.block_id], key=lambda item: item.start_offset, reverse=True):
            text = text[:record.start_offset] + record.placeholder + text[record.end_offset:]
        output.blocks.append(DocumentBlock(
            block.block_id, block.block_type, text, block.source_location,
            block.extraction_status, {**block.metadata, "sanitized": True},
        ))
    return output


def serialize_sanitized(result: RedactionResult) -> str:
    """Serialize only sanitized text and non-sensitive numeric structure."""

    if not result.succeeded:
        raise ValueError("Cannot serialize a failed redaction.")
    lines: list[str] = []
    previous_boundary: tuple[str, int] | None = None
    for block in result.blocks:
        page = block.metadata.get("page")
        slide = block.metadata.get("slide")
        boundary = ("PAGE", page) if isinstance(page, int) else ("SLIDE", slide) if isinstance(slide, int) else None
        if boundary and boundary != previous_boundary:
            lines.append(f"\n--- {boundary[0]} {boundary[1]} ---")
            previous_boundary = boundary
        if block.block_type == "table_cell":
            table, row, column = (block.metadata.get(key) for key in ("table", "row", "column"))
            if all(isinstance(value, int) for value in (table, row, column)):
                lines.append(f"[TABLE {table} ROW {row} COLUMN {column}]")
        lines.append(block.text)
    return "\n".join(lines).strip()

