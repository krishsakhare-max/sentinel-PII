"""Normalized, source-traceable PII detection results."""

from __future__ import annotations

from dataclasses import dataclass, field

from core.document_model import DocumentBlock


@dataclass(frozen=True, slots=True)
class PIIFinding:
    finding_id: str
    entity_type: str
    start_offset: int
    end_offset: int
    block_id: str
    source_page_or_slide: int | None
    source_location: str
    detection_method: str
    confidence_score: float
    original_block_reference: DocumentBlock
    masked_preview: str


@dataclass(slots=True)
class DetectionResult:
    document_id: str
    findings: list[PIIFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    extraction_complete: bool = False
    extraction_warnings: list[str] = field(default_factory=list)
    analyzed_blocks: int = 0
    failed_blocks: list[str] = field(default_factory=list)
