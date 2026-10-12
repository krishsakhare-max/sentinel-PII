"""Explainable potential-exposure scoring using documented project assumptions."""

from __future__ import annotations

from collections import Counter, defaultdict
import re

from core.document_model import DocumentResult
from privacy.pii_model import DetectionResult, PIIFinding
from intelligence.risk_model import RiskAssessment


# Project assumptions for the competition prototype—not Cadence policy ratings.
SENSITIVITY_WEIGHTS = {
    "PERSON": 2,
    "EMAIL_ADDRESS": 2,
    "PHONE_NUMBER": 3,
    "EMPLOYEE_ID": 3,
    "GOVERNMENT_ID": 5,
    "BANK_ACCOUNT": 5,
    "DATE_OF_BIRTH": 4,
    "LOCATION": 2,
}

RECORD_LABELS = {
    "PERSON": ("name", "employee", "contact"),
    "EMAIL_ADDRESS": ("email", "e-mail"),
    "PHONE_NUMBER": ("phone", "mobile", "telephone"),
    "EMPLOYEE_ID": ("employee id", "employee number", "staff id"),
    "GOVERNMENT_ID": ("government id", "ssn", "tax id"),
    "BANK_ACCOUNT": ("bank account", "account number", "iban"),
    "DATE_OF_BIRTH": ("date of birth", "birth date", "dob"),
    "LOCATION": ("address", "location"),
}
LINKAGE_ANCHORS = {
    "EMAIL_ADDRESS", "PHONE_NUMBER", "EMPLOYEE_ID", "GOVERNMENT_ID",
    "BANK_ACCOUNT", "DATE_OF_BIRTH",
}


def _raw_value(finding: PIIFinding) -> str:
    return finding.original_block_reference.text[finding.start_offset:finding.end_offset]


def _normalize(finding: PIIFinding) -> str:
    value = " ".join(_raw_value(finding).split()).casefold()
    if finding.entity_type == "PHONE_NUMBER":
        return re.sub(r"\D", "", value)
    if finding.entity_type in {"EMPLOYEE_ID", "GOVERNMENT_ID", "BANK_ACCOUNT"}:
        return re.sub(r"[^a-z0-9]", "", value)
    return value.strip(" .,;:")


def _has_record_linkage(findings: list[PIIFinding]) -> bool:
    """Link only structured rows or explicitly labeled records, never pages."""

    table_rows: dict[tuple[int | None, int | None, int, int], set[str]] = defaultdict(set)
    by_block: dict[str, list[PIIFinding]] = defaultdict(list)
    for finding in findings:
        block = finding.original_block_reference
        table, row = block.metadata.get("table"), block.metadata.get("row")
        if block.block_type == "table_cell" and isinstance(table, int) and isinstance(row, int):
            table_rows[(block.metadata.get("page"), block.metadata.get("slide"), table, row)].add(
                finding.entity_type
            )
        by_block[finding.block_id].append(finding)
    if any(len(categories) >= 2 and bool(categories & LINKAGE_ANCHORS)
           for categories in table_rows.values()):
        return True

    for block_findings in by_block.values():
        categories = {finding.entity_type for finding in block_findings}
        if len(categories) < 2:
            continue
        text = block_findings[0].original_block_reference.text.casefold()
        labeled = {
            category for category in categories
            if any(re.search(rf"\b{re.escape(label)}\s*[:\-]", text)
                   for label in RECORD_LABELS[category])
        }
        if len(labeled) >= 2:
            return True
    return False


def _risk_level(score: int) -> str:
    if score == 0:
        return "No PII detected — detection does not guarantee absence."
    if score <= 29:
        return "Low"
    if score <= 49:
        return "Moderate"
    if score <= 74:
        return "High"
    return "Critical"


def assess_risk(document: DocumentResult | None, detection: DetectionResult | None) -> RiskAssessment:
    """Assess original exposure without influencing verification or release."""

    document_id = document.document_id if document else detection.document_id if detection else "unavailable"
    if document is None or detection is None:
        return RiskAssessment(document_id, "UNAVAILABLE", assessment_warnings=[
            "Risk assessment requires both extraction and detection results."
        ])
    if document.document_id != detection.document_id:
        return RiskAssessment(document_id, "UNAVAILABLE", assessment_warnings=[
            "Extraction and detection results refer to different documents."
        ])
    unknown = sorted({finding.entity_type for finding in detection.findings} - SENSITIVITY_WEIGHTS.keys())
    malformed = [finding.finding_id for finding in detection.findings if (
        finding.block_id != finding.original_block_reference.block_id
        or finding.start_offset < 0
        or finding.end_offset > len(finding.original_block_reference.text)
        or finding.start_offset >= finding.end_offset
    )]
    if unknown or malformed:
        warnings = []
        if unknown:
            warnings.append("Unsupported finding categories: " + ", ".join(unknown) + ".")
        if malformed:
            warnings.append("One or more findings have invalid source references or offsets.")
        return RiskAssessment(document_id, "UNAVAILABLE", assessment_warnings=warnings)

    counts = Counter(finding.entity_type for finding in detection.findings)
    distinct = {(finding.entity_type, _normalize(finding)) for finding in detection.findings}
    maximum = max((SENSITIVITY_WEIGHTS[category] for category in counts), default=0)
    volume = min(5, len(distinct))
    linked = _has_record_linkage(detection.findings)
    score = min(100, 12 * maximum + 5 * volume + 15 * int(linked))
    top = sorted(counts, key=lambda category: (-SENSITIVITY_WEIGHTS[category], -counts[category], category))[:3]
    warnings = [
        "Sensitivity weights are PII Sentinel project assumptions, not official Cadence policy ratings.",
        "The score estimates original potential exposure; it is not a breach probability or release decision.",
    ]
    if "LOCATION" in counts:
        warnings.append("LOCATION findings may include non-private places and are not assumed to be home addresses.")
    if not detection.findings:
        warnings.append("No detector can guarantee the absence of PII.")
    explanation = (
        f"R = min(100, 12×{maximum} + 5×{volume} + 15×{int(linked)}) = {score}. "
        f"Volume uses {len(distinct)} distinct category/value pairs, capped at 5."
    )
    return RiskAssessment(
        document_id=document_id,
        status="AVAILABLE",
        score=score,
        risk_level=_risk_level(score),
        maximum_sensitivity_weight=maximum,
        distinct_pii_count=len(distinct),
        linkage_indicator=linked,
        calculation_explanation=explanation,
        category_counts=dict(sorted(counts.items())),
        top_contributing_categories=top,
        assessment_warnings=warnings,
    )
