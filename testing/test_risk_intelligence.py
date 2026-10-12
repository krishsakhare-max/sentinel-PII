"""Phase 6 explainable risk scoring, recommendations, privacy, and UI tests."""

from __future__ import annotations

import json

import pytest
from streamlit.testing.v1 import AppTest

from core.document_model import DocumentBlock, DocumentResult
from core.security_gate import GateDecision
from intelligence.recommendations import build_recommendations
from intelligence.risk_model import export_risk_report
from intelligence.risk_rating import SENSITIVITY_WEIGHTS, assess_risk
from privacy.pii_model import DetectionResult, PIIFinding
from privacy.verifier import VerificationResult


VALUES = {
    "PERSON": "Morgan Vale", "EMAIL_ADDRESS": "morgan@example.com",
    "PHONE_NUMBER": "+1 202-555-0102", "EMPLOYEE_ID": "EMP-2048",
    "GOVERNMENT_ID": "123-45-6789", "BANK_ACCOUNT": "GB82 WEST 1234 5698 7654 32",
    "DATE_OF_BIRTH": "1990-02-03", "LOCATION": "42 Example Road",
}


def finding(entity: str, value: str | None = None, *, block_id: str = "b1",
            metadata: dict | None = None, block_type: str = "paragraph", prefix: str = "Value: ") -> PIIFinding:
    raw = value or VALUES[entity]
    text = prefix + raw
    block = DocumentBlock(block_id, block_type, text, "Synthetic source", "native", metadata or {})
    start = len(prefix)
    return PIIFinding(f"{block_id}-{entity}-{start}", entity, start, start + len(raw), block_id,
                      block.metadata.get("page", block.metadata.get("slide")), "Synthetic source",
                      "Synthetic", 1.0, block, "masked")


def inputs(findings: list[PIIFinding], *, complete: bool = True, warnings: list[str] | None = None):
    blocks = {item.block_id: item.original_block_reference for item in findings}
    document = DocumentResult("doc", "synthetic.docx", "DOCX", list(blocks.values()), complete, warnings or [])
    detection = DetectionResult("doc", findings=findings, extraction_complete=complete,
                                extraction_warnings=warnings or [], analyzed_blocks=len(blocks))
    return document, detection


def decision(state: str, *, verification: str | None = None) -> GateDecision:
    return GateDecision(state, ["Synthetic gate evidence."], verification or ("PASSED" if state == "APPROVED" else "FAILED"),
                        "COMPLETE", 1, 1, 0, "2026-01-01T00:00:00Z", "doc", "hash", None)


def test_empty_findings_are_zero_but_never_labeled_safe() -> None:
    document, detection = inputs([])
    assessment = assess_risk(document, detection)
    assert assessment.status == "AVAILABLE"
    assert assessment.score == 0
    assert assessment.risk_level == "No PII detected — detection does not guarantee absence."
    assert "safe" not in assessment.risk_level.casefold()


@pytest.mark.parametrize("category,weight", SENSITIVITY_WEIGHTS.items())
def test_each_sensitivity_category_uses_configured_weight(category: str, weight: int) -> None:
    document, detection = inputs([finding(category)])
    assessment = assess_risk(document, detection)
    assert assessment.maximum_sensitivity_weight == weight
    assert assessment.score == 12 * weight + 5
    assert assessment.category_counts == {category: 1}


def test_duplicate_identifiers_count_once_without_removing_findings() -> None:
    first = finding("EMAIL_ADDRESS", block_id="one")
    duplicate = finding("EMAIL_ADDRESS", "MORGAN@EXAMPLE.COM", block_id="two")
    document, detection = inputs([first, duplicate])
    assessment = assess_risk(document, detection)
    assert assessment.distinct_pii_count == 1
    assert assessment.category_counts["EMAIL_ADDRESS"] == 2
    assert len(detection.findings) == 2


def test_multiple_distinct_identifiers_and_maximum_score_cap() -> None:
    findings = [finding("GOVERNMENT_ID", f"999-88-77{index}{index}", block_id=f"g{index}") for index in range(5)]
    findings.extend([
        finding("PERSON", block_id="name", metadata={"table": 1, "row": 1}, block_type="table_cell"),
        finding("EMAIL_ADDRESS", block_id="email", metadata={"table": 1, "row": 1}, block_type="table_cell"),
    ])
    document, detection = inputs(findings)
    assessment = assess_risk(document, detection)
    assert assessment.distinct_pii_count == 7
    assert assessment.linkage_indicator
    assert assessment.score == 100


def test_linkage_requires_structured_row_or_explicit_labels() -> None:
    row_findings = [
        finding("PERSON", block_id="name", metadata={"slide": 1, "table": 2, "row": 3}, block_type="table_cell"),
        finding("EMAIL_ADDRESS", block_id="email", metadata={"slide": 1, "table": 2, "row": 3}, block_type="table_cell"),
    ]
    document, detection = inputs(row_findings)
    assert assess_risk(document, detection).linkage_indicator

    labeled_block = DocumentBlock("record", "paragraph", "Name: Morgan Vale; Email: morgan@example.com",
                                  "Contact record", "native", {})
    labeled = [
        PIIFinding("p", "PERSON", 6, 17, "record", None, "Contact record", "Synthetic", 1, labeled_block, "masked"),
        PIIFinding("e", "EMAIL_ADDRESS", 26, 44, "record", None, "Contact record", "Synthetic", 1, labeled_block, "masked"),
    ]
    document, detection = inputs(labeled)
    assert assess_risk(document, detection).linkage_indicator


def test_same_page_and_same_table_row_on_different_slides_do_not_link() -> None:
    unrelated_page = [
        finding("PERSON", block_id="p", metadata={"page": 1}),
        finding("EMAIL_ADDRESS", block_id="e", metadata={"page": 1}),
    ]
    document, detection = inputs(unrelated_page)
    assert not assess_risk(document, detection).linkage_indicator

    different_slides = [
        finding("PERSON", block_id="s1", metadata={"slide": 1, "table": 1, "row": 1}, block_type="table_cell"),
        finding("EMAIL_ADDRESS", block_id="s2", metadata={"slide": 2, "table": 1, "row": 1}, block_type="table_cell"),
    ]
    document, detection = inputs(different_slides)
    assert not assess_risk(document, detection).linkage_indicator

    person_location_only = [
        finding("PERSON", block_id="person", metadata={"table": 1, "row": 2}, block_type="table_cell"),
        finding("LOCATION", block_id="place", metadata={"table": 1, "row": 2}, block_type="table_cell"),
    ]
    document, detection = inputs(person_location_only)
    assert not assess_risk(document, detection).linkage_indicator


def test_missing_mismatched_and_malformed_results_are_unavailable() -> None:
    assert assess_risk(None, None).status == "UNAVAILABLE"
    document, detection = inputs([finding("PERSON")])
    detection.document_id = "other"
    assert assess_risk(document, detection).status == "UNAVAILABLE"
    bad = finding("PERSON")
    object.__setattr__(bad, "end_offset", 999)
    document, detection = inputs([bad])
    assert assess_risk(document, detection).status == "UNAVAILABLE"


def test_score_is_deterministic_across_finding_order() -> None:
    findings = [finding("PERSON", block_id="p"), finding("PHONE_NUMBER", block_id="t")]
    first = assess_risk(*inputs(findings))
    second = assess_risk(*inputs(list(reversed(findings))))
    assert (first.score, first.distinct_pii_count, first.category_counts) == (
        second.score, second.distinct_pii_count, second.category_counts
    )


def test_recommendations_reflect_categories_partial_residual_and_block() -> None:
    document, detection = inputs([finding("GOVERNMENT_ID")], complete=False, warnings=["image unresolved"])
    assessment = assess_risk(document, detection)
    verification = VerificationResult(residual_findings=[finding("GOVERNMENT_ID")])
    items = build_recommendations(assessment, document, verification, decision("BLOCKED"))
    titles = {item.title for item in items}
    assert {"Protect government identifiers", "Resolve incomplete extraction",
            "Resolve residual sensitive data", "Maintain the release block"} <= titles
    assert items[0].priority == "Critical"


def test_approved_recommendation_permits_only_verified_payload() -> None:
    document, detection = inputs([finding("EMAIL_ADDRESS")])
    items = build_recommendations(assess_risk(document, detection), document,
                                  VerificationResult(passed=True), decision("APPROVED"))
    assert any(item.title == "Use only the verified payload" for item in items)
    assert not any(item.title == "Maintain the release block" for item in items)


def test_export_contains_aggregates_but_no_raw_pii() -> None:
    document, detection = inputs([finding("EMAIL_ADDRESS")])
    assessment = assess_risk(document, detection)
    recommendations = build_recommendations(assessment, document, VerificationResult(passed=True), decision("APPROVED"))
    report = export_risk_report(assessment, recommendations, extraction_status="COMPLETE",
                                verification_status="PASSED", release_decision="APPROVED")
    serialized = json.dumps(report)
    assert "morgan@example.com" not in serialized
    assert report["security_controls"]["release_decision"] == "APPROVED"


def test_risk_dashboard_empty_state_loads_without_fabricated_data() -> None:
    app = AppTest.from_file("app.py").run(timeout=120)
    app.radio[0].set_value("Risk Intelligence").run(timeout=120)
    assert not app.exception
    assert any("Analyze a document" in item.value for item in app.info)


def test_risk_dashboard_uses_live_session_results() -> None:
    document, detection = inputs([finding("GOVERNMENT_ID")])
    verification = VerificationResult(passed=False, residual_findings=[finding("GOVERNMENT_ID")])
    gate = decision("BLOCKED")
    app = AppTest.from_file("app.py").run(timeout=120)
    app.session_state["current_record_key"] = "risk:full"
    app.session_state["extraction_cache"] = {
        "risk:full": document,
        "pii:risk:full": detection,
        "gateway:risk:full": (None, "", verification, gate),
    }
    app.radio[0].set_value("Risk Intelligence").run(timeout=120)
    assert not app.exception
    metrics = {item.label: item.value for item in app.metric}
    assert metrics["Original exposure"].startswith("65/100")
    assert metrics["Sanitized verification"] == "FAILED"
    assert metrics["Release decision"] == "BLOCKED"
