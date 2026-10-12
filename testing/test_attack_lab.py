"""Phase 7 adversarial fixture, execution, evaluation, and isolation tests."""

from __future__ import annotations

import hashlib
import inspect

import pytest

from attack_lab.evaluator import evaluate_scenario, normalize_value
from attack_lab.fixtures import all_scenarios, build_scenario
from attack_lab.runner import aggregate_results, run_scenario
from attack_lab.scenarios import SCENARIO_ORDER
from core.mock_ai import mock_ai_process
from core.pipeline import run_secure_analysis
from core.security_gate import ApprovedPayload
from core.validator import validate_file
from intelligence import assess_risk
from privacy.detector import detect_pii
from core.document_model import DocumentBlock, DocumentResult


@pytest.fixture(scope="module")
def executed():
    return {scenario_id: run_scenario(scenario_id) for scenario_id in SCENARIO_ORDER}


def test_fixture_generation_is_deterministic_and_synthetic() -> None:
    for scenario_id in SCENARIO_ORDER:
        first = build_scenario(scenario_id)
        second = build_scenario(scenario_id)
        assert first.data == second.data
        text = " ".join(
            [first.name, first.objective, *first.safe_content]
            + [entity.value for entity in first.ground_truth]
        ).casefold()
        assert "cadence" not in text
        assert first.ground_truth is not None


def test_real_docx_pptx_pdf_fixtures_validate() -> None:
    formats = {scenario.document_format for scenario in all_scenarios()}
    assert formats == {"DOCX", "PPTX", "PDF"}
    for scenario in all_scenarios():
        validation = validate_file(scenario.data, scenario.filename)
        assert validation.is_valid
        assert validation.detected_format == scenario.document_format


def test_genuine_scanned_pdf_uses_ocr(executed) -> None:
    scenario = build_scenario("scanned_phone")
    analysis = run_secure_analysis(scenario.data, scenario.filename)
    assert analysis.document.blocks
    assert all(block.extraction_status == "ocr" for block in analysis.document.blocks)
    assert analysis.document.text
    assert executed["scanned_phone"].ocr_average_confidence is not None


def test_obfuscated_email_normalization_and_negative_detection() -> None:
    assert normalize_value("alex [at] example [dot] com", "EMAIL_ADDRESS") == "alex@example.com"
    positive = DocumentResult("p", "p.docx", "DOCX", [
        DocumentBlock("b", "paragraph", "Contact: alex [at] example [dot] com", "p", "native", {})
    ], True, [])
    negative = DocumentResult("n", "n.docx", "DOCX", [
        DocumentBlock("b", "paragraph", "Meet Alex at example dot com before lunch.", "p", "native", {})
    ], True, [])
    assert any(item.entity_type == "EMAIL_ADDRESS" for item in detect_pii(positive).findings)
    assert not any(item.entity_type == "EMAIL_ADDRESS" for item in detect_pii(negative).findings)


def test_independent_ground_truth_detection_and_false_positive_tracking(executed) -> None:
    ordinary = executed["ordinary_pii"]
    assert ordinary.expected_entity_count == 3
    assert ordinary.detected_ground_truth_count == 3
    assert ordinary.false_positive_count == 0
    trap = executed["false_positive_trap"]
    assert trap.expected_entity_count == 0
    assert trap.false_positive_count == 0
    assert trap.over_redaction_count == 0


def test_split_shape_composite_is_not_invented_as_one_span(executed) -> None:
    result = executed["split_shape_name"]
    assert result.expected_entity_count == 1
    assert result.detected_ground_truth_count in {0, 1}
    if result.detected_ground_truth_count == 0:
        assert "PERSON" in result.missed_entity_types
        assert result.detection_outcome == "FAILED"


def test_incomplete_extraction_is_really_partial_blocked_and_rejected(executed) -> None:
    result = executed["incomplete_extraction"]
    assert result.extraction_status == "PARTIAL"
    assert result.release_decision == "BLOCKED"
    assert result.containment_outcome == "PASS"
    scenario = build_scenario("incomplete_extraction")
    analysis = run_secure_analysis(
        scenario.data, scenario.filename,
        ocr_status=__import__("extraction.ocr", fromlist=["OCRStatus"]).OCRStatus(
            False, None, False, "SIMULATED EXTRACTION FAILURE: OCR unavailable."
        ),
    )
    with pytest.raises(PermissionError):
        mock_ai_process(analysis.payload, analysis.decision)


def test_all_displayed_results_come_from_runner_not_hardcoded() -> None:
    source = inspect.getsource(run_scenario)
    assert "run_secure_analysis" in source
    assert "containment_outcome" not in source
    assert "release_decision =" not in source


def test_scenarios_are_isolated(executed) -> None:
    assert set(executed) == set(SCENARIO_ORDER)
    assert len({build_scenario(item).filename for item in executed}) == len(executed)
    assert len({hashlib.sha256(build_scenario(item).data).hexdigest() for item in executed}) == len(executed)


def test_pipeline_errors_are_not_reported_as_pass() -> None:
    scenario = build_scenario("ordinary_pii")
    failed = run_secure_analysis(b"broken", "broken.docx")
    result = evaluate_scenario(scenario, failed, 0.01)
    assert result.containment_outcome == "ERROR"
    assert result.detection_outcome == "INCONCLUSIVE"
    assert result.usability_outcome == "INCONCLUSIVE"


def test_independent_evaluator_catches_accepted_known_pii_leakage() -> None:
    scenario = build_scenario("obfuscated_email")
    analysis = run_secure_analysis(scenario.data, scenario.filename)
    leaked = f"Contact: {scenario.ground_truth[0].value}"
    payload_hash = hashlib.sha256(leaked.encode()).hexdigest()
    approved = ApprovedPayload(leaked, analysis.document.document_id, payload_hash,
                               analysis.verification.verification_id)
    analysis.payload = leaked
    analysis.decision.decision = "APPROVED"
    analysis.decision.verification_status = "PASSED"
    analysis.decision.payload_hash = payload_hash
    analysis.decision.approved_payload = approved
    result = evaluate_scenario(scenario, analysis, 0.01)
    assert result.containment_outcome == "FAIL"
    assert result.approved_payload_leakage
    assert result.error_category == "APPROVED_PAYLOAD_LEAKAGE"


def test_aggregation_uses_actual_result_fields(executed) -> None:
    results = list(executed.values())
    summary = aggregate_results(results)
    assert summary.scenarios_executed == 6
    assert summary.containment_passes + summary.containment_failures + summary.errors <= 6
    assert summary.detection_successes == sum(item.detection_outcome == "SUCCESS" for item in results)


def test_baseline_risk_formula_is_unchanged() -> None:
    block = DocumentBlock("b", "paragraph", "Email: safe.person@example.test", "p", "native", {})
    document = DocumentResult("risk", "risk.docx", "DOCX", [block], True, [])
    detection = detect_pii(document)
    detection.document_id = "risk"
    assessment = assess_risk(document, detection)
    assert assessment.score == 29  # S=2, V=1, L=0
