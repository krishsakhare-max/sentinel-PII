"""Independent ground-truth comparison for adversarial pipeline results."""

from __future__ import annotations

import re

from attack_lab.models import AttackResult, AttackScenario, GroundTruthEntity
from core.mock_ai import mock_ai_process
from core.pipeline import AnalysisResult
from privacy.pii_model import PIIFinding


def _finding_value(finding: PIIFinding) -> str:
    return finding.original_block_reference.text[finding.start_offset:finding.end_offset]


def normalize_value(value: str, entity_type: str) -> str:
    folded = value.casefold()
    if entity_type == "EMAIL_ADDRESS":
        folded = re.sub(r"\s*[\[(]\s*at\s*[\])]?\s*", "@", folded)
        folded = re.sub(r"\s*[\[(]\s*dot\s*[\])]?\s*", ".", folded)
        return re.sub(r"\s+", "", folded)
    if entity_type == "PHONE_NUMBER":
        return re.sub(r"\D", "", folded)
    return " ".join(folded.split()).strip(" .,;:")


def _entity_detected(entity: GroundTruthEntity, findings: list[PIIFinding]) -> bool:
    if entity.composite_parts:
        predicted = [normalize_value(_finding_value(item), entity.entity_type)
                     for item in findings if item.entity_type == entity.entity_type]
        return all(normalize_value(part, entity.entity_type) in predicted for part in entity.composite_parts)
    expected = normalize_value(entity.value, entity.entity_type)
    return any(item.entity_type == entity.entity_type
               and normalize_value(_finding_value(item), item.entity_type) == expected
               for item in findings)


def _entity_present(entity: GroundTruthEntity, payload: str) -> bool:
    if entity.composite_parts:
        expected = "".join(re.sub(r"\W", "", part.casefold()) for part in entity.composite_parts)
        candidate = re.sub(r"\W", "", payload.casefold())
        return expected in candidate
    expected = normalize_value(entity.value, entity.entity_type)
    candidate = normalize_value(payload, entity.entity_type)
    return expected in candidate


def _matched_prediction(finding: PIIFinding, entities: tuple[GroundTruthEntity, ...]) -> bool:
    actual = normalize_value(_finding_value(finding), finding.entity_type)
    for entity in entities:
        if entity.entity_type != finding.entity_type:
            continue
        expected_values = entity.composite_parts or (entity.value,)
        if actual in {normalize_value(value, entity.entity_type) for value in expected_values}:
            return True
    return False


def evaluate_scenario(scenario: AttackScenario, analysis: AnalysisResult, runtime: float) -> AttackResult:
    output = AttackResult(
        scenario.scenario_id, scenario.name, scenario.document_format,
        expected_entity_count=len(scenario.ground_truth), runtime_seconds=runtime,
    )
    if analysis.errors or not all((analysis.document, analysis.detection, analysis.redaction,
                                   analysis.verification, analysis.decision)):
        output.detection_outcome = "INCONCLUSIVE"
        output.containment_outcome = "ERROR"
        output.usability_outcome = "INCONCLUSIVE"
        output.error_category = "PIPELINE_EXECUTION_ERROR"
        output.lessons.append("The production pipeline did not produce complete evaluable evidence.")
        return output

    document = analysis.document
    detection = analysis.detection
    decision = analysis.decision
    output.release_decision = decision.decision
    output.extraction_status = decision.extraction_status
    output.verification_reasons = list(decision.reasons)
    detected = [_entity_detected(entity, detection.findings) for entity in scenario.ground_truth]
    output.detected_ground_truth_count = sum(detected)
    output.missed_entity_types = [entity.entity_type for entity, found in zip(scenario.ground_truth, detected) if not found]
    output.false_positive_count = sum(
        not _matched_prediction(finding, scenario.ground_truth) for finding in detection.findings
    )
    if not scenario.ground_truth:
        output.detection_outcome = "SUCCESS" if not detection.findings else "FAILED"
    elif output.detected_ground_truth_count == len(scenario.ground_truth):
        output.detection_outcome = "SUCCESS"
    elif output.detected_ground_truth_count:
        output.detection_outcome = "PARTIAL"
    else:
        output.detection_outcome = "FAILED"

    candidate = decision.approved_payload.text if decision.approved_payload else analysis.payload
    remaining = [_entity_present(entity, candidate) for entity in scenario.ground_truth]
    output.redacted_ground_truth_count = sum(
        found and not present for found, present in zip(detected, remaining)
    )
    output.over_redaction_count = sum(
        normalize_value(safe, "PERSON") not in normalize_value(candidate, "PERSON")
        for safe in scenario.safe_content
    )

    if decision.decision == "APPROVED":
        try:
            mock_ai_process(decision.approved_payload, decision)
        except (PermissionError, TypeError, ValueError):
            output.containment_outcome = "ERROR"
            output.error_category = "APPROVED_PAYLOAD_REJECTED"
        else:
            output.approved_payload_leakage = any(remaining)
            output.containment_outcome = "FAIL" if output.approved_payload_leakage else "PASS"
            if output.approved_payload_leakage:
                output.error_category = "APPROVED_PAYLOAD_LEAKAGE"
                output.lessons.append("Independent ground truth remained in a payload accepted by the mock AI.")
    elif decision.decision == "BLOCKED":
        try:
            mock_ai_process(analysis.payload, decision)  # type: ignore[arg-type]
        except PermissionError:
            output.containment_outcome = "PASS"
            output.lessons.append("The fail-closed boundary rejected the blocked candidate payload.")
        else:
            output.containment_outcome = "FAIL"
            output.error_category = "AUTHORIZATION_BYPASS"
    else:
        output.containment_outcome = "INCONCLUSIVE"
        output.error_category = "NO_GATE_DECISION"

    if scenario.simulated_extraction_failure:
        output.usability_outcome = "INCONCLUSIVE"
        output.lessons.append("A simulated OCR outage intentionally made extraction incomplete.")
    elif output.over_redaction_count or output.false_positive_count:
        output.usability_outcome = "FAIL"
        output.lessons.append("Nonsensitive content was removed or classified as sensitive.")
    elif output.detection_outcome == "SUCCESS" and decision.decision == "APPROVED":
        output.usability_outcome = "PASS"
    else:
        output.usability_outcome = "FAIL"
        output.lessons.append("Safe containment did not provide full detection and usable sanitized output.")

    if document.extraction_complete != (scenario.expected_extraction == "COMPLETE"):
        output.error_category = output.error_category or "UNEXPECTED_EXTRACTION_STATUS"
        output.lessons.append("Observed extraction status differed from independently defined expectations.")
        if output.containment_outcome == "PASS" and decision.decision == "APPROVED":
            output.containment_outcome = "INCONCLUSIVE"
    if output.missed_entity_types:
        output.mitigations.append("Extend generalizable recognition only with negative tests for false positives.")
    if decision.decision == "BLOCKED":
        output.mitigations.append("Keep the candidate local until every gate failure is resolved.")
    if output.approved_payload_leakage:
        output.mitigations.append("Treat this as a detector coverage vulnerability; do not release similar content.")

    ocr_confidences = [
        float(box["confidence"])
        for block in document.blocks if block.extraction_status == "ocr"
        for box in block.metadata.get("word_boxes", []) if "confidence" in box
    ]
    if ocr_confidences:
        output.ocr_average_confidence = round(sum(ocr_confidences) / len(ocr_confidences), 2)
    return output
