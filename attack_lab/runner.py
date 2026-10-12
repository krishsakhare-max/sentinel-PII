"""Isolated execution of synthetic attacks through the production pipeline."""

from __future__ import annotations

from collections.abc import Callable
from time import perf_counter

from attack_lab.evaluator import evaluate_scenario
from attack_lab.fixtures import build_scenario
from attack_lab.models import AttackResult, AttackSummary
from core.pipeline import run_secure_analysis
from extraction.ocr import OCRStatus, configure_tesseract


LabProgress = Callable[[int, int, str], None]


def run_scenario(scenario_id: str, progress_callback: LabProgress | None = None) -> AttackResult:
    """Generate and execute one isolated fixture using production controls."""

    scenario = build_scenario(scenario_id)
    started = perf_counter()
    status = (OCRStatus(False, None, False, "SIMULATED EXTRACTION FAILURE: OCR unavailable.")
              if scenario.simulated_extraction_failure else configure_tesseract())
    analysis = run_secure_analysis(
        scenario.data, scenario.filename, ocr_status=status,
        progress_callback=progress_callback,
    )
    return evaluate_scenario(scenario, analysis, perf_counter() - started)


def aggregate_results(results: list[AttackResult]) -> AttackSummary:
    return AttackSummary(
        scenarios_executed=len(results),
        detection_successes=sum(item.detection_outcome == "SUCCESS" for item in results),
        containment_passes=sum(item.containment_outcome == "PASS" for item in results),
        containment_failures=sum(item.containment_outcome == "FAIL" for item in results),
        inconclusive_tests=sum(
            "INCONCLUSIVE" in {item.detection_outcome, item.containment_outcome, item.usability_outcome}
            for item in results
        ),
        errors=sum(item.containment_outcome == "ERROR" for item in results),
    )
