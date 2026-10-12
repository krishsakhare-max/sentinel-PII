"""Hybrid Presidio, spaCy, and contextual-regex PII detection."""

from __future__ import annotations

from functools import lru_cache
import hashlib
import re

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from core.document_model import DocumentBlock, DocumentResult
from privacy.patterns import CONTEXT_LABELS, CONTEXT_REQUIRED, custom_recognizers
from privacy.pii_model import DetectionResult, PIIFinding
from privacy.span_resolver import resolve_findings


SUPPORTED_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "EMPLOYEE_ID", "GOVERNMENT_ID",
    "BANK_ACCOUNT", "DATE_OF_BIRTH", "LOCATION",
]
PERSON_LABEL_PATTERN = re.compile(
    r"(?i)\b(?:name|employee|contact|officer|manager|approved\s+by|policy\s+owner)\s*[:\-]\s*"
    r"(?P<value>[^\W\d_][\w'’.-]+(?:[ \t]+[^\W\d_][\w'’.-]+){1,3})"
)
EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
OBFUSCATED_EMAIL_PATTERN = re.compile(
    r"(?i)(?<![\w.+-])[\w.+-]+\s*(?:\[\s*at\s*\]|\(\s*at\s*\))\s*"
    r"[A-Za-z0-9-]+(?:\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\))\s*[A-Za-z0-9-]+)+"
    r"(?![\w.-])"
)
PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+\d{1,3}[\d ()-]*\d|\d[\d ()-]{8,}\d)(?!\w)")
NON_PERSON_TERMS = {
    "server", "database", "environment", "application", "system", "service",
    "board", "committee", "team", "group", "department", "policy", "procedure",
}


@lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    """Initialize the local NLP engine once per Python process."""

    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    })
    analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
    for recognizer in custom_recognizers():
        analyzer.registry.add_recognizer(recognizer)
    return analyzer


def _source_number(block: DocumentBlock) -> int | None:
    value = block.metadata.get("page", block.metadata.get("slide"))
    return int(value) if isinstance(value, int) else None


def _mask(value: str) -> str:
    if len(value) <= 2:
        return "•" * len(value)
    return f"{value[0]}{'•' * min(len(value) - 2, 8)}{value[-1]}"


def _finding(block: DocumentBlock, entity: str, start: int, end: int, method: str, score: float) -> PIIFinding:
    identity = f"{block.block_id}:{start}:{end}:{entity}:{method}"
    return PIIFinding(
        finding_id=hashlib.sha256(identity.encode()).hexdigest()[:16],
        entity_type=entity,
        start_offset=start,
        end_offset=end,
        block_id=block.block_id,
        source_page_or_slide=_source_number(block),
        source_location=block.source_location,
        detection_method=method,
        confidence_score=round(float(score), 3),
        original_block_reference=block,
        masked_preview=_mask(block.text[start:end]),
    )


def _context_for(blocks: list[DocumentBlock], index: int) -> list[str]:
    context: set[str] = set()
    for neighbor_index in range(max(0, index - 1), min(len(blocks), index + 2)):
        text = blocks[neighbor_index].text.casefold()
        context.update(label for label in CONTEXT_LABELS if label in text)
    return sorted(context)


def _has_required_context(entity: str, block_text: str, context: list[str]) -> bool:
    if entity not in CONTEXT_REQUIRED:
        return True
    combined = f"{block_text.casefold()} {' '.join(context)}"
    required = {
        "GOVERNMENT_ID": ("ssn", "social security", "government id", "tax id"),
        "BANK_ACCOUNT": ("bank", "account", "iban", "routing"),
        "DATE_OF_BIRTH": ("date of birth", "dob", "born", "birth date"),
    }[entity]
    return any(label in combined for label in required)


def detect_pii(document: DocumentResult, analyzer: AnalyzerEngine | None = None) -> DetectionResult:
    """Detect PII in each original block while preserving exact local offsets."""

    output = DetectionResult(
        document_id=document.document_id,
        extraction_complete=document.extraction_complete,
        extraction_warnings=list(document.extraction_warnings),
    )
    if not document.blocks:
        output.warnings.append("The document contains no extracted text blocks to analyze.")
        return output
    try:
        engine = analyzer or get_analyzer()
    except (OSError, RuntimeError, ValueError, ImportError) as exc:
        output.warnings.append(f"PII detector initialization failed: {type(exc).__name__}.")
        output.failed_blocks = [block.block_id for block in document.blocks if block.text.strip()]
        return output

    candidates: list[PIIFinding] = []
    for index, block in enumerate(document.blocks):
        if not block.text.strip():
            continue
        context = _context_for(document.blocks, index)
        try:
            results = engine.analyze(
                text=block.text,
                language="en",
                entities=SUPPORTED_ENTITIES,
                context=context,
                score_threshold=0.25,
                return_decision_process=True,
            )
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            output.warnings.append(f"Block {block.block_id} could not be analyzed: {type(exc).__name__}.")
            output.failed_blocks.append(block.block_id)
            continue
        output.analyzed_blocks += 1
        for result in results:
            if not _has_required_context(result.entity_type, block.text, context):
                continue
            candidate_text = block.text[result.start:result.end].strip(" :.-").casefold()
            # Field labels are context, not people. spaCy can classify a
            # capitalized standalone label such as "Email" as PERSON after its
            # value has been replaced by a placeholder.
            if result.entity_type == "PERSON" and candidate_text in CONTEXT_LABELS:
                continue
            explanation = result.analysis_explanation
            method = explanation.recognizer if explanation and explanation.recognizer else "Presidio"
            candidates.append(_finding(block, result.entity_type, result.start, result.end, method, result.score))

        for match in PERSON_LABEL_PATTERN.finditer(block.text):
            start, end = match.span("value")
            words = {word.casefold().strip(".,") for word in match.group("value").split()}
            label_prefix = block.text[max(0, match.start() - 24):match.start()].casefold()
            technical_label = any(term in label_prefix for term in ("database", "server", "system", "application"))
            if not words & NON_PERSON_TERMS and not technical_label:
                candidates.append(_finding(block, "PERSON", start, end, "LabeledPersonRegex", 0.72))

        for match in EMAIL_PATTERN.finditer(block.text):
            candidates.append(_finding(block, "EMAIL_ADDRESS", match.start(), match.end(), "EmailRegex", 0.86))

        for match in OBFUSCATED_EMAIL_PATTERN.finditer(block.text):
            candidates.append(_finding(
                block, "EMAIL_ADDRESS", match.start(), match.end(), "ObfuscatedEmailRegex", 0.84,
            ))

        for match in PHONE_PATTERN.finditer(block.text):
            value = match.group().strip()
            start = match.start() + len(match.group()) - len(match.group().lstrip())
            end = start + len(value)
            digit_count = len(re.sub(r"\D", "", value))
            has_label = any(label in block.text.casefold() or label in context for label in ("phone", "mobile", "telephone"))
            if 8 <= digit_count <= 15 and (value.startswith("+") or has_label):
                candidates.append(_finding(block, "PHONE_NUMBER", start, end, "PhoneRegex", 0.8))

    initial_findings = resolve_findings(candidates)

    # A value established as sensitive in one block remains sensitive when it
    # is repeated elsewhere. This closes a common presentation/document gap:
    # a labeled name may be recognized while the same name in a heading is not.
    # Boundary-aware matching prevents names such as "Tim" matching "time".
    propagated: list[PIIFinding] = []
    seen_values: set[tuple[str, str]] = set()
    for finding in initial_findings:
        value = finding.original_block_reference.text[finding.start_offset:finding.end_offset]
        normalized = " ".join(value.split()).casefold()
        if len(normalized) < 4 or (finding.entity_type == "PERSON" and " " not in normalized):
            continue
        identity = (finding.entity_type, normalized)
        if identity in seen_values:
            continue
        seen_values.add(identity)
        pattern = re.compile(rf"(?<!\w){re.escape(value)}(?!\w)", re.IGNORECASE)
        for block in document.blocks:
            for match in pattern.finditer(block.text):
                if any(existing.block_id == block.block_id
                       and existing.start_offset <= match.start()
                       and match.end() <= existing.end_offset
                       for existing in initial_findings):
                    continue
                propagated.append(_finding(
                    block, finding.entity_type, match.start(), match.end(),
                    "RepeatedValuePropagation", min(finding.confidence_score, 0.8),
                ))

    output.findings = resolve_findings(initial_findings + propagated)
    if not output.findings:
        output.warnings.append("No PII was detected; this is not proof that the document is PII-free.")
    return output
