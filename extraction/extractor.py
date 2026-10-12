"""Validation-first format router returning the unified document model."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable

from core.document_model import DocumentResult
from core.validator import validate_file
from extraction.ocr import OCRStatus, configure_tesseract
from extraction.pdf import extract_pdf
from extraction.powerpoint import extract_pptx
from extraction.word import extract_docx


ROUTES = {"PDF": extract_pdf, "DOCX": extract_docx, "PPTX": extract_pptx}


def extract_document(
    data: bytes,
    filename: str,
    ocr_status: OCRStatus | None = None,
    selected_pages: Iterable[int] | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> DocumentResult:
    """Validate, route, and extract a supported document entirely in memory."""

    validation = validate_file(data, filename)
    document_id = hashlib.sha256(data).hexdigest()[:16] if data else "empty"
    result = DocumentResult(document_id, filename, validation.detected_format or "UNKNOWN")
    if not validation.is_valid:
        result.extraction_warnings.append(f"Validation failed: {validation.reason}")
        return result

    status = ocr_status or configure_tesseract()
    try:
        if selected_pages is not None:
            if validation.detected_format != "PDF":
                result.extraction_warnings.append("Selected-page extraction is supported only for PDF files.")
                return result
            pages = list(selected_pages)
            blocks, warnings = extract_pdf(data, status, pages, progress)
            warnings.append(
                "Selected Pages Demo processed only part of the original document; full-document extraction is incomplete."
            )
        else:
            if validation.detected_format == "PDF":
                blocks, warnings = extract_pdf(data, status, progress=progress)
            else:
                blocks, warnings = ROUTES[validation.detected_format](data, status)
        result.blocks = blocks
        result.extraction_warnings = warnings
        result.extraction_complete = not warnings
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError) as exc:
        result.extraction_warnings.append(f"Extraction failed safely: {type(exc).__name__}.")
    return result
