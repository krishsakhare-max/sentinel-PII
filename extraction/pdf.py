"""PDF text and scanned-page extraction using PyMuPDF and local OCR."""

from __future__ import annotations

from collections.abc import Callable, Iterable
import re

import fitz

from core.document_model import DocumentBlock
from extraction.ocr import OCRStatus, configure_tesseract, ocr_image


def _ordered_native_blocks(page: fitz.Page) -> list[tuple]:
    """Return blocks in a practical reading order, including two-column pages."""

    native = [item for item in page.get_text("blocks") if str(item[4]).strip()]
    midpoint = page.rect.width / 2
    left = [item for item in native if item[2] <= midpoint * 1.1]
    right = [item for item in native if item[0] >= midpoint * 0.9]
    other = [item for item in native if item not in left and item not in right]
    if len(left) >= 2 and len(right) >= 2 and not other:
        return sorted(left, key=lambda item: (item[1], item[0])) + sorted(right, key=lambda item: (item[1], item[0]))
    return sorted(native, key=lambda item: (item[1], item[0]))


def _normalized(text: str) -> str:
    return re.sub(r"\W+", "", text).casefold()


def _area(rect: fitz.Rect) -> float:
    return max(0.0, rect.width) * max(0.0, rect.height)


def extract_pdf(
    data: bytes,
    ocr_status: OCRStatus | None = None,
    page_numbers: Iterable[int] | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> tuple[list[DocumentBlock], list[str]]:
    blocks: list[DocumentBlock] = []
    warnings: list[str] = []
    status = ocr_status or configure_tesseract()

    with fitz.open(stream=data, filetype="pdf") as document:
        requested = list(page_numbers) if page_numbers is not None else list(range(1, document.page_count + 1))
        if not requested or any(number < 1 or number > document.page_count for number in requested):
            raise ValueError("Selected PDF pages are outside the document range.")
        for processed, page_number in enumerate(requested, start=1):
            page = document[page_number - 1]
            native = _ordered_native_blocks(page)
            native_text = "".join(str(item[4]).strip() for item in native)
            if len(native_text) >= 30:
                for block_index, item in enumerate(native, start=1):
                    text = str(item[4]).strip()
                    if not text:
                        continue
                    blocks.append(
                        DocumentBlock(
                            block_id=f"pdf-p{page_number}-b{block_index}",
                            block_type="text",
                            text=text,
                            source_location=f"page {page_number}",
                            extraction_status="native",
                            metadata={"page": page_number, "bbox": list(item[:4]), "method": "PyMuPDF"},
                        )
                    )
                # Native text does not prove that text inside a page image was
                # extracted. OCR sufficiently large image regions as well.
                seen_xrefs: set[int] = set()
                for image_number, image_info in enumerate(page.get_images(full=True), start=1):
                    xref = image_info[0]
                    if xref in seen_xrefs:
                        continue
                    seen_xrefs.add(xref)
                    rects = page.get_image_rects(xref)
                    if not rects or max(_area(rect) for rect in rects) < _area(page.rect) * 0.01:
                        continue
                    if not status.available:
                        warnings.append(f"Page {page_number}, image {image_number} requires OCR but {status.reason}")
                        continue
                    image_result = ocr_image(document.extract_image(xref)["image"], status)
                    if image_result.warning:
                        warnings.append(f"Page {page_number}, image {image_number}: {image_result.warning}")
                    elif image_result.text.strip():
                        if _normalized(image_result.text) not in _normalized(native_text):
                            blocks.append(DocumentBlock(
                                f"pdf-p{page_number}-image-{image_number}", "image_ocr",
                                image_result.text.strip(), f"page {page_number}, image {image_number}", "ocr",
                                {"page": page_number, "image_bboxes": [list(rect) for rect in rects],
                                 "word_boxes": image_result.boxes, "method": "Tesseract"},
                            ))
                    else:
                        warnings.append(f"Page {page_number}, image {image_number} produced no OCR text.")
                if progress:
                    progress(processed, len(requested))
                continue

            # Sparse and empty pages are rendered in full so image-only text is not skipped.
            if not status.available:
                warnings.append(f"Page {page_number} requires OCR but {status.reason}")
                continue
            # Grayscale rendering avoids creating an unnecessary RGB buffer;
            # OCR preprocessing uses grayscale in all cases.
            pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), colorspace=fitz.csGRAY, alpha=False)
            result = ocr_image(pixmap.tobytes("png"), status)
            if result.warning:
                warnings.append(f"Page {page_number}: {result.warning}")
            elif result.text.strip():
                blocks.append(
                    DocumentBlock(
                        block_id=f"pdf-p{page_number}-ocr",
                        block_type="ocr_text",
                        text=result.text.strip(),
                        source_location=f"page {page_number}",
                        extraction_status="ocr",
                        metadata={"page": page_number, "word_boxes": result.boxes, "method": "Tesseract"},
                    )
                )
            else:
                warnings.append(f"Page {page_number} produced no native or OCR text.")
            if progress:
                progress(processed, len(requested))
    return blocks, warnings
