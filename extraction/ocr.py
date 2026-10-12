"""Local Tesseract discovery and image OCR helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
import math
import shutil

from PIL import Image, ImageOps, UnidentifiedImageError
import fitz
import pytesseract
from pytesseract import Output, TesseractError, TesseractNotFoundError


WINDOWS_TESSERACT = Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe")


@dataclass(frozen=True, slots=True)
class OCRStatus:
    available: bool
    executable: str | None
    english_available: bool
    reason: str


@dataclass(slots=True)
class OCRResult:
    text: str = ""
    boxes: list[dict[str, int | str | float]] = field(default_factory=list)
    warning: str | None = None


def configure_tesseract() -> OCRStatus:
    """Find Tesseract, configure pytesseract, and verify English data."""

    executable = shutil.which("tesseract")
    if not executable and WINDOWS_TESSERACT.is_file():
        executable = str(WINDOWS_TESSERACT)
    if not executable:
        return OCRStatus(False, None, False, "Tesseract executable was not found.")

    pytesseract.pytesseract.tesseract_cmd = executable
    try:
        languages = set(pytesseract.get_languages(config=""))
    except (TesseractNotFoundError, TesseractError, OSError) as exc:
        return OCRStatus(False, executable, False, f"Tesseract could not be queried: {type(exc).__name__}.")
    if "eng" not in languages:
        return OCRStatus(False, executable, False, "Tesseract English language data is unavailable.")
    return OCRStatus(True, executable, True, "Tesseract and English language data are available.")


def _prepare_image(image: Image.Image) -> Image.Image:
    """Normalize an image and enlarge small sources for more reliable OCR."""

    # Composite transparency onto white before grayscale conversion. Converting
    # RGBA directly can turn a transparent background black and hide dark text.
    if image.mode in {"RGBA", "LA"} or "transparency" in image.info:
        rgba = image.convert("RGBA")
        white = Image.new("RGBA", rgba.size, "white")
        white.alpha_composite(rgba)
        image = white.convert("RGB")
    prepared = ImageOps.autocontrast(ImageOps.grayscale(image))
    if prepared.width < 1200 or prepared.height < 300:
        scale = min(
            3,
            max(
                2,
                math.ceil(1200 / max(prepared.width, 1)),
                math.ceil(300 / max(prepared.height, 1)),
            ),
        )
        prepared = prepared.resize((prepared.width * scale, prepared.height * scale))
    return prepared


def ocr_image(image_data: bytes | Image.Image, status: OCRStatus | None = None) -> OCRResult:
    """OCR an image locally and return text plus word bounding boxes."""

    status = status or configure_tesseract()
    if not status.available:
        return OCRResult(warning=status.reason)
    try:
        if isinstance(image_data, Image.Image):
            source = image_data
        else:
            try:
                source = Image.open(BytesIO(image_data))
                source.load()
            except UnidentifiedImageError:
                # Pillow does not decode SVG. PyMuPDF provides a local, network-
                # free renderer and rejects malformed vector data safely.
                if not image_data.lstrip().startswith(b"<svg"):
                    raise
                with fitz.open(stream=image_data, filetype="svg") as vector:
                    pixmap = vector[0].get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                    source = Image.open(BytesIO(pixmap.tobytes("png")))
                    source.load()
        image = _prepare_image(source)
        # Wide workflow banners and logos often contain separated labels that
        # Tesseract's automatic page segmentation overlooks.
        config = "--psm 11" if image.width / max(image.height, 1) >= 4 else ""
        data = pytesseract.image_to_data(image, lang="eng", config=config, output_type=Output.DICT)
        words: list[str] = []
        boxes: list[dict[str, int | str | float]] = []
        for index, raw_text in enumerate(data["text"]):
            word = raw_text.strip()
            if not word:
                continue
            confidence = float(data["conf"][index])
            if confidence < 0:
                continue
            words.append(word)
            boxes.append(
                {
                    "text": word,
                    "left": int(data["left"][index]),
                    "top": int(data["top"][index]),
                    "width": int(data["width"][index]),
                    "height": int(data["height"][index]),
                    "confidence": confidence,
                }
            )
        if not words and image.width / max(image.height, 1) >= 8:
            # Very wide process diagrams often contain several isolated labels.
            # Segment by the typical label-panel aspect ratio, then read each
            # panel as one line. This is generic geometry, not document-specific.
            segment_count = max(2, round(image.width / image.height / 2.5))
            for segment in range(segment_count):
                left = segment * image.width // segment_count
                right = (segment + 1) * image.width // segment_count
                segment_data = pytesseract.image_to_data(
                    image.crop((left, 0, right, image.height)),
                    lang="eng",
                    config="--psm 7",
                    output_type=Output.DICT,
                )
                for index, raw_text in enumerate(segment_data["text"]):
                    word = raw_text.strip()
                    if not word:
                        continue
                    confidence = float(segment_data["conf"][index])
                    if confidence < 0:
                        continue
                    words.append(word)
                    boxes.append(
                        {
                            "text": word,
                            "left": left + int(segment_data["left"][index]),
                            "top": int(segment_data["top"][index]),
                            "width": int(segment_data["width"][index]),
                            "height": int(segment_data["height"][index]),
                            "confidence": confidence,
                        }
                    )
        return OCRResult(text=" ".join(words), boxes=boxes)
    except (UnidentifiedImageError, TesseractNotFoundError, TesseractError, OSError, ValueError) as exc:
        return OCRResult(warning=f"OCR failed: {type(exc).__name__}.")
