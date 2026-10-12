"""Security-focused, in-memory validation for supported uploads.

Validation establishes that an upload has the expected outer file structure.
It does not extract content and does not establish that a document is PII-free.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
import re
import zipfile

import fitz


MAX_FILE_SIZE = 20 * 1024 * 1024
MAX_ZIP_ENTRIES = 10_000
MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
ALLOWED_EXTENSIONS = {".pdf": "PDF", ".docx": "DOCX", ".pptx": "PPTX"}
OOXML_CONTENT_TYPES = {
    "DOCX": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "PPTX": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
}
OOXML_REQUIRED_PARTS = {"DOCX": "word/document.xml", "PPTX": "ppt/presentation.xml"}
OLE_HEADER = bytes.fromhex("D0CF11E0A1B11AE1")


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """A safe, display-ready outcome from upload validation."""

    is_valid: bool
    detected_format: str | None
    file_size: int
    reason: str


def _result(valid: bool, detected: str | None, size: int, reason: str) -> ValidationResult:
    return ValidationResult(valid, detected, size, reason)


def _safe_zip_name(name: str) -> bool:
    """Allow only relative, normalized archive member paths."""

    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return bool(name) and "\x00" not in name and not path.is_absolute() and not re.match(
        r"^[A-Za-z]:", normalized
    ) and ".." not in path.parts


def _inspect_office(data: bytes, expected: str) -> tuple[bool, str | None, str]:
    """Validate an OOXML container without extracting it to disk."""

    if data.startswith(OLE_HEADER):
        return False, None, "Legacy, macro-enabled, or encrypted Office containers are not supported."
    if not data.startswith(b"PK"):
        return False, None, "The file header does not match an Open XML Office document."

    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ZIP_ENTRIES:
                return False, None, "The Office archive has an unsafe number of entries."

            total_size = 0
            names: set[str] = set()
            for info in infos:
                if not _safe_zip_name(info.filename):
                    return False, None, "The Office archive contains a suspicious path."
                if info.flag_bits & 0x1:
                    return False, None, "Password-protected Office archives are not supported."
                total_size += info.file_size
                if total_size > MAX_TOTAL_UNCOMPRESSED:
                    return False, None, "The Office archive expands beyond the safety limit."
                if info.file_size and info.compress_size == 0:
                    return False, None, "The Office archive has a suspicious compression ratio."
                if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                    return False, None, "The Office archive has a suspicious compression ratio."
                names.add(info.filename.replace("\\", "/"))

            if archive.testzip() is not None:
                return False, None, "The Office archive is corrupted."
            if "[Content_Types].xml" not in names:
                return False, None, "The Office package is missing its content-type manifest."

            manifest = archive.read("[Content_Types].xml")
            if b"vbaProject" in manifest or any(
                name.lower().endswith("vbaproject.bin") for name in names
            ):
                return False, None, "Macro-enabled Office documents are not supported."

            detected = next(
                (kind for kind, marker in OOXML_CONTENT_TYPES.items() if marker.encode() in manifest),
                None,
            )
            if detected is None or OOXML_REQUIRED_PARTS[detected] not in names:
                return False, None, "The Office package type could not be verified."
            if detected != expected:
                return False, detected, f"The file is a {detected} document, not a {expected} document."
            return True, detected, "The Office container and declared document type are valid."
    except (zipfile.BadZipFile, RuntimeError, OSError, KeyError, ValueError):
        return False, None, "The Office archive is malformed, corrupted, or unreadable."


def _inspect_pdf(data: bytes) -> tuple[bool, str | None, str]:
    if not data.startswith(b"%PDF-"):
        return False, None, "The file header does not match a PDF document."
    try:
        with fitz.open(stream=data, filetype="pdf") as document:
            if document.needs_pass:
                return False, "PDF", "Password-protected or encrypted PDFs are not supported."
            # Force parsing of the page tree so truncated files are not accepted on header alone.
            _ = document.page_count
            if not document.is_pdf:
                return False, None, "The uploaded data is not a valid PDF document."
        return True, "PDF", "The PDF structure is valid and is not password-protected."
    except (fitz.FileDataError, RuntimeError, ValueError, OSError):
        return False, "PDF", "The PDF is malformed, corrupted, or unreadable."


def validate_file(data: bytes, filename: str) -> ValidationResult:
    """Validate an uploaded file using its name, signature, and container structure."""

    size = len(data) if isinstance(data, bytes) else 0
    if not isinstance(data, bytes):
        return _result(False, None, size, "The upload must be provided as bytes.")
    if size == 0:
        return _result(False, None, 0, "The uploaded file is empty.")
    if size > MAX_FILE_SIZE:
        return _result(False, None, size, "The file exceeds the 20 MB upload limit.")

    extension = Path(filename).suffix.lower()
    expected = ALLOWED_EXTENSIONS.get(extension)
    if expected is None:
        return _result(False, None, size, "Unsupported file extension. Use PDF, DOCX, or PPTX.")

    valid, detected, reason = (
        _inspect_pdf(data) if expected == "PDF" else _inspect_office(data, expected)
    )
    return _result(valid, detected, size, reason)

