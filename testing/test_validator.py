"""Synthetic security tests for the Phase 1 upload validator."""

from io import BytesIO
import zipfile

import fitz
import pytest

from core.validator import MAX_FILE_SIZE, validate_file


CONTENT_TYPES = {
    "DOCX": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "PPTX": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
}
MAIN_PARTS = {"DOCX": "word/document.xml", "PPTX": "ppt/presentation.xml"}


def make_pdf(*, encrypted: bool = False) -> bytes:
    document = fitz.open()
    document.new_page()
    options = {}
    if encrypted:
        options = {
            "encryption": fitz.PDF_ENCRYPT_AES_256,
            "owner_pw": "synthetic-owner-password",
            "user_pw": "synthetic-user-password",
        }
    data = document.tobytes(**options)
    document.close()
    return data


def make_office(kind: str, *, extra_entries: dict[str, bytes] | None = None) -> bytes:
    output = BytesIO()
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f'<Override PartName="/{MAIN_PARTS[kind]}" ContentType="{CONTENT_TYPES[kind]}"/>'
        "</Types>"
    ).encode()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", manifest)
        archive.writestr(MAIN_PARTS[kind], b"<?xml version='1.0'?><root/>")
        archive.writestr("_rels/.rels", b"<?xml version='1.0'?><Relationships/>")
        for name, content in (extra_entries or {}).items():
            archive.writestr(name, content)
    return output.getvalue()


def test_valid_pdf() -> None:
    result = validate_file(make_pdf(), "sample.pdf")
    assert result.is_valid
    assert result.detected_format == "PDF"


@pytest.mark.parametrize("kind,filename", [("DOCX", "sample.docx"), ("PPTX", "sample.pptx")])
def test_valid_office_documents(kind: str, filename: str) -> None:
    result = validate_file(make_office(kind), filename)
    assert result.is_valid
    assert result.detected_format == kind


def test_unsupported_extension() -> None:
    result = validate_file(b"plain synthetic text", "sample.txt")
    assert not result.is_valid
    assert "Unsupported" in result.reason


def test_empty_file() -> None:
    result = validate_file(b"", "empty.pdf")
    assert not result.is_valid
    assert result.file_size == 0


def test_file_larger_than_20_mb() -> None:
    result = validate_file(b"x" * (MAX_FILE_SIZE + 1), "oversized.pdf")
    assert not result.is_valid
    assert "20 MB" in result.reason


def test_extension_header_mismatch() -> None:
    result = validate_file(make_pdf(), "disguised.docx")
    assert not result.is_valid
    assert result.detected_format is None


def test_corrupted_office_file() -> None:
    result = validate_file(b"PK\x03\x04truncated synthetic archive", "broken.docx")
    assert not result.is_valid
    assert "malformed" in result.reason.lower()


@pytest.mark.parametrize(
    "actual,filename,detected", [("DOCX", "renamed.pptx", "DOCX"), ("PPTX", "renamed.docx", "PPTX")]
)
def test_renamed_office_format(actual: str, filename: str, detected: str) -> None:
    result = validate_file(make_office(actual), filename)
    assert not result.is_valid
    assert result.detected_format == detected
    assert "not a" in result.reason


@pytest.mark.parametrize("path", ["../escape.xml", "/absolute.xml", "C:/drive.xml", "safe/../../escape.xml"])
def test_suspicious_zip_entry(path: str) -> None:
    result = validate_file(make_office("DOCX", extra_entries={path: b"synthetic"}), "unsafe.docx")
    assert not result.is_valid
    assert "suspicious path" in result.reason


def test_password_protected_pdf() -> None:
    result = validate_file(make_pdf(encrypted=True), "protected.pdf")
    assert not result.is_valid
    assert result.detected_format == "PDF"
    assert "password" in result.reason.lower() or "encrypted" in result.reason.lower()


def test_macro_enabled_office_package() -> None:
    result = validate_file(
        make_office("DOCX", extra_entries={"word/vbaProject.bin": b"synthetic macro bytes"}),
        "macro.docx",
    )
    assert not result.is_valid
    assert "Macro-enabled" in result.reason


def test_corrupted_pdf() -> None:
    result = validate_file(b"%PDF-1.7\nnot a real PDF", "broken.pdf")
    assert not result.is_valid

