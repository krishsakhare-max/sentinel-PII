"""Offline, non-sensitive pre-demo environment diagnostic."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import sys

import spacy.util

from extraction.ocr import configure_tesseract


REQUIRED = {
    "streamlit": "1.50.0", "PyMuPDF": "1.26.5", "python-docx": "1.2.0",
    "python-pptx": "1.0.2", "pytesseract": "0.3.13", "Pillow": "11.0.0",
    "presidio-analyzer": "2.2.364", "spacy": "3.8.16", "plotly": "6.3.1",
    "pytest": "8.4.2",
}


def main() -> int:
    failures: list[str] = []
    print(f"Python: {sys.version.split()[0]}")
    if sys.version_info[:2] != (3, 12):
        failures.append("Python 3.12 is required for the verified demo environment.")
    for package, expected in REQUIRED.items():
        try:
            installed = version(package)
        except PackageNotFoundError:
            installed = "MISSING"
        state = "OK" if installed == expected else "CHECK"
        print(f"{state}: {package} {installed} (expected {expected})")
        if installed != expected:
            failures.append(f"{package} version mismatch or missing.")
    model_ready = spacy.util.is_package("en_core_web_sm")
    print(f"{'OK' if model_ready else 'CHECK'}: spaCy en_core_web_sm")
    if not model_ready:
        failures.append("spaCy en_core_web_sm is unavailable.")
    ocr = configure_tesseract()
    print(f"{'OK' if ocr.available and ocr.english_available else 'CHECK'}: OCR — {ocr.reason}")
    if not ocr.available or not ocr.english_available:
        failures.append(ocr.reason)

    project = Path(__file__).resolve().parent
    documents = {
        "Risk Policy PDF": project / "sample_documents" / "Cadence_Group_Risk_Management_Policy__v6.0.pdf",
        "TPRM DOCX": project / "sample_documents" / "Cadence_TPRM_Training.docx",
    }
    pptx_name = "Cadence_Financial_Group_Organizational_Pack.pptx"
    pptx_candidates = [project / "sample_documents" / pptx_name,
                       Path.home() / "OneDrive" / "Desktop" / pptx_name,
                       Path.home() / "Downloads" / pptx_name]
    documents["Organizational PPTX"] = next((path for path in pptx_candidates if path.is_file()), pptx_candidates[0])
    for label, path in documents.items():
        print(f"{'OK' if path.is_file() else 'OPTIONAL MISSING'}: {label}")
    if failures:
        print("Diagnostic failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("Environment ready for local demo preparation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
