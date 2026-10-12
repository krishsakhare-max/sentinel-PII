# PII Sentinel

**Know What AI Sees**

PII Sentinel is a local-first privacy gateway. Phase 2 validates and extracts
native and image-based content from PDF, DOCX, and PPTX documents. It does not
yet detect or redact PII, calculate risk, or send content to an AI endpoint.

Phase 2.1 adds extraction accuracy tests, mixed native/image PDF handling,
two-column ordering, vector-image OCR, processing progress, and a deliberately
partial PDF page-range demonstration mode.

Phase 3 adds local hybrid PII detection with Microsoft Presidio, spaCy,
context-aware regular expressions, exact block-relative offsets, and measured
synthetic accuracy. Detection does not redact or authorize document release.

Phase 4 adds exact-offset typed redaction, sanitized structured-text
serialization, independent residual scanning, a fail-closed security gate, a
local mock AI boundary, and safe privacy release receipts. It does not provide
risk scoring or claim that a clean scan proves universal privacy safety.

Phase 5 adds a premium enterprise Streamlit control center around those proven
workflows: live session metrics, an activity ledger, a focused document
analyzer, a side-by-side privacy preview, and clear roadmap-only states for
future risk and attack-lab modules. Dashboard values come from the current
local session; no sample security statistics are preloaded.

Phase 5.1 consolidates the product workflow behind one testable
Validate → Extract → Detect → Redact → Verify → Gate operation. It adds
document-wide repeated-value protection, boundary-aware leakage verification,
aligned original/sanitized block inspection, prominent fail-closed decisions,
and raw-PII-free receipt export. Individual controls remain available under
Advanced for debugging.

Phase 6 activates local Risk Intelligence. It calculates an explainable
potential original-data exposure score from documented project weights,
in-memory distinct-value counts, and conservative structured-record linkage.
It keeps exposure, sanitized verification, and release authority separate and
produces condition-specific recommendations plus aggregate, raw-PII-free JSON
reports. The score is neither a breach probability nor a security-gate input.

Phase 7 activates the local Privacy Attack Lab. Six entirely synthetic DOCX,
PPTX, and image-only PDF fixtures run through the same production validation,
extraction, detection, redaction, verification, gate, and mock-AI boundary as
uploaded documents. An independent evaluator compares results with ground truth
defined before detection and reports detection, containment, and usability as
separate outcomes.

## Requirements

- Python 3.12.3
- Tesseract OCR with English language data. On Windows, the application checks
  both `PATH` and `C:\Program Files\Tesseract-OCR\tesseract.exe`.

## Setup

From the `pii-sentinel` directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

On macOS or Linux, activate with `source .venv/bin/activate` instead.

## Run

```powershell
python -m streamlit run app.py
```

Streamlit prints the local address, normally `http://localhost:8501`.

Before a live demonstration, verify the offline environment and create ignored
synthetic demo inputs:

```powershell
python demo_prepare.py
```

Final architecture, verified results, demo steps, and interview preparation are
in [`docs/`](docs/).

## Test

```powershell
python -m pytest
```

Tests construct synthetic files in memory; no external or real-person documents
are used.

## Current capabilities

- Accepts uploads up to 20 MB with `.pdf`, `.docx`, or `.pptx` extensions.
- Parses PDFs with PyMuPDF and rejects password-protected or malformed PDFs.
- Inspects Office ZIP containers in memory without extracting files to disk.
- Distinguishes DOCX from PPTX using Open XML content types and required parts.
- Rejects path traversal, excessive expansion, extreme compression ratios,
  encrypted ZIP entries, corruption, and macro-enabled Office packages.
- Returns a small structured result safe to display in the interface.
- Extracts ordered PDF text blocks with page numbers and bounding boxes.
- OCRs scanned or sparse PDF pages locally using Tesseract.
- Extracts DOCX paragraphs, ordered tables, headers, footers, and image text.
- Extracts PPTX text, tables, grouped shapes, chart labels, notes, and image text.
- Reports unreadable pages, blank OCR results, and unsupported content as
  extraction warnings rather than silently declaring extraction complete.
- Caches results by document hash and selected range during the Streamlit
  session, avoiding repeated OCR after normal interface reruns.
- Offers a **Selected Pages Demo** for PDF page ranges. Its result is always
  marked PARTIAL and must never be used as a full-document release decision.
- Detects supported PII categories locally and shows masked, filterable,
  source-traceable findings. Recognition scores are not accuracy probabilities.
- Replaces detected spans with deterministic typed placeholders, verifies the
  exact serialized payload, and blocks partial or unresolved documents.
- Presents extraction, detection, redaction, verification, and release state in
  five clearly separated enterprise workflow views.
- Keeps Risk Intelligence and Privacy Attack Lab visibly disabled rather than
  representing unimplemented capabilities as active controls.
- Runs the complete privacy gateway from a single **Analyze & Secure Document**
  action with stage-level progress and safe early termination.
- Aligns original and sanitized preview panels to the same source block and
  labels blocked candidates as not authorized for AI.
- Explains original-data exposure using `min(100, 12S + 5V + 15L)` and displays
  the underlying weights, capped volume, linkage decision, and category counts.
- Generates deterministic recommendations from detected categories, extraction
  completeness, residual findings, verification, and the actual gate decision.
- Runs six real adversarial scenarios: ordinary identifiers, bracket-obfuscated
  email, a name split across PowerPoint shapes, an OCR-only phone number, a
  false-positive trap, and a simulated OCR outage that forces partial extraction.
- Evaluates the exact approved payload against independent transient synthetic
  values, including normalized obfuscated email and cross-block composite names.

## Privacy Attack Lab

Ground truth is stored separately from detector findings and contains only
synthetic identifiers. Fixtures are generated in memory and never use Cadence
or other confidential values. The incomplete-extraction scenario uses a real
embedded text image with a clearly labeled simulated OCR-unavailable status;
the production extractor and fail-closed gate still determine its outcome.

Lab outcomes have different meanings:

- **Detection** measures whether expected entities were actually recognized.
- **Containment PASS** means no independently known PII reached an accepted
  payload, or a blocked candidate was rejected by the mock boundary.
- **Usability** measures preservation of safe context and unnecessary redaction.
- **FAIL** identifies measured leakage, authorization bypass, or quality loss.
- **ERROR** means execution did not produce evaluable evidence.
- **INCONCLUSIVE** is used when a designed failure prevents a complete quality
  conclusion; it is never converted to PASS.

Run the automated laboratory regression with:

```powershell
python -m pytest testing/test_attack_lab.py
```

The Attack Lab is a limited adversarial regression harness, not a penetration-
testing certification or proof of exhaustive privacy protection.

## Known limitations

- Structural validation and extraction are not malware scanning, PII detection,
  sanitization, or proof that a file is safe or PII-free.
- The validator does not recursively inspect embedded objects or detect every
  possible malicious document technique.
- OOXML signatures are not cryptographically authenticated.
- The 100 MB uncompressed archive limit and 200:1 per-entry ratio are defensive
  policy limits and may reject unusual but legitimate documents.
- Legacy Office (`.doc`, `.ppt`), macro-enabled formats, and encrypted documents
  are deliberately unsupported.
- OCR quality depends on scan resolution, orientation, fonts, and image quality.
- Some advanced Office objects, diagrams, and embedded packages cannot be fully
  interpreted and are reported for review.
- The optional spaCy language model improves name recognition when installed;
  the local detection pipeline reports its actual engine status.
- Risk Intelligence and Privacy Attack Lab remain intentionally unimplemented.
