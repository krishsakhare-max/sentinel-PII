# PII Sentinel Demo Guide

Target duration: **2–3 minutes**. Do not process the 35-page policy PDF live.

## Prepare before presentation

```powershell
cd "C:\Users\panka\OneDrive\Desktop\New folder (2)\pii-sentinel"
python demo_prepare.py
python -m pytest -q
python -m streamlit run app.py
```

`demo_prepare.py` verifies pinned packages, spaCy, Tesseract English data, and
demo-document availability. It creates two synthetic files under ignored
`demo_cache/` and prints their full SHA-256 hashes.

In the opened app, run **Privacy Attack Lab → Ordinary personal information**
once. This is a genuine run and warms Presidio/spaCy inside the Streamlit
process. Leave that browser session open. Cached labels mean a result came from
an earlier real execution of the same scenario; reload/restart Streamlit to
force a fresh lab session.

## Live sequence

1. **Command Center — 10 seconds**
   - Explain that session metrics start empty and are never seeded.
   - State the rule: extraction is evidence, not release approval.

2. **Document Analyzer — 35 seconds**
   - Upload `demo_cache/attack-ordinary.docx`.
   - Click **Analyze & Secure Document**.
   - Show six completed stages, masked findings, APPROVED decision, and counts.

3. **Privacy Preview — 25 seconds**
   - Select the same source block on both sides.
   - Show highlighted original data and typed placeholders.
   - Show the release receipt and the enabled local mock-AI action.

4. **Cadence Organizational PPTX — 35 seconds**
   - Upload the locally available PPTX and run the same button.
   - Expected from the 2026-10-11 regression: COMPLETE, 120 findings and
     redactions, zero residual, PASSED, APPROVED, approximately 17.48 seconds.
   - If it was already processed in this browser session, disclose that the
     displayed result is the full-hash/scope cache from earlier actual work.
     Use Advanced Controls or restart the session when a fresh reprocess is needed.

5. **Blocked control — 15 seconds**
   - Open Attack Lab and run **Incomplete extraction**.
   - Show PARTIAL, BLOCKED, containment PASS, and mock-boundary rejection.

6. **Adversarial and risk evidence — 25 seconds**
   - Run **Obfuscated email** and show genuine SUCCESS/PASS/APPROVED evidence.
   - Open Risk Intelligence for the PPTX: exposure 61/100 High, verification
     PASSED, gate APPROVED. Explain that exposure does not authorize release.

## Fallbacks

- If OCR is slow, use the sub-second scanned-phone Lab fixture rather than the
  policy PDF or TPRM DOCX.
- If Tesseract fails the diagnostic, do not claim OCR readiness. Demonstrate the
  simulated incomplete-extraction block instead.
- If the PPTX is unavailable, continue with the synthetic approved fixture and
  quote the dated regression table in `docs/TEST_RESULTS.md` as earlier actual
  processing—not as a live result.
- If any expected state changes, show the actual state and stop release; never
  override or describe a BLOCKED result as approved.

## Manual visual checklist

At 1366×768 and 1920×1080 verify sidebar navigation, readable labels, decision
colors, unclipped tables, aligned preview panels, Risk Intelligence formula,
all six Attack Lab cards, loading states, and disabled mock-AI control when
blocked. Browser screenshot automation was unavailable during final review.
