# PII Sentinel Architecture

Verified 2026-10-11. PII Sentinel is a local competition prototype, not a
production certification or malware scanner.

## Dataflow

```text
Upload bytes
  → structural validation
  → format router
  → native extraction and local OCR
  → normalized DocumentBlock objects
  → Presidio + spaCy + contextual regex detection
  → repeated-value consistency pass
  → exact-offset redaction
  → safe structured serialization
  → independent residual and known-value verification
  → fail-closed release gate
  → ApprovedPayload
  → local mock AI only
```

Risk Intelligence reads extraction, detection, verification, and gate evidence
but cannot change the gate. Privacy Attack Lab creates synthetic documents,
runs this same production dataflow, and compares the candidate or approved
payload with independently defined ground truth.

## Responsibilities

- `core/validator.py`: true-type and defensive PDF/OOXML validation.
- `extraction/`: ordered PDF, DOCX, PPTX, and Tesseract extraction.
- `privacy/detector.py`: hybrid recognition and conservative repeated-value pass.
- `privacy/span_resolver.py`: deterministic overlap resolution.
- `privacy/redactor.py`: exact offsets, typed placeholders, safe serialization.
- `privacy/verifier.py`: extraction coverage, content integrity, known-value
  leakage, residual rescan, and serializer equality.
- `core/security_gate.py`: creates an approved payload only when every required
  check succeeds.
- `core/mock_ai.py`: independently checks decision, hash, document identity,
  and verification identity before accepting sanitized content.
- `intelligence/`: original-exposure scoring and deterministic recommendations.
- `attack_lab/`: synthetic fixtures, isolated execution, and independent truth
  evaluation.
- `reporting/`: aggregate release receipt with no raw source text.
- `app.py`: Streamlit presentation and session-local caches.

## Trust boundaries

Uploaded bytes, extracted text, findings, and original previews remain inside
the trusted local process and Streamlit session. Only the exact serialized
sanitized payload can become an `ApprovedPayload`. Reports contain hashes,
counts, categories, statuses, and reasons—not raw PII. No external document or
AI service is called.

Session caches use full SHA-256 content identity plus processing scope. A new
upload invalidates the selected document state. Streamlit session state is not
shared across browser sessions; synthetic fixture definitions may be process-
cached because they contain no confidential values.

## Fail-closed gateway

Release is blocked for validation failure, selected-page processing, incomplete
extraction, incomplete detection coverage, redaction failure, count mismatch,
verification failure, residual PII, or payload hash mismatch. The mock boundary
then revalidates the hash and binds the payload to the gate's document and
verification identifiers. Exposure scores never authorize release.
