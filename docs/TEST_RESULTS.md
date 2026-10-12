# Verified Test Results

Verification date: **2026-10-11**

## Automated verification

- pytest: **125 passed, 0 failed, 0 skipped**
- Python compilation: passed
- Streamlit AppTest routes: passed
- Streamlit HTTP health check: passed
- Environment diagnostic: passed
- Five non-failing SWIG deprecation warnings originate in installed dependencies.

## Privacy Attack Lab

| Scenario | Detection | Containment | Usability | Gate | Runtime |
|---|---|---|---|---|---:|
| Ordinary personal information | SUCCESS | PASS | PASS | APPROVED | 1.591s |
| Obfuscated email | SUCCESS | PASS | PASS | APPROVED | 0.191s |
| Split name across shapes | FAILED | PASS | FAIL | APPROVED | 0.179s |
| Scanned phone number | SUCCESS | PASS | PASS | APPROVED | 0.899s |
| False-positive trap | SUCCESS | PASS | PASS | APPROVED | 0.315s |
| Simulated incomplete extraction | FAILED | PASS | INCONCLUSIVE | BLOCKED | 0.069s |

Four scenarios achieved their defined detection objective. All six contained
the independently defined synthetic values. The split identity was not detected
as PERSON; reconstruction was prevented because one component was removed under
another classification. This is containment, not detection success. The OCR
phone scenario reported 95.38 mean Tesseract word confidence.

## Cadence document regression

| Document | Validation | Extraction | Findings | Redactions | Residual | Verification | Gate | Runtime |
|---|---|---|---:|---:|---:|---|---|---:|
| Organizational PPTX | PASS | COMPLETE | 120 | 120 | 0 | PASSED | APPROVED | 17.48s |
| Risk Policy PDF | PASS | COMPLETE | 1,065 | 1,065 | 23 | FAILED | BLOCKED | 177.54s |
| TPRM DOCX | PASS | PARTIAL | 978 | 978 | 18 | FAILED | BLOCKED | 110.42s |

The PDF failed `payload_has_no_known_raw_spans` and `no_residual_pii`. The DOCX
also failed `extraction_complete` and retains one unresolved embedded-image OCR
warning. Confidential values were not logged or written to reports.

## Known limitations

- NLP and OCR can produce false positives and false negatives.
- Cross-shape composite PERSON detection remains limited.
- Six attacks are regression evidence, not exhaustive assurance.
- Risk weights are project assumptions, not breach probabilities or policy.
- Selected-page results are always partial and non-releasable.
- Structural validation is not antivirus or full malicious-document analysis.
- Streamlit is suitable for this local prototype, not multi-tenant production.
