# Technical Interview Q&A

## 1. Why combine Presidio, spaCy, and regex?

Presidio coordinates recognizers, spaCy finds contextual entities such as
people and locations, and regex provides deterministic handling for structured
identifiers. Their errors differ, so the combination improves coverage.

## 2. Why is OCR separate from PII detection?

OCR recovers characters from pixels; it does not decide whether those
characters are sensitive. OCR confidence and detection correctness are reported
as different measurements.

## 3. How are source offsets preserved?

Every finding references one immutable extracted block and exact block-relative
start/end offsets. Redaction validates that reference before replacing spans.

## 4. How are overlapping findings handled?

A deterministic resolver applies entity precedence and span rules before
redaction. Replacements occur right-to-left so earlier offsets remain valid.

## 5. How do you avoid missing repeated names?

After initial detection, a conservative consistency pass searches other blocks
for exact boundary-aware occurrences of already established multi-token values.
It does not globally replace short or previously unknown words.

## 6. What prevents raw PII from reaching AI?

Only the sanitized serializer output can become an `ApprovedPayload`. The gate
requires complete extraction, detection coverage, exact redaction, independent
verification, no residual findings, and matching hashes.

## 7. Why rescan after redaction?

Exact replacement proves known spans changed; rescanning can find different or
previously hidden recognized PII. Known-value comparison adds another independent
check because a clean residual detector is not proof of no leakage.

## 8. What does fail-closed mean here?

Any missing evidence, partial extraction, failed check, residual finding, or
payload mismatch produces BLOCKED. The mock boundary separately verifies the
decision, hash, document identity, and verification identity.

## 9. Can a high risk score block or approve a document?

No. Risk describes potential exposure in the original document. Verification
describes the sanitized output, and only the security gate authorizes release.

## 10. How is the risk score calculated?

`min(100, 12S + 5V + 15L)`: maximum sensitivity, capped distinct-value volume,
and conservative structured-record linkage. Weights are disclosed assumptions,
not probabilities or official policy.

## 11. What is independent ground truth?

Attack fixtures declare expected synthetic values and categories before the
detector runs. Evaluation compares predictions and the exact eligible payload
against those declarations rather than deriving truth from detector output.

## 12. What happened with obfuscated email?

The first adversarial run found approved leakage for bracketed `[at]` and
`[dot]`. A narrow recognizer fixed it, negative prose tests limited false
positives, and an intentional leakage regression keeps the evaluator honest.

## 13. What remains limited about split PowerPoint names?

The detector does not create a cross-shape identity graph. The Lab reports the
composite PERSON miss even when removing one component prevents reconstruction;
containment PASS is not relabeled as detection success.

## 14. How do you control false positives?

Context requirements, negative fixtures, boundary-aware propagation, explicit
ground truth, and usability measurements expose over-redaction. Recognition
scores are not presented as accuracy probabilities.

## 15. How is cache isolation handled?

Session keys use full SHA-256 content identity plus processing scope. New
uploads clear the current selection, and selected-page results have distinct,
non-releasable keys.

## 16. Why is the PDF not used live?

Its final measured runtime was 177.54 seconds. The demo uses small fixtures and
the 17.48-second PPTX, while the dated PDF result remains documented evidence.

## 17. Does the application upload files externally?

No. Parsing, OCR, NLP, risk scoring, attacks, and the mock AI run locally after
dependencies are installed. There are no external AI calls.

## 18. What would change for production?

Use authenticated users, encrypted storage, process isolation, malware scanning,
audited model/version governance, secure secrets, retention policies, stronger
observability without raw content, accessibility testing, and formal threat and
privacy impact assessments.
