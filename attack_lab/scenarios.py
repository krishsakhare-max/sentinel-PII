"""Static scenario definitions; outcomes are never stored here."""

SCENARIO_ORDER = (
    "ordinary_pii",
    "obfuscated_email",
    "split_shape_name",
    "scanned_phone",
    "false_positive_trap",
    "incomplete_extraction",
)

SCENARIO_METADATA = {
    "ordinary_pii": (
        "Ordinary personal information", "Detect and sanitize ordinary direct identifiers.", "DOCX", "Baseline",
    ),
    "obfuscated_email": (
        "Obfuscated email", "Challenge normalized email detection and downstream leakage controls.", "DOCX", "Evasion",
    ),
    "split_shape_name": (
        "Split name across shapes", "Test identity reconstruction across independent PowerPoint blocks.", "PPTX", "Cross-block",
    ),
    "scanned_phone": (
        "Scanned phone number", "Test image-only OCR, detection, redaction, and release.", "PDF", "OCR",
    ),
    "false_positive_trap": (
        "False-positive trap", "Measure unnecessary detection and destructive over-redaction.", "DOCX", "Precision",
    ),
    "incomplete_extraction": (
        "Incomplete extraction", "Confirm unresolved image content propagates PARTIAL and BLOCKED.", "DOCX", "Fault injection",
    ),
}
