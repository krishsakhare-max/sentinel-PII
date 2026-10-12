"""Defensible custom patterns and context assumptions for PII Sentinel."""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


CONTEXT_LABELS = {
    "name", "employee", "contact", "officer", "manager", "approved by", "policy owner",
    "email", "phone", "mobile", "telephone", "employee id", "staff id", "date of birth",
    "dob", "born", "social security", "ssn", "tax id", "bank account", "account number", "iban",
    "address", "location",
}

CONTEXT_REQUIRED = {"GOVERNMENT_ID", "BANK_ACCOUNT", "DATE_OF_BIRTH"}


def custom_recognizers() -> list[PatternRecognizer]:
    """Return recognizers with conservative formats and documented context."""

    return [
        PatternRecognizer(
            supported_entity="EMPLOYEE_ID",
            name="EmployeeIdRecognizer",
            patterns=[Pattern("employee-id", r"\b(?:EMP|EID|STAFF)[-_ ]?\d{3,10}\b", 0.78)],
            context=["employee", "staff", "personnel", "id"],
        ),
        PatternRecognizer(
            supported_entity="GOVERNMENT_ID",
            name="GovernmentIdRecognizer",
            # Phase 3 supports US SSN-style identifiers only and requires context.
            patterns=[Pattern("us-ssn-format", r"\b\d{3}-\d{2}-\d{4}\b", 0.35)],
            context=["ssn", "social security", "government id", "tax id"],
        ),
        PatternRecognizer(
            supported_entity="BANK_ACCOUNT",
            name="BankAccountRecognizer",
            # Broad digit lengths are accepted only when an account label is nearby.
            patterns=[Pattern("labelled-bank-account", r"\b\d{8,17}\b", 0.25)],
            context=["bank", "account", "account number", "iban", "routing"],
        ),
        PatternRecognizer(
            supported_entity="DATE_OF_BIRTH",
            name="DateOfBirthRecognizer",
            patterns=[
                Pattern("dob-numeric", r"\b(?:0?[1-9]|[12]\d|3[01])[/-](?:0?[1-9]|1[0-2])[/-](?:19|20)\d{2}\b", 0.3),
                Pattern("dob-iso", r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b", 0.3),
            ],
            context=["date of birth", "dob", "born", "birth date"],
        ),
    ]

