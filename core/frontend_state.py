"""Deterministic presentation helpers kept independent of Streamlit widgets."""

from __future__ import annotations

import hashlib
import html
import re
from collections.abc import MutableMapping, Sequence

from core.document_model import DocumentBlock, DocumentResult
from core.security_gate import GateDecision
from privacy.redactor import RedactionResult


PLACEHOLDER = re.compile(
    r"\[(?:PERSON|EMAIL|PHONE|EMPLOYEE_ID|GOVERNMENT_ID|BANK_ACCOUNT|DOB|LOCATION)_\d+\]"
)


def analysis_cache_key(data: bytes, selected_pages: list[int] | None = None) -> str:
    digest = hashlib.sha256(data).hexdigest()
    scope = "full" if selected_pages is None else f"pages-{selected_pages[0]}-{selected_pages[-1]}"
    return f"{digest}:{scope}"


def escape_display(value: object) -> str:
    """Escape untrusted display values before scoped HTML rendering."""

    return html.escape(str(value), quote=True)


def activate_upload(state: MutableMapping, digest: str) -> bool:
    """Switch active input and invalidate only document-specific selection."""

    changed = state.get("active_upload_digest") != digest
    if changed:
        state["active_upload_digest"] = digest
        state.pop("current_record_key", None)
    return changed


def decision_presentation(decision: GateDecision | None) -> tuple[str, str]:
    if decision is None:
        return "PENDING", "PENDING — Verification not completed"
    if decision.decision == "APPROVED":
        return "APPROVED", "APPROVED — Sanitized content eligible for local mock AI"
    return "BLOCKED", "BLOCKED — Review required"


def aligned_preview_blocks(
    original: DocumentResult, redaction: RedactionResult, block_id: str
) -> tuple[DocumentBlock, DocumentBlock]:
    originals = {block.block_id: block for block in original.blocks}
    sanitized = {block.block_id: block for block in redaction.blocks}
    if block_id not in originals or block_id not in sanitized:
        raise KeyError("The selected block is unavailable in one preview panel.")
    return originals[block_id], sanitized[block_id]


def highlighted_text(text: str, spans: Sequence[tuple[int, int]], css_class: str) -> str:
    """Return escaped markup with non-overlapping exact-offset highlights."""

    parts: list[str] = []
    cursor = 0
    for start, end in sorted(spans):
        if start < cursor or start < 0 or end > len(text) or start >= end:
            continue
        parts.append(html.escape(text[cursor:start]))
        parts.append(f'<mark class="{css_class}">{html.escape(text[start:end])}</mark>')
        cursor = end
    parts.append(html.escape(text[cursor:]))
    return "".join(parts).replace("\n", "<br>")


def highlighted_placeholders(text: str) -> str:
    return highlighted_text(text, [match.span() for match in PLACEHOLDER.finditer(text)], "ps-placeholder")
