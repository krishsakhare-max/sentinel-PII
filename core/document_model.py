"""Shared document representations used by future PII Sentinel phases.

Phase 1 defines these types only. File validation does not populate document
blocks and must not be interpreted as content extraction or a PII safety check.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class DocumentBlock:
    """One logical unit extracted from a document in a future phase."""

    block_id: str
    block_type: str
    text: str
    source_location: str
    extraction_status: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DocumentResult:
    """The normalized result of a future document extraction operation."""

    document_id: str
    filename: str
    file_type: str
    blocks: list[DocumentBlock] = field(default_factory=list)
    extraction_complete: bool = False
    extraction_warnings: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        """Return extracted block text in document order."""

        return "\n".join(block.text for block in self.blocks if block.text.strip())

