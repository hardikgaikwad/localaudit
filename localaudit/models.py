"""Core data types shared across LocalAudit."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITIES))}  # info=0 ... critical=4


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]


def validate_severity(value: str) -> str:
    value = value.lower()
    if value not in SEVERITY_RANK:
        raise ValueError(f"unknown severity {value!r}; expected one of {', '.join(SEVERITIES)}")
    return value


@dataclass
class Triage:
    """LLM output for one finding. `available=False` means triage was not performed."""

    available: bool = False
    explanation: str = ""
    risk_in_context: str = ""
    likely_false_positive: bool = False
    confidence: str = ""
    suggested_fix: str = ""
    fixed_code_example: str = ""
    note: str = ""  # e.g. "LLM triage unavailable"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    snippet: str  # the line plus up to 3 lines of context either side, secrets masked
    match: str  # matched text, secrets masked
    snippet_start: int = 1  # line number of the first snippet line
    description: str = ""
    cwe: Optional[str] = None
    id: str = ""
    triage: Triage = field(default_factory=Triage)

    def __post_init__(self) -> None:
        if not self.id:
            digest = hashlib.sha1(f"{self.rule_id}|{self.file}|{self.line}|{self.match}".encode()).hexdigest()
            self.id = f"LA-{digest[:10]}"

    @property
    def likely_false_positive(self) -> bool:
        return self.triage.available and self.triage.likely_false_positive

    def to_dict(self) -> dict:
        return asdict(self)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.file, f.line, f.rule_id))
