from dataclasses import dataclass, asdict


# Most severe first. Used for sorting, filtering and exit codes.
SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
]


def severity_rank(severity: str) -> int:
    """
    Lower number = more severe.
    Unknown severities sort after INFO.
    """

    try:
        return SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return len(SEVERITY_ORDER)


@dataclass
class Finding:
    agent: str
    title: str
    severity: str
    confidence: float
    file: str
    line: int
    evidence: str
    explanation: str
    recommendation: str
    cwe: str = ""

    def to_dict(self):
        return asdict(self)

    def sort_key(self):
        return (
            severity_rank(self.severity),
            -self.confidence,
            self.file,
            self.line,
        )
