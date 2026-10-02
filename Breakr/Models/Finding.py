from dataclasses import dataclass


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

    def to_dict(self):
        return {
            "agent": self.agent,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
        }