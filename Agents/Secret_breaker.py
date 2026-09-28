from pathlib import Path
import re

from Models.Finding import Finding


class SecretBreaker:

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()

    def scan_file(self, file_path: Path):
        findings = []

        try:
            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore"
            )
        except OSError:
            return findings

        patterns = {
            "Potential API Key": r'(?i)(api[_-]?key)\s*[:=]\s*["\'][^"\']+["\']',

            "Potential Secret": r'(?i)(secret[_-]?key)\s*[:=]\s*["\'][^"\']+["\']',

            "Potential Password": r'(?i)(password|passwd)\s*[:=]\s*["\'][^"\']+["\']',

            "Potential Token": r'(?i)(token|auth[_-]?token)\s*[:=]\s*["\'][^"\']+["\']',
        }

        lines = content.splitlines()

        for line_number, line in enumerate(lines, start=1):

            for finding_type, pattern in patterns.items():

                if re.search(pattern, line):

                    findings.append(
                        Finding(
                            agent="SecretBreaker",
                            title=finding_type,
                            severity="HIGH",
                            confidence=0.85,
                            file=str(
                                file_path.relative_to(
                                    self.project_path
                                )
                            ),
                            line=line_number,
                            evidence=line.strip(),
                            explanation=(
                                "A hardcoded value was detected in "
                                "source code that may represent a "
                                "sensitive credential."
                            ),
                            recommendation=(
                                "Move the credential to a secure "
                                "environment variable or secret "
                                "manager and avoid exposing it "
                                "in client-side code."
                            ),
                        )
                    )

        return findings

    def scan(self):

        findings = []

        ignored_directories = {
            ".git",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            "env",
            ".next",
            "dist",
            "build",
        }

        for path in self.project_path.rglob("*"):

            if not path.is_file():
                continue

            relative_parts = path.relative_to(
                self.project_path
            ).parts

            if any(
                part in ignored_directories
                for part in relative_parts
            ):
                continue

            findings.extend(
                self.scan_file(path)
            )

        return findings


if __name__ == "__main__":

    breaker = SecretBreaker(".")

    findings = breaker.scan()

    print("\nSECRET BREAKER")
    print("=" * 40)

    if not findings:

        print("\nNo potential secrets found.")

    else:

        print(
            f"\nPotential findings: {len(findings)}\n"
        )

        for finding in findings:

            print(
                f"[{finding.severity}] "
                f"{finding.title} "
                f"{finding.file}:"
                f"{finding.line}"
            )

            print(
                f"Evidence: {finding.evidence}\n"
            )