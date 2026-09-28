from pathlib import Path
import re

from Models.Finding import Finding


class APIBreaker:

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()

    def is_relevant_file(self, file_path: Path):
        path = str(
            file_path.relative_to(self.project_path)
        ).lower()

        keywords = {
            "api",
            "route",
            "server",
            "backend",
            "app",
            "controller",
            "endpoint",
        }

        return any(
            keyword in path
            for keyword in keywords
        )

    def contains_protection(self, content: str):
        protection_patterns = [
            r"\bauthori[sz]e\b",
            r"\bauthori[sz]ation\b",
            r"\bauthenticate\b",
            r"\bauthentication\b",
            r"\brequireauth\b",
            r"\brequire_auth\b",
            r"\bverifytoken\b",
            r"\bverify_token\b",
            r"\bverifyjwt\b",
            r"\bverify_jwt\b",
            r"\bmiddleware\b",
            r"\bisAdmin\b",
            r"\bis_admin\b",
            r"\bpermission\b",
            r"\bpermissions\b",
            r"\brole\b",
        ]

        for pattern in protection_patterns:
            if re.search(
                pattern,
                content,
                re.IGNORECASE
            ):
                return True

        return False

    def find_routes(self, content: str):
        route_pattern = (
            r"(app\.(get|post|put|patch|delete)"
            r"|router\.(get|post|put|patch|delete)"
            r"|@app\.(get|post|put|patch|delete)"
            r"|@router\.(get|post|put|patch|delete)"
            r"|export\s+(async\s+)?function\s+"
            r"(GET|POST|PUT|PATCH|DELETE))"
        )

        return list(
            re.finditer(
                route_pattern,
                content,
                re.IGNORECASE
            )
        )

    def is_sensitive_route(self, content: str, route_match):
        start = route_match.start()

        line_start = content.rfind(
            "\n",
            0,
            start
        ) + 1

        line_end = content.find(
            "\n",
            start
        )

        if line_end == -1:
            line_end = len(content)

        line = content[line_start:line_end]

        sensitive_keywords = [
            "admin",
            "user",
            "users",
            "account",
            "accounts",
            "payment",
            "payments",
            "order",
            "orders",
            "customer",
            "customers",
            "profile",
            "profiles",
            "database",
            "db",
            "internal",
            "private",
            "secret",
        ]

        return any(
            keyword in line.lower()
            for keyword in sensitive_keywords
        )

    def scan_file(self, file_path: Path):
        findings = []

        try:
            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore"
            )
        except OSError:
            return findings

        routes = self.find_routes(content)

        if not routes:
            return findings

        for route in routes:

            if not self.is_sensitive_route(
                content,
                route
            ):
                continue

            # Look for protection in the surrounding file.
            if self.contains_protection(content):
                continue

            line_number = (
                content[:route.start()]
                .count("\n")
                + 1
            )

            relative_file = str(
                file_path.relative_to(
                    self.project_path
                )
            )

            findings.append(
                Finding(
                    agent="APIBreaker",
                    title=(
                        "Potential sensitive API "
                        "endpoint exposure"
                    ),
                    severity="MEDIUM",
                    confidence=0.65,
                    file=relative_file,
                    line=line_number,
                    evidence=(
                        "A potentially sensitive API "
                        "route was detected without "
                        "an obvious protection mechanism "
                        "in the file."
                    ),
                    explanation=(
                        "The endpoint appears to expose "
                        "a potentially sensitive resource. "
                        "The scan did not identify an "
                        "obvious authentication or "
                        "authorization mechanism in the "
                        "same file."
                    ),
                    recommendation=(
                        "Verify that the endpoint requires "
                        "appropriate authentication and "
                        "authorization before exposing "
                        "sensitive data or operations."
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

            relative_parts = (
                path.relative_to(
                    self.project_path
                ).parts
            )

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

    breaker = APIBreaker(".")

    findings = breaker.scan()

    print("\nAPI BREAKER")
    print("=" * 40)

    if not findings:

        print(
            "\nNo potential API exposure "
            "issues found."
        )

    else:

        print(
            f"\nPotential findings: "
            f"{len(findings)}\n"
        )

        for finding in findings:

            print(
                f"[{finding.severity}] "
                f"{finding.title}"
            )

            print(
                f"Agent: "
                f"{finding.agent}"
            )

            print(
                f"Location: "
                f"{finding.file}:"
                f"{finding.line}"
            )

            print(
                f"Confidence: "
                f"{finding.confidence}"
            )

            print(
                f"Evidence: "
                f"{finding.evidence}\n"
            )