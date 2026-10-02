from pathlib import Path
import re

from Models.Finding import Finding


class AuthBreaker:

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()

    def is_relevant_file(self, file_path: Path):
        """
        Determine whether a file is likely related to
        authentication, authorization, admin functionality,
        or API routes.
        """

        path = str(
            file_path.relative_to(self.project_path)
        ).lower()

        keywords = {
            "admin",
            "auth",
            "login",
            "user",
            "account",
            "api",
            "route",
            "protected",
            "permission",
            "role",
        }

        return any(
            keyword in path
            for keyword in keywords
        )

    def contains_authorization_check(self, content: str):

        # Remove comments before searching for authorization logic.
        # This prevents comments such as:
        # "There is no authorization check"
        # from being treated as real security controls.

        content_without_comments = re.sub(
            r"#.*",
            "",
            content
        )

        authorization_patterns = [
            r"\brole\b",
            r"\bisAdmin\b",
            r"\bis_admin\b",
            r"\bpermission\b",
            r"\bauthori[sz]e\b",
            r"\bauthori[sz]ation\b",
            r"\bpermissions\b",
            r"\brequireAdmin\b",
            r"\brequire_admin\b",
            r"\bcheckRole\b",
            r"\bcheck_role\b",
            r"\bverifyRole\b",
            r"\bverify_role\b",
        ]

        for pattern in authorization_patterns:
            if re.search(
                pattern,
                content_without_comments,
                re.IGNORECASE
            ):
                return True

        return False

    def scan_file(self, file_path: Path):

        findings = []


        try:
            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore"
            )
        except OSError:
            return findings

        # Look for API/route definitions
        route_pattern = (
            r"(app\.(get|post|put|patch|delete)"
            r"|router\.(get|post|put|patch|delete)"
            r"|export\s+(async\s+)?function\s+"
            r"(GET|POST|PUT|PATCH|DELETE)"
            r"|@app\.(get|post|put|patch|delete))"
        )

        has_route = re.search(
            route_pattern,
            content,
            re.IGNORECASE
        )

        if not has_route:
            return findings

        has_authorization = self.contains_authorization_check(
            content
        )

        if not has_authorization:

            relative_file = str(
                file_path.relative_to(
                    self.project_path
                )
            )

            findings.append(
                Finding(
                    agent="AuthBreaker",
                    title=(
                        "Potential missing server-side "
                        "authorization"
                    ),
                    severity="HIGH",
                    confidence=0.70,
                    file=relative_file,
                    line=content[:has_route.start()].count("\n") + 1,
                    evidence=(
                        "A potential API/route was detected, "
                        "but no obvious authorization check "
                        "was found in the file."
                    ),
                    explanation=(
                        "The endpoint may rely on frontend "
                        "authorization or another mechanism "
                        "that was not visible during this scan."
                    ),
                    recommendation=(
                        "Verify that authentication and "
                        "authorization are enforced server-side "
                        "for this endpoint. Do not rely solely "
                        "on frontend access controls."
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

    breaker = AuthBreaker(".")

    findings = breaker.scan()

    print("\nAUTH BREAKER")
    print("=" * 40)

    if not findings:

        print("\nNo potential authorization issues found.")

    else:

        print(
            f"\nPotential findings: {len(findings)}\n"
        )

        for finding in findings:

            print(
                f"[{finding.severity}] "
                f"{finding.title}"
            )

            print(
                f"Agent: {finding.agent}"
            )

            print(
                f"Location: "
                f"{finding.file}:{finding.line}"
            )

            print(
                f"Confidence: "
                f"{finding.confidence}"
            )

            print(
                f"Evidence: "
                f"{finding.evidence}\n"
            )