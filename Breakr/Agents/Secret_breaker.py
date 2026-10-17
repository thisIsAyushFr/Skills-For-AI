from pathlib import Path
import re

from Agents.base_breaker import (
    BaseBreaker,
    TEST_PATH,
    LineIndex,
    clip,
    is_env_file,
    mask_secret,
)


# Values that are clearly not real secrets.
PLACEHOLDER = re.compile(
    r"^(?:<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|\*+|x{3,}|\.{3,}|"
    r"(?:your|my|enter|insert|replace|change|put)[-_ ]?.*|"
    r"placeholder|example|sample|dummy|fake|test|testing|todo|tbd|"
    r"none|null|undefined|false|true|string|secret|password|token|"
    r"api[-_]?key|process\.env.*|os\.environ.*)$",
    re.IGNORECASE,
)

VERSION_VALUE = re.compile(r"^[\^~>=<v]*\d+(?:\.\d+){1,3}(?:[-+.][\w.]*)?$", re.IGNORECASE)

# Dependency manifests: "jsonwebtoken": "9.0.0" is not a token.
MANIFEST_FILES = {
    "package.json", "composer.json", "pipfile", "pyproject.toml",
    "cargo.toml", "go.mod", "gemfile",
}

TRANSLATION_PATH = re.compile(
    r"(^|/)(locales?|i18n|l10n|lang|langs|translations?|messages)(/|$)",
    re.IGNORECASE,
)

LOCAL_DATABASE_HOST = re.compile(
    r"@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|db|database|postgres|mysql|mongo|redis)(?=[:/]|$)",
    re.IGNORECASE,
)

DOCS_PATH = re.compile(r"(^|/)docs?(/|$)|\.mdx?$", re.IGNORECASE)

# name, regex with a (?P<secret>...) group, severity, confidence, explanation
PROVIDER_PATTERNS = [
    (
        "AWS access key ID",
        r"\b(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16})\b",
        "CRITICAL", 0.9,
        "AWS access keys give direct access to cloud resources and are "
        "actively harvested from public repositories within minutes.",
    ),
    (
        "GitHub token",
        r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b",
        "CRITICAL", 0.95,
        "GitHub tokens can read or push code and access organisation data.",
    ),
    (
        "Stripe secret key",
        r"\b(?P<secret>(?:sk|rk)_live_[0-9a-zA-Z]{20,})\b",
        "CRITICAL", 0.95,
        "Live Stripe secret keys can issue refunds, read customer data and "
        "move money.",
    ),
    (
        "Stripe test secret key",
        r"\b(?P<secret>sk_test_[0-9a-zA-Z]{20,})\b",
        "LOW", 0.8,
        "Test-mode Stripe keys cannot move real money but still expose your "
        "test account and should not be committed.",
    ),
    (
        "OpenRouter API key",
        r"\b(?P<secret>sk-or-v1-[A-Za-z0-9]{32,})\b",
        "CRITICAL", 0.95,
        "LLM API keys are abused for free usage and can run up large bills.",
    ),
    (
        "OpenAI API key",
        r"\b(?P<secret>sk-(?!or-|ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})\b",
        "CRITICAL", 0.85,
        "LLM API keys are abused for free usage and can run up large bills.",
    ),
    (
        "Anthropic API key",
        r"\b(?P<secret>sk-ant-[A-Za-z0-9_-]{32,})\b",
        "CRITICAL", 0.95,
        "LLM API keys are abused for free usage and can run up large bills.",
    ),
    (
        "Slack token",
        r"\b(?P<secret>xox[abposr]-[A-Za-z0-9-]{10,})\b",
        "HIGH", 0.9,
        "Slack tokens can read messages and post as your app or user.",
    ),
    (
        "Slack webhook URL",
        r"(?P<secret>https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,})",
        "MEDIUM", 0.9,
        "Anyone with this URL can post messages into your Slack workspace.",
    ),
    (
        "Google API key",
        r"\b(?P<secret>AIza[0-9A-Za-z_-]{35})\b",
        "LOW", 0.7,
        "Google API keys are often public by design (e.g. Firebase web "
        "config), but unrestricted keys can be abused for paid APIs.",
    ),
    (
        "SendGrid API key",
        r"\b(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b",
        "HIGH", 0.95,
        "SendGrid keys let attackers send email as your domain (phishing).",
    ),
    (
        "Twilio API key",
        r"\b(?P<secret>SK[0-9a-fA-F]{32})\b",
        "HIGH", 0.6,
        "Twilio keys can send SMS and make calls billed to your account.",
    ),
    (
        "Private key",
        r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
        "CRITICAL", 0.95,
        "Private keys allow impersonating your servers or signing as you.",
    ),
    (
        "Database URL with embedded password",
        r"(?P<secret>(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql)"
        r"://[^:\s/\"'@]+:[^@\s\"'/]{3,}@[^\s\"']+)",
        "HIGH", 0.85,
        "A connection string with a password gives direct database access.",
    ),
]

# Generic "name = 'value'" assignments.
GENERIC_PATTERNS = [
    (
        "Hardcoded API key",
        r"(?:api[_-]?key|apikey|x-api-key)",
    ),
    (
        "Hardcoded secret",
        r"(?:secret[_-]?key|client[_-]?secret|app[_-]?secret|jwt[_-]?secret|"
        r"session[_-]?secret|signing[_-]?key|encryption[_-]?key)",
    ),
    (
        "Hardcoded password",
        r"(?:password|passwd|pwd|db[_-]?pass(?:word)?)",
    ),
    (
        "Hardcoded token",
        r"(?:access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer[_-]?token|"
        r"api[_-]?token|bot[_-]?token|token)",
    ),
]

GENERIC_ASSIGNMENT = r"[\"']?\s*[:=]\s*[\"'](?P<secret>[^\"'\s]{4,})[\"']"


class SecretBreaker(BaseBreaker):

    name = "SecretBreaker"
    description = (
        "Hardcoded API keys, passwords, tokens, private keys, credentialed "
        "database URLs and committed .env files"
    )
    prompt_file = "Secret.txt"
    always_run = True

    def __init__(self, project_path, files=None, options=None):
        super().__init__(project_path, files, options)

        self.provider_patterns = [
            (title, re.compile(pattern), severity, confidence, explanation)
            for title, pattern, severity, confidence, explanation in PROVIDER_PATTERNS
        ]

        self.generic_patterns = [
            (
                title,
                re.compile(
                    r"(?<![\w-])\w*?" + key + GENERIC_ASSIGNMENT,
                    re.IGNORECASE,
                ),
            )
            for title, key in GENERIC_PATTERNS
        ]

    # -------------------------
    # .env handling
    # -------------------------

    @staticmethod
    def is_env_template(name: str) -> bool:
        return any(
            word in name.lower()
            for word in ("example", "sample", "template", "dist", "defaults")
        )

    # -------------------------
    # Scanning
    # -------------------------

    def scan_file(self, file_path: Path, content: str):

        findings = []
        relative = self.relative(file_path)
        name = file_path.name
        in_tests = bool(TEST_PATH.search(relative) or DOCS_PATH.search(relative))
        in_translations = bool(TRANSLATION_PATH.search(relative))
        skip_generic = (
            in_tests
            or in_translations
            or name.lower() in MANIFEST_FILES
            or name.lower().startswith("requirements")
        )

        if is_env_file(name) and not self.is_env_template(name):

            # Local env files that git ignores are where secrets belong.
            if self.is_gitignored(file_path):
                return findings

            findings.append(
                self.make_finding(
                    title="Environment file not ignored by git",
                    severity="HIGH",
                    confidence=0.75,
                    file=relative,
                    line=1,
                    evidence=f"{relative} is not ignored by git (or is already tracked)",
                    explanation=(
                        "Env files usually hold real credentials. If this "
                        "file is committed, every secret in it is exposed to "
                        "anyone with access to the repository."
                    ),
                    recommendation=(
                        "Add .env* to .gitignore (keep a .env.example with "
                        "dummy values), remove the file from git history, and "
                        "rotate any secrets it contained."
                    ),
                    cwe="CWE-538",
                )
            )

        index = LineIndex(content)
        flagged_lines = set()

        for line_number, line in enumerate(index.lines, start=1):

            if len(line) > 2000:
                continue

            # Provider-specific formats: high confidence.
            for title, pattern, severity, confidence, explanation in self.provider_patterns:

                match = pattern.search(line)

                if not match:
                    continue

                secret = match.group("secret")

                if PLACEHOLDER.match(secret) or "example" in secret.lower():
                    continue

                if in_tests and severity != "CRITICAL":
                    continue

                # Default credentials for a local/docker database.
                if title.startswith("Database URL") and LOCAL_DATABASE_HOST.search(secret):
                    severity, confidence = "LOW", 0.5

                flagged_lines.add(line_number)

                findings.append(
                    self._secret_finding(
                        title, severity, confidence,
                        relative, line_number, line, secret, explanation,
                    )
                )

            if line_number in flagged_lines or skip_generic:
                continue

            # Generic assignments: only if no provider pattern matched.
            for title, pattern in self.generic_patterns:

                match = pattern.search(line)

                if not match:
                    continue

                secret = match.group("secret")

                if (
                    PLACEHOLDER.match(secret)
                    or VERSION_VALUE.match(secret)
                    or secret.startswith(("http://", "https://", "/", "./"))
                ):
                    continue

                findings.append(
                    self._secret_finding(
                        title, "HIGH", 0.7,
                        relative, line_number, line, secret,
                        "A credential-like value is hardcoded in source. "
                        "Anyone who can read the code (or the built frontend "
                        "bundle) can read it.",
                    )
                )

                break

        return findings

    def _secret_finding(self, title, severity, confidence, file, line_number, line, secret, explanation):
        return self.make_finding(
            title=title,
            severity=severity,
            confidence=round(confidence, 2),
            file=file,
            line=line_number,
            evidence=clip(line.replace(secret, mask_secret(secret))),
            explanation=explanation,
            recommendation=(
                "Move the value to an environment variable or secret manager, "
                "never ship it in client-side code, and rotate it: assume any "
                "secret that was committed is already compromised."
            ),
            cwe="CWE-798",
        )


if __name__ == "__main__":
    SecretBreaker.cli()
