from pathlib import Path
import re

from Agents.base_breaker import (
    BaseBreaker,
    CODE_EXTENSIONS,
    CONFIG_EXTENSIONS,
    JS_EXTENSIONS,
    PYTHON_EXTENSIONS,
    LineIndex,
    Rule,
    clip,
    strip_comments,
)


JS = frozenset(JS_EXTENSIONS)
PY = frozenset(PYTHON_EXTENSIONS)
CODE = frozenset(CODE_EXTENSIONS)
ANY_CONFIG = frozenset(CODE_EXTENSIONS | CONFIG_EXTENSIONS)

CREDENTIALS_ALLOWED = re.compile(
    r"credentials\s*:\s*true|allow_credentials\s*=\s*True|"
    r"CORS_ALLOW_CREDENTIALS\s*=\s*True|supports_credentials\s*=\s*True|"
    r"Access-Control-Allow-Credentials[\"']?\s*[,:]\s*[\"']true",
    re.IGNORECASE,
)

TLS_DISABLED = dict(
    severity="HIGH",
    explanation=(
        "TLS certificate verification is turned off, so anyone on the "
        "network path can impersonate the server and read or modify the "
        "traffic (man-in-the-middle)."
    ),
    recommendation=(
        "Remove the override. If you need a private CA, point the client "
        "at that CA bundle instead of disabling verification."
    ),
    cwe="CWE-295",
)

CORS_WILDCARD = dict(
    severity="MEDIUM",
    explanation=(
        "Any website can call this API from a visitor's browser and read "
        "the responses."
    ),
    recommendation=(
        "Allow only the origins you own (e.g. an allowlist from an env "
        "variable). Never combine a wildcard or reflected origin with "
        "credentials."
    ),
    cwe="CWE-942",
)

RULES = [

    # -------------------------
    # Debug mode
    # -------------------------

    Rule(
        title="Debug mode enabled",
        code_only=True,
        pattern=r"^\s*DEBUG\s*=\s*True\b",
        severity="MEDIUM",
        confidence=0.6,
        explanation=(
            "Debug mode shows stack traces, settings and sometimes an "
            "interactive console to anyone who triggers an error."
        ),
        recommendation="Read DEBUG from an environment variable and default it to False.",
        cwe="CWE-489",
        extensions=PY,
        ignore_case=False,
    ),
    Rule(
        title="Flask debug server enabled",
        code_only=True,
        pattern=r"\.run\([^)]*debug\s*=\s*True",
        severity="HIGH",
        confidence=0.7,
        explanation=(
            "The Werkzeug debugger allows running arbitrary Python from the "
            "browser if it is ever reachable from the network."
        ),
        recommendation="Never enable debug=True outside local development; use an env variable.",
        cwe="CWE-489",
        extensions=PY,
    ),
    Rule(
        title="Django ALLOWED_HOSTS allows any host",
        pattern=r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']\s*\]",
        severity="MEDIUM",
        confidence=0.7,
        explanation="A wildcard host header enables host-header poisoning (e.g. password reset links).",
        recommendation="List your real domains in ALLOWED_HOSTS.",
        cwe="CWE-644",
        extensions=PY,
        ignore_case=False,
    ),

    # -------------------------
    # CORS
    # -------------------------

    Rule(
        title="CORS allows any origin",
        pattern=(
            r"\borigin\s*:\s*(?:[\"']\*[\"']|true\b)"
            r"|allow_origins\s*=\s*\[\s*[\"']\*[\"']"
            r"|CORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True"
            r"|Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*[\"']"
            r"|origins\s*=\s*[\"']\*[\"']"
        ),
        confidence=0.7,
        extensions=ANY_CONFIG,
        **CORS_WILDCARD,
    ),
    Rule(
        title="CORS enabled with default (allow-all) settings",
        pattern=r"\bcors\(\s*\)|\bCORS\(\s*app\s*\)",
        confidence=0.5,
        extensions=frozenset(JS | PY),
        **{**CORS_WILDCARD, "severity": "LOW"},
    ),
    Rule(
        title="CORS reflects the request origin",
        pattern=(
            r"Access-Control-Allow-Origin[\"']?\s*,\s*req\.headers\.origin"
            r"|origin\s*:\s*\(\s*origin\s*,\s*callback\s*\)\s*=>\s*callback\(\s*null\s*,\s*true\s*\)"
        ),
        severity="HIGH",
        confidence=0.7,
        explanation=(
            "Echoing back whatever Origin the browser sends is the same as "
            "allowing every website, and with credentials it lets any site "
            "act as the logged-in user."
        ),
        recommendation="Compare the origin against an allowlist before echoing it.",
        cwe="CWE-942",
        extensions=JS,
    ),

    # -------------------------
    # Cookies and sessions
    # -------------------------

    Rule(
        title="Cookie readable by JavaScript (httpOnly disabled)",
        pattern=r"httpOnly\s*:\s*false|SESSION_COOKIE_HTTPONLY\s*=\s*False|httponly\s*=\s*False",
        severity="MEDIUM",
        confidence=0.7,
        explanation="Without HttpOnly, any XSS bug can steal the session cookie.",
        recommendation="Set httpOnly: true on session and auth cookies.",
        cwe="CWE-1004",
        extensions=frozenset(JS | PY),
    ),
    Rule(
        title="Cookie sent over plain HTTP (secure disabled)",
        pattern=(
            r"cookie\w*\s*[:(]\s*\{[^}]*\bsecure\s*:\s*false"
            r"|\.cookie\([^)]*\bsecure\s*:\s*false"
            r"|SESSION_COOKIE_SECURE\s*=\s*False"
            r"|CSRF_COOKIE_SECURE\s*=\s*False|set_cookie\([^)]*secure\s*=\s*False"
        ),
        severity="LOW",
        confidence=0.5,
        explanation="Cookies without the Secure flag can be sent over unencrypted HTTP and intercepted.",
        recommendation="Set secure: true in production (e.g. secure: process.env.NODE_ENV === 'production').",
        cwe="CWE-614",
        extensions=frozenset(JS | PY),
    ),
    Rule(
        title="Session secret is a weak default",
        pattern=(
            r"secret\s*:\s*[\"'](?:keyboard cat|secret|changeme|change-me|mysecret|"
            r"my-secret|supersecret|super-secret|default|dev|development|test|123456)[\"']"
            r"|SECRET_KEY\s*=\s*[\"'](?:django-insecure-[^\"']*|secret|changeme|dev|development)[\"']"
        ),
        severity="HIGH",
        confidence=0.85,
        explanation=(
            "Sessions are signed with a well-known secret, so attackers can "
            "forge session cookies and log in as anyone."
        ),
        recommendation="Generate a long random secret and load it from an environment variable.",
        cwe="CWE-1392",
        extensions=frozenset(JS | PY),
    ),

    # -------------------------
    # TLS
    # -------------------------

    Rule(
        title="TLS certificate verification disabled",
        pattern=r"\bverify\s*=\s*False\b",
        code_only=True,
        confidence=0.8,
        extensions=PY,
        ignore_case=False,
        **TLS_DISABLED,
    ),
    Rule(
        title="TLS certificate verification disabled",
        pattern=(
            r"ssl\._create_unverified_context|CERT_NONE|check_hostname\s*=\s*False"
        ),
        code_only=True,
        confidence=0.75,
        extensions=PY,
        **TLS_DISABLED,
    ),
    Rule(
        title="TLS certificate verification disabled",
        pattern=r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[=:]\s*[\"']?0",
        confidence=0.8,
        extensions=ANY_CONFIG,
        **TLS_DISABLED,
    ),
    Rule(
        title="TLS certificate verification disabled",
        pattern=r"InsecureSkipVerify\s*:\s*true",
        code_only=True,
        confidence=0.8,
        extensions=frozenset({".go"}),
        **TLS_DISABLED,
    ),

    # -------------------------
    # CSRF
    # -------------------------

    Rule(
        title="CSRF protection disabled",
        code_only=True,
        pattern=r"@csrf_exempt\b|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*=\s*False|csrf_protection\s*=\s*False",
        severity="MEDIUM",
        confidence=0.6,
        explanation=(
            "Without CSRF protection, a malicious site can make a logged-in "
            "user's browser submit requests (change email, transfer funds)."
        ),
        recommendation=(
            "Keep CSRF protection on for cookie-authenticated endpoints. "
            "Exempt only endpoints authenticated by tokens or signatures "
            "(e.g. verified webhooks)."
        ),
        cwe="CWE-352",
        extensions=PY,
    ),

    # -------------------------
    # Exposure
    # -------------------------

    Rule(
        title="GraphQL introspection or playground enabled",
        pattern=r"introspection\s*:\s*true|playground\s*:\s*true|graphiql\s*[:=]\s*(?:true|True)",
        severity="LOW",
        confidence=0.5,
        explanation="Introspection publishes your full API schema, making it easier to find weak spots.",
        recommendation="Disable introspection and playgrounds in production.",
        cwe="CWE-200",
        extensions=frozenset(JS | PY),
    ),
    Rule(
        title="Production source maps enabled",
        pattern=r"productionBrowserSourceMaps\s*:\s*true|GENERATE_SOURCEMAP\s*=\s*true",
        severity="LOW",
        confidence=0.6,
        explanation="Public source maps expose your original frontend source code.",
        recommendation="Disable browser source maps in production or upload them privately to your error tracker.",
        cwe="CWE-540",
        extensions=ANY_CONFIG,
    ),
    Rule(
        title="Directory listing enabled",
        pattern=r"serveIndex\(|autoindex\s+on|Options\s+\+?Indexes",
        severity="LOW",
        confidence=0.6,
        explanation="Directory listing lets anyone browse every file in the served folder.",
        recommendation="Disable directory listing.",
        cwe="CWE-548",
        extensions=frozenset(ANY_CONFIG | {".htaccess"}),
    ),
]

EXPRESS_APP = re.compile(r"=\s*express\(\s*\)")
HELMET = re.compile(r"\bhelmet\b|secure-headers|contentSecurityPolicy", re.IGNORECASE)
DEV_FILE = re.compile(
    r"(?:^|[/_.-])(?:dev|development|local|test|tests)(?:[_./-]|$)",
    re.IGNORECASE,
)
DOCKER_USER = re.compile(r"^\s*USER\s+(?!root\b|0\b)\S+", re.MULTILINE | re.IGNORECASE)


class ConfigBreaker(BaseBreaker):

    name = "ConfigBreaker"
    description = (
        "Debug mode, permissive CORS, insecure cookies, disabled TLS "
        "verification, CSRF off, missing security headers, root containers"
    )
    prompt_file = "Config.txt"
    always_run = True
    extensions = CODE_EXTENSIONS | CONFIG_EXTENSIONS | {".htaccess"}

    def scan(self):
        self._express_apps = []
        self._has_helmet = False
        return super().scan()

    def refine(self, finding, rule, match, code):

        # Wildcard CORS + credentials is the dangerous combination.
        if rule.cwe == "CWE-942" and CREDENTIALS_ALLOWED.search(code):
            finding.severity = "HIGH"
            finding.confidence = min(finding.confidence + 0.1, 0.95)
            finding.explanation += (
                " Credentials are also allowed in this file, so other sites "
                "can make authenticated requests as your users."
            )

        # Settings files named like dev/local/test are expected to be loose.
        if DEV_FILE.search(finding.file):
            finding.severity = "INFO"
            finding.confidence = round(finding.confidence * 0.5, 2)

        return finding

    def scan_file(self, file_path: Path, content: str):

        name = file_path.name.lower()

        if name == "dockerfile" or name.startswith("dockerfile."):
            return self.scan_dockerfile(file_path, content)

        code = strip_comments(content, file_path)

        if file_path.suffix.lower() in JS_EXTENSIONS:

            if HELMET.search(code):
                self._has_helmet = True

            match = EXPRESS_APP.search(code)

            if match:
                index = LineIndex(content)
                line = index.line_of(match.start())
                self._express_apps.append(
                    (self.relative(file_path), line, index.text(line))
                )

        return self.scan_rules(file_path, content, RULES, code)

    def scan_dockerfile(self, file_path: Path, content: str):

        code = strip_comments(content, file_path)

        if DOCKER_USER.search(code):
            return []

        return [
            self.make_finding(
                title="Container runs as root",
                severity="LOW",
                confidence=0.6,
                file=self.relative(file_path),
                line=1,
                evidence="No non-root USER instruction found",
                explanation=(
                    "If the app is compromised, the attacker has root inside "
                    "the container, which makes container escapes and "
                    "tampering easier."
                ),
                recommendation="Create an unprivileged user and add a USER instruction before CMD.",
                cwe="CWE-250",
            )
        ]

    def scan_project(self):

        if self._has_helmet:
            return []

        return [
            self.make_finding(
                title="Express app without security headers (helmet)",
                severity="LOW",
                confidence=0.5,
                file=file,
                line=line,
                evidence=clip(text),
                explanation=(
                    "No helmet (or equivalent) was found, so responses lack "
                    "headers such as Content-Security-Policy, "
                    "X-Content-Type-Options and Strict-Transport-Security."
                ),
                recommendation="Add app.use(helmet()) and configure a Content-Security-Policy.",
                cwe="CWE-693",
            )
            for file, line, text in self._express_apps
        ]


if __name__ == "__main__":
    ConfigBreaker.cli()
