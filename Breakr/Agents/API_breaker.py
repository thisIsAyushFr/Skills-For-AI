from pathlib import Path
import re

from Agents.base_breaker import (
    BaseBreaker,
    JS_EXTENSIONS,
    PYTHON_EXTENSIONS,
    WEB_TECHNOLOGIES,
    LineIndex,
    Rule,
    clip,
    strip_comments,
)
from Agents.web_routes import (
    AUTHENTICATION,
    file_level_protection,
    find_routes,
    handler_window,
    project_protection,
)


JS = frozenset(JS_EXTENSIONS)
PY = frozenset(PYTHON_EXTENSIONS)

ID_PARAMETER = re.compile(
    r":\w*id\b|\{\w*id\}|\[\w*id\]|<(?:\w+:)?\w*id>",
    re.IGNORECASE,
)

LOOKUP_BY_ID = re.compile(
    r"findbyid|findbypk|findunique|findfirst|findone|get_object_or_404|"
    r"query\.get\(|\.get\(\s*\w*id|filter_by\(|\.filter\(|\.where\(|"
    r"\.eq\(\s*[\"'`]id[\"'`]|params\.\w*id|params\[",
    re.IGNORECASE,
)

OWNERSHIP_CHECK = re.compile(
    r"req\.user|request\.user|current_user|user_?id|owner|session\.user|"
    r"auth\.uid|\.eq\(\s*[\"'`]user_id|tenant|org(?:anization)?_?id",
    re.IGNORECASE,
)

LOGIN_ROUTE = re.compile(r"log-?in|sign-?in|auth/token|/token\b|otp|password", re.IGNORECASE)

RATE_LIMITING = re.compile(
    r"rate-?limit|ratelimit|slowapi|limiter|throttl|express-brute|"
    r"flask_limiter|@Throttle|upstash/ratelimit|rate_limit",
    re.IGNORECASE,
)

MASS_ASSIGNMENT = dict(
    title="Mass assignment from request body",
    severity="MEDIUM",
    confidence=0.6,
    explanation=(
        "The whole request body is passed straight into a database write. "
        "An attacker can add extra fields such as role, isAdmin, balance "
        "or ownerId and the database will save them."
    ),
    recommendation=(
        "Pick allowed fields explicitly (or validate with a schema such as "
        "zod / Joi / pydantic with extra fields forbidden) before writing "
        "to the database."
    ),
    cwe="CWE-915",
)

RULES = [
    Rule(
        pattern=(
            r"\.(?:create|insert|insertOne|insertMany|update|updateOne|updateMany|"
            r"upsert|build|bulkCreate|findByIdAndUpdate|findOneAndUpdate)\(\s*"
            r"(?:[^,()]+,\s*)?(?:\{\s*\.\.\.\s*)?req\.body\s*[,)}]"
        ),
        extensions=JS,
        **MASS_ASSIGNMENT,
    ),
    Rule(
        pattern=(
            r"Object\.assign\(\s*\w+\s*,\s*req\.body\s*\)"
            r"|\bdata\s*:\s*req\.body\b"
            r"|new\s+[A-Z]\w*\(\s*req\.body\s*\)"
        ),
        extensions=JS,
        ignore_case=False,
        **MASS_ASSIGNMENT,
    ),
    Rule(
        pattern=(
            r"\b[A-Z]\w*(?:\.objects\.create)?\(\s*\*\*\s*(?:await\s+)?request\."
            r"(?:json|form|data|POST|get_json\(\)|json\(\))"
            r"|\.update\(\s*\*\*\s*(?:await\s+)?request\."
        ),
        extensions=PY,
        ignore_case=False,
        **MASS_ASSIGNMENT,
    ),
    Rule(
        title="Stack trace returned to client",
        pattern=(
            r"res\.(?:status\(\s*\d+\s*\)\s*\.)?(?:json|send)\([^)\n]*"
            r"\b(?:err|error|e|ex)\.stack\b"
        ),
        severity="MEDIUM",
        confidence=0.7,
        explanation=(
            "Stack traces reveal file paths, library versions and internal "
            "logic that help attackers plan further attacks."
        ),
        recommendation=(
            "Log the full error on the server and return a generic message "
            "with an error ID to the client."
        ),
        cwe="CWE-209",
        extensions=JS,
    ),
    Rule(
        title="Raw error object returned to client",
        pattern=(
            r"res\.(?:status\(\s*5\d\d\s*\)\s*\.)?(?:json|send)\(\s*"
            r"(?:err|error|e|ex)\s*\)"
        ),
        severity="LOW",
        confidence=0.5,
        explanation=(
            "Sending the raw error object can leak database errors, query "
            "fragments or internal details."
        ),
        recommendation="Return a generic error message and log the details server-side.",
        cwe="CWE-209",
        extensions=JS,
    ),
    Rule(
        title="Stack trace returned to client",
        pattern=r"(?:return|jsonify|JSONResponse|HTTPException|Response)[^\n]*traceback\.format_exc\(\)",
        severity="MEDIUM",
        confidence=0.7,
        explanation=(
            "Stack traces reveal file paths, library versions and internal "
            "logic that help attackers plan further attacks."
        ),
        recommendation=(
            "Log the traceback on the server and return a generic message "
            "to the client."
        ),
        cwe="CWE-209",
        extensions=PY,
    ),
    Rule(
        title="Exception message returned to client",
        pattern=(
            r"(?:return\s+jsonify|return\s+JSONResponse|raise\s+HTTPException|return\s+Response)"
            r"\([^\n]*\bstr\(\s*(?:e|err|exc|error|ex)\s*\)"
        ),
        severity="LOW",
        confidence=0.4,
        explanation=(
            "Exception messages can include SQL errors, file paths or other "
            "internal details."
        ),
        recommendation="Return a generic error message and log the exception server-side.",
        cwe="CWE-209",
        extensions=PY,
    ),
]


class APIBreaker(BaseBreaker):

    name = "APIBreaker"
    description = (
        "Sensitive read endpoints without login, IDOR, mass assignment, "
        "error leakage, login routes without rate limiting"
    )
    prompt_file = "Api.txt"
    trigger_technologies = WEB_TECHNOLOGIES
    extensions = JS_EXTENSIONS | PYTHON_EXTENSIONS

    def scan(self):
        self._login_routes = []
        self._rate_limited = False
        return super().scan()

    def scan_file(self, file_path: Path, content: str):

        findings = []
        relative = self.relative(file_path)
        code = strip_comments(content, file_path)

        if RATE_LIMITING.search(code):
            self._rate_limited = True

        findings.extend(
            self.scan_rules(file_path, content, RULES, code)
        )

        routes = find_routes(code, relative)

        if not routes:
            return findings

        file_authn, _ = file_level_protection(code)

        mounted, next_middleware_auth = project_protection(
            str(self.project_path),
            tuple(self.files),
        )

        file_authn = file_authn or mounted.get(relative, (False, False))[0]

        index = LineIndex(content)

        for position, route in enumerate(routes):

            window = handler_window(code, routes, position)
            authn = file_authn or bool(AUTHENTICATION.search(window))

            evidence = clip(
                f"{route.method_label} {route.path} -> {index.text(route.line)}"
            )

            if route.is_state_changing and LOGIN_ROUTE.search(route.path):
                self._login_routes.append((relative, route.line, evidence))

            # Admin and state-changing routes are AuthBreaker's job.
            if not route.is_read or route.is_admin or route.is_public:
                continue

            if not route.is_sensitive:
                continue

            # -------------------------
            # Sensitive data readable without login
            # -------------------------

            if not authn:

                severity, confidence, note = "MEDIUM", 0.6, ""

                if route.framework.startswith("nextjs") and next_middleware_auth:
                    severity, confidence = "LOW", 0.35
                    note = (
                        " A Next.js middleware file with auth logic exists; "
                        "confirm its matcher covers this route."
                    )

                findings.append(
                    self.make_finding(
                        title="Sensitive data endpoint without visible authentication",
                        severity=severity,
                        confidence=confidence,
                        file=relative,
                        line=route.line,
                        evidence=evidence,
                        explanation=(
                            f"GET {route.path} looks like it returns sensitive "
                            "data, but no authentication check is visible in "
                            "the handler, the file, or the middleware it is "
                            "mounted behind." + note
                        ),
                        recommendation=(
                            "Require a verified session or token before "
                            "returning this data, and return only the fields "
                            "the caller needs."
                        ),
                        cwe="CWE-200",
                    )
                )

                continue

            # -------------------------
            # IDOR: logged in, but can read anyone's record by ID
            # -------------------------

            if (
                ID_PARAMETER.search(route.path)
                and LOOKUP_BY_ID.search(window)
                and not OWNERSHIP_CHECK.search(window)
            ):
                findings.append(
                    self.make_finding(
                        title="Possible IDOR: record fetched by ID without ownership check",
                        severity="MEDIUM",
                        confidence=0.45,
                        file=relative,
                        line=route.line,
                        evidence=evidence,
                        explanation=(
                            "The handler loads a record using an ID from the "
                            "URL but never compares it with the logged-in user. "
                            "A user could change the ID and read someone "
                            "else's data."
                        ),
                        recommendation=(
                            "Scope the query to the current user (e.g. WHERE "
                            "id = ? AND user_id = current_user) or check "
                            "ownership/role before returning the record."
                        ),
                        cwe="CWE-639",
                    )
                )

        return findings

    def scan_project(self):

        if self._rate_limited or not self._login_routes:
            return []

        return [
            self.make_finding(
                title="Login endpoint without rate limiting",
                severity="MEDIUM",
                confidence=0.5,
                file=file,
                line=line,
                evidence=evidence,
                explanation=(
                    "No rate limiting library or middleware was found anywhere "
                    "in the project, so this login/OTP/password endpoint can be "
                    "brute-forced or used for credential stuffing."
                ),
                recommendation=(
                    "Add rate limiting (express-rate-limit, @upstash/ratelimit, "
                    "slowapi, Flask-Limiter, or your platform's WAF) to "
                    "authentication endpoints, keyed by IP and account."
                ),
                cwe="CWE-307",
            )
            for file, line, evidence in self._login_routes
        ]


if __name__ == "__main__":
    APIBreaker.cli()
