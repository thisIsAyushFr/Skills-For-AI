from pathlib import Path
import re

from Agents.base_breaker import (
    BaseBreaker,
    COMPONENT_EXTENSIONS,
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
    AUTHORIZATION,
    file_level_protection,
    find_routes,
    handler_window,
    project_protection,
)


WEBHOOK_VERIFICATION = re.compile(
    r"signature|constructevent|hmac|svix|webhook_?secret|x-hub-signature|"
    r"timingsafeequal|compare_digest|verify",
    re.IGNORECASE,
)

CLIENT_EXTENSIONS = frozenset(JS_EXTENSIONS | COMPONENT_EXTENSIONS)

CLIENT_RULES = [
    Rule(
        title="Authorization decided in client-side code",
        pattern=(
            r"\b(?:user|currentUser|session\??\.user|profile|me|account)\??\."
            r"(?:role|isAdmin|is_admin)\s*(?:===?|!==?)\s*[\"'`](?:admin|superadmin|owner)[\"'`]"
            r"|(?:if\s*\(\s*!?|\{\s*!?)(?:user|currentUser|session\??\.user|profile|me|account)"
            r"\??\.(?:isAdmin|is_admin)\b"
        ),
        severity="LOW",
        confidence=0.4,
        explanation=(
            "A role or admin flag is checked in code that may run in the "
            "browser. Anyone can edit client-side code, so this check only "
            "hides UI; it does not protect data."
        ),
        recommendation=(
            "Keep the client-side check for UX, but make sure every API "
            "route or database policy behind this screen enforces the same "
            "role on the server."
        ),
        cwe="CWE-602",
        extensions=frozenset({".jsx", ".tsx", ".vue", ".svelte"}),
    ),
    Rule(
        title="Auth token stored in localStorage",
        pattern=(
            r"localStorage\.setItem\(\s*[\"'`](?:token|jwt|access_?token|"
            r"id_?token|auth_?token|auth|session|refresh_?token)[\"'`]"
        ),
        severity="LOW",
        confidence=0.6,
        explanation=(
            "Tokens in localStorage can be read by any script on the page, "
            "so a single XSS bug lets an attacker steal user sessions."
        ),
        recommendation=(
            "Prefer HttpOnly, Secure, SameSite cookies for session tokens, "
            "or keep tokens in memory with short lifetimes."
        ),
        cwe="CWE-922",
        extensions=CLIENT_EXTENSIONS,
    ),
]


class AuthBreaker(BaseBreaker):

    name = "AuthBreaker"
    description = (
        "Routes that change data without login, admin routes without "
        "role checks, unverified webhooks, client-only auth"
    )
    prompt_file = "Auth.txt"
    trigger_technologies = WEB_TECHNOLOGIES
    extensions = JS_EXTENSIONS | PYTHON_EXTENSIONS | COMPONENT_EXTENSIONS

    def scan_file(self, file_path: Path, content: str):

        findings = []
        relative = self.relative(file_path)
        code = strip_comments(content, file_path)

        findings.extend(
            self.scan_rules(file_path, content, CLIENT_RULES, code)
        )

        routes = find_routes(code, relative)

        if not routes:
            return findings

        # -------------------------
        # Protection that covers the whole file
        # -------------------------

        file_authn, file_authz = file_level_protection(code)

        mounted, next_middleware_auth = project_protection(
            str(self.project_path),
            tuple(self.files),
        )

        mounted_authn, mounted_authz = mounted.get(relative, (False, False))

        file_authn = file_authn or mounted_authn
        file_authz = file_authz or mounted_authz

        index = LineIndex(content)

        # -------------------------
        # Check each route
        # -------------------------

        for position, route in enumerate(routes):

            window = handler_window(code, routes, position)

            authn = file_authn or bool(AUTHENTICATION.search(window))
            authz = file_authz or bool(AUTHORIZATION.search(window))

            evidence = clip(
                f"{route.method_label} {route.path} -> {index.text(route.line)}"
            )

            def add(title, severity, confidence, explanation, recommendation, cwe):
                findings.append(
                    self.make_finding(
                        title=title,
                        severity=severity,
                        confidence=confidence,
                        file=relative,
                        line=route.line,
                        evidence=evidence,
                        explanation=explanation,
                        recommendation=recommendation,
                        cwe=cwe,
                    )
                )

            # Webhooks are public by design but must verify the sender.
            if "webhook" in route.path.lower() and route.is_state_changing:

                if not WEBHOOK_VERIFICATION.search(window):
                    add(
                        "Webhook without signature verification",
                        "HIGH",
                        0.6,
                        "This webhook endpoint accepts requests without any "
                        "visible signature check, so anyone who finds the URL "
                        "can send fake events (for example fake payments).",
                        "Verify the provider's signature header (e.g. "
                        "stripe.webhooks.constructEvent, Svix, or an HMAC "
                        "compared with a constant-time function) before "
                        "trusting the payload.",
                        "CWE-345",
                    )

                continue

            # Admin routes need a role check, not just a login check.
            if route.is_admin:

                if not authz:
                    add(
                        "Admin route without role check"
                        if authn
                        else "Admin route without authentication or role check",
                        "HIGH",
                        0.6 if authn else 0.7,
                        "This route looks administrative but no role, "
                        "permission or admin check is visible in the handler, "
                        "the file, or the middleware it is mounted behind. "
                        + (
                            "Any logged-in user may be able to call it."
                            if authn
                            else "Anyone may be able to call it."
                        ),
                        "Enforce an admin/role check on the server for this "
                        "route (middleware, decorator or guard). Hiding the "
                        "admin page in the frontend is not enough.",
                        "CWE-285",
                    )

                continue

            if not route.is_state_changing or route.is_public or authn:
                continue

            severity = "HIGH"
            confidence = 0.6
            note = ""

            if route.framework.startswith("nextjs") and next_middleware_auth:
                severity = "LOW"
                confidence = 0.35
                note = (
                    " A Next.js middleware file with auth logic exists; "
                    "confirm its matcher covers this route and that the "
                    "handler does not rely on it alone."
                )

            add(
                "State-changing route without visible authentication",
                severity,
                confidence,
                f"{route.method_label} {route.path} can create, change or "
                "delete data, but no authentication check is visible in the "
                "handler, the file, or the middleware it is mounted behind."
                + note,
                "Require a verified session or token on the server before "
                "running this handler. Do not rely on the frontend hiding "
                "the button.",
                "CWE-306",
            )

        return findings


if __name__ == "__main__":
    AuthBreaker.cli()
