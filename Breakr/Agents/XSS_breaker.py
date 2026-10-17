from pathlib import Path
import re

from Agents.base_breaker import (
    BaseBreaker,
    CODE_EXTENSIONS,
    COMPONENT_EXTENSIONS,
    FRONTEND_TECHNOLOGIES,
    JS_EXTENSIONS,
    PYTHON_EXTENSIONS,
    TEMPLATE_EXTENSIONS,
    Rule,
)


SCRIPT = frozenset(JS_EXTENSIONS | COMPONENT_EXTENSIONS | {".html", ".htm"})
JSX = frozenset({".jsx", ".tsx", ".js", ".ts"})
PY = frozenset(PYTHON_EXTENSIONS)
TEMPLATES = frozenset(TEMPLATE_EXTENSIONS)

SANITIZER = re.compile(r"dompurify|sanitize|purify|xss\(|escapehtml|bleach\.clean", re.IGNORECASE)

DOM_XSS = dict(
    severity="MEDIUM",
    explanation=(
        "HTML is inserted into the page without escaping. If any part of it "
        "comes from users (comments, names, URLs, API data), an attacker "
        "can run JavaScript in other users' browsers and steal sessions."
    ),
    recommendation=(
        "Render text with textContent / normal JSX / {{ }} interpolation. "
        "If you must render HTML, sanitise it first with DOMPurify (or "
        "bleach on the server) using a strict allowlist."
    ),
    cwe="CWE-79",
)

TEMPLATE_XSS = dict(
    severity="MEDIUM",
    explanation=(
        "Auto-escaping is turned off for this value. If it contains user "
        "input, attackers can inject scripts into the page."
    ),
    recommendation=(
        "Keep auto-escaping on. Only mark content as safe after sanitising "
        "it, and never for raw user input."
    ),
    cwe="CWE-79",
)

RULES = [

    # -------------------------
    # Framework escape hatches
    # -------------------------

    Rule(
        title="XSS: dangerouslySetInnerHTML",
        pattern=r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:",
        confidence=0.65,
        extensions=JSX,
        **DOM_XSS,
    ),
    Rule(
        title="XSS: v-html directive",
        pattern=r"\bv-html\s*=",
        confidence=0.65,
        extensions=frozenset({".vue", ".html"}),
        **DOM_XSS,
    ),
    Rule(
        title="XSS: Svelte {@html} block",
        pattern=r"\{@html\s",
        confidence=0.65,
        extensions=frozenset({".svelte"}),
        **DOM_XSS,
    ),
    Rule(
        title="XSS: Angular sanitizer bypassed",
        pattern=r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\(",
        confidence=0.7,
        extensions=frozenset({".ts", ".js"}),
        **DOM_XSS,
    ),
    Rule(
        title="XSS: Angular [innerHTML] binding",
        pattern=r"\[innerHTML\]\s*=",
        confidence=0.4,
        extensions=frozenset({".html", ".ts"}),
        **{**DOM_XSS, "severity": "LOW"},
    ),

    # -------------------------
    # Raw DOM sinks
    # -------------------------

    Rule(
        title="XSS: assignment to innerHTML / outerHTML",
        # Skip assignments of a plain constant string, e.g. el.innerHTML = "";
        pattern=(
            r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)"
            r"(?!\s*(?:[\"'][^\"'`$+\n]*[\"']|`[^`$]*`)\s*;?\s*$)"
        ),
        confidence=0.6,
        extensions=SCRIPT,
        **DOM_XSS,
    ),
    Rule(
        title="XSS: insertAdjacentHTML / document.write",
        pattern=r"\.insertAdjacentHTML\(|\bdocument\.write(?:ln)?\(",
        confidence=0.55,
        extensions=SCRIPT,
        **DOM_XSS,
    ),
    Rule(
        title="XSS: jQuery .html() with dynamic content",
        pattern=r"\$\([^)]*\)\.(?:html|append|prepend|before|after|replaceWith)\(\s*(?![\"'][^\"'+]*[\"']\s*\)|\))",
        confidence=0.45,
        extensions=SCRIPT,
        **DOM_XSS,
    ),
    Rule(
        title="XSS: URL fragment or query used in a DOM sink",
        pattern=(
            r"(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML|\.html\()[^\n;]*"
            r"(?:location\.(?:hash|search|href)|URLSearchParams|searchParams\.get)"
        ),
        severity="HIGH",
        confidence=0.8,
        explanation=(
            "Data from the URL is written into the page as HTML. An attacker "
            "can send a victim a crafted link that runs JavaScript in their "
            "session (DOM-based XSS)."
        ),
        recommendation="Treat URL data as text (textContent) or sanitise it with DOMPurify.",
        cwe="CWE-79",
        extensions=SCRIPT,
    ),
    Rule(
        title="XSS: javascript: URL built from a variable",
        pattern=r"href\s*=\s*\{\s*[`\"']javascript:|href\s*=\s*[\"']javascript:[^\"']*\$\{",
        severity="MEDIUM",
        confidence=0.5,
        explanation="javascript: URLs run code when clicked; with dynamic content they enable XSS.",
        recommendation="Use onClick handlers instead, and validate user-supplied URLs to http(s) only.",
        cwe="CWE-79",
        extensions=SCRIPT,
    ),

    # -------------------------
    # Server-side reflection
    # -------------------------

    Rule(
        title="Reflected XSS: request data written into the response",
        pattern=(
            r"res\.(?:send|write|end)\(\s*(?:`[^`]*\$\{\s*req\.(?:query|params|body)"
            r"|[\"'][^\"']*<[^\"']*[\"']\s*\+\s*req\.(?:query|params|body))"
        ),
        severity="HIGH",
        confidence=0.75,
        explanation=(
            "Request parameters are concatenated into an HTML response "
            "without escaping, so a malicious link can inject scripts."
        ),
        recommendation="Render through a template engine with auto-escaping, or escape the value.",
        cwe="CWE-79",
        extensions=frozenset(JS_EXTENSIONS),
    ),
    Rule(
        title="Reflected XSS: request data in an f-string response",
        pattern=r"return\s+(?:make_response\(|HTMLResponse\(|HttpResponse\()?\s*f[\"'][^\"'\n]*<[^\"'\n]*\{\s*request\.",
        severity="HIGH",
        confidence=0.7,
        explanation=(
            "Request data is formatted into raw HTML without escaping, so a "
            "malicious link can inject scripts."
        ),
        recommendation="Use render_template / Django templates (auto-escaped) or markupsafe.escape().",
        cwe="CWE-79",
        extensions=PY,
    ),

    # -------------------------
    # Template engines with escaping disabled
    # -------------------------

    Rule(
        title="XSS: Jinja/Django |safe filter",
        pattern=r"\{\{[^}]*\|\s*safe\b[^}]*\}\}",
        confidence=0.55,
        extensions=TEMPLATES,
        **TEMPLATE_XSS,
    ),
    Rule(
        title="XSS: autoescape disabled",
        pattern=r"\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}|autoescape\s*=\s*False|autoescape\s*:\s*false",
        severity="HIGH",
        confidence=0.75,
        explanation=(
            "Auto-escaping is disabled for a whole template or environment, "
            "so every variable rendered there is a potential XSS."
        ),
        recommendation="Enable auto-escaping (select_autoescape) and escape-opt-out only sanitised values.",
        cwe="CWE-79",
        extensions=frozenset(TEMPLATES | PY | JS_EXTENSIONS),
    ),
    Rule(
        title="XSS: mark_safe / Markup on formatted string",
        pattern=r"\b(?:mark_safe|Markup)\(\s*(?:f[\"']|[^)\"']*\+|[\"'][^\"']*[\"']\s*(?:%|\.format))",
        confidence=0.65,
        extensions=PY,
        **TEMPLATE_XSS,
    ),
    Rule(
        title="XSS: unescaped EJS output <%-",
        pattern=r"<%-(?!\s*include\b)",
        confidence=0.5,
        extensions=frozenset({".ejs"}),
        **TEMPLATE_XSS,
    ),
    Rule(
        title="XSS: unescaped Handlebars/Mustache output {{{ }}}",
        pattern=r"\{\{\{\s*[^}]+\}\}\}",
        confidence=0.5,
        extensions=frozenset({".hbs", ".handlebars", ".mustache", ".html"}),
        **TEMPLATE_XSS,
    ),
]


class XSSBreaker(BaseBreaker):

    name = "XSSBreaker"
    description = (
        "Cross-site scripting: innerHTML, dangerouslySetInnerHTML, v-html, "
        "{@html}, |safe, unescaped template output, reflected request data"
    )
    prompt_file = "XSS.txt"
    trigger_technologies = FRONTEND_TECHNOLOGIES | {"Express", "Flask", "Django", "FastAPI"}
    trigger_files = ("*.html", "*.ejs", "*.hbs", "*.jinja", "*.jinja2", "*.j2", "*.njk")
    extensions = CODE_EXTENSIONS | TEMPLATE_EXTENSIONS

    def refine(self, finding, rule, match, code):
        """Lower the score when the file visibly sanitises its HTML."""

        if rule.cwe == "CWE-79" and SANITIZER.search(code):
            finding.severity = "LOW"
            finding.confidence = round(finding.confidence * 0.5, 2)
            finding.explanation += (
                " A sanitiser is used in this file; confirm it is applied "
                "to this exact value."
            )

        return finding

    def scan_file(self, file_path: Path, content: str):
        return self.scan_rules(file_path, content, RULES)


if __name__ == "__main__":
    XSSBreaker.cli()
