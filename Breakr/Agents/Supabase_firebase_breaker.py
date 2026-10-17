"""
SupabaseFirebaseBreaker

Backend-as-a-service apps talk to the database straight from the
browser, so security depends entirely on (1) never shipping admin
keys to the client and (2) Row Level Security / Security Rules.

Checks:
- Supabase service_role keys (decoded from the JWT) or sb_secret_ keys
  in the repo, and service_role / firebase-admin used in client code
- secrets exposed through NEXT_PUBLIC_ / VITE_ / REACT_APP_ variables
- SQL migrations: tables without RLS, RLS disabled, USING (true)
  policies, grants to anon, SECURITY DEFINER without search_path
- Firebase rules: open read/write, test-mode expiry rules, rules
  that only check "signed in"
"""

from pathlib import Path, PurePosixPath
import base64
import json
import re

from Agents.base_breaker import (
    BaseBreaker,
    COMPONENT_EXTENSIONS,
    JS_EXTENSIONS,
    LineIndex,
    clip,
    is_env_file,
    mask_secret,
    strip_comments,
)


JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
SUPABASE_SECRET_KEY = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}")

PUBLIC_SECRET_ENV = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY|VUE_APP)_"
    r"\w*(?:SERVICE_ROLE|SERVICE_KEY|SECRET|PRIVATE_KEY|ADMIN_KEY)\w*"
)

SERVICE_ROLE_USAGE = re.compile(r"service_?role|SERVICE_ROLE|supabaseAdmin|SUPABASE_SECRET", re.IGNORECASE)
FIREBASE_ADMIN = re.compile(r"[\"']firebase-admin(?:/[\w-]+)?[\"']")
USE_CLIENT = re.compile(r"\A\s*[\"']use client[\"']")

DOC_EXTENSIONS = {".md", ".mdx", ".txt", ".rst", ".adoc"}

CLIENT_PATH = re.compile(
    r"(^|/)(components|hooks|public|static|client|frontend|web)/"
    r"|(^|/)pages/(?!api/)",
    re.IGNORECASE,
)

# -------------------------
# SQL
# -------------------------

CREATE_TABLE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?(?P<schema>\w+)\"?\.)?\"?(?P<table>\w+)\"?",
    re.IGNORECASE,
)
ENABLE_RLS = re.compile(
    r"alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:\"?\w+\"?\.)?\"?(?P<table>\w+)\"?\s+"
    r"(?:force\s+|enable\s+)row\s+level\s+security",
    re.IGNORECASE,
)
DISABLE_RLS = re.compile(
    r"alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:\"?\w+\"?\.)?\"?(?P<table>\w+)\"?\s+"
    r"disable\s+row\s+level\s+security",
    re.IGNORECASE,
)
POLICY = re.compile(r"create\s+policy\b[^;]*;", re.IGNORECASE | re.DOTALL)
ALWAYS_TRUE = re.compile(r"(?:using|with\s+check)\s*\(\s*\(?\s*true\s*\)?\s*\)", re.IGNORECASE)
POLICY_COMMAND = re.compile(r"\bfor\s+(select|insert|update|delete|all)\b", re.IGNORECASE)
GRANT_ANON = re.compile(r"grant\s+(?:all|insert|update|delete|truncate)[^;]*\bto\s+(?:anon|public)\b", re.IGNORECASE)
SECURITY_DEFINER = re.compile(r"create\s+(?:or\s+replace\s+)?function\b[^;]*?security\s+definer[^;]*", re.IGNORECASE | re.DOTALL)

NON_PUBLIC_SCHEMAS = {"auth", "storage", "private", "extensions", "realtime", "graphql", "pgsodium", "vault", "supabase_functions", "cron", "net"}

# -------------------------
# Firebase rules
# -------------------------

ALLOW_RULE = re.compile(r"allow\s+(?P<ops>[\w\s,]+?)\s*(?::\s*if\s+(?P<condition>[^;]+))?;")
TEST_MODE = re.compile(r"request\.time\s*<\s*timestamp\.date\(")
RECURSIVE_MATCH = re.compile(r"match\s+/\{\w+=\*\*\}")
SIGNED_IN_ONLY = re.compile(r"^\s*request\.auth\s*!=\s*null\s*$")
RTDB_RULE = re.compile(r"\"\.(?P<op>read|write)\"\s*:\s*(?P<value>true|\"true\"|\"auth\s*!=\s*null\"|\"auth\s*!==\s*null\")")


def decode_jwt_payload(token: str):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, IndexError, json.JSONDecodeError):
        return None


class SupabaseFirebaseBreaker(BaseBreaker):

    name = "SupabaseFirebaseBreaker"
    description = (
        "Supabase service_role keys in the client, tables without RLS, "
        "USING (true) policies, open Firebase security rules"
    )
    prompt_file = "SupabaseFirebase.txt"
    trigger_technologies = {"Supabase", "Firebase"}
    trigger_files = (
        "firestore.rules", "storage.rules", "database.rules.json",
        "firebase.json", "supabase/*",
    )

    def scan(self):
        self._tables = {}
        self._rls_tables = set()
        self._sql_files = 0
        return super().scan()

    # -------------------------
    # Helpers
    # -------------------------

    def is_client_file(self, relative: str, code: str):

        suffix = PurePosixPath(relative).suffix.lower()

        if suffix in COMPONENT_EXTENSIONS or USE_CLIENT.search(code):
            return True

        return suffix in JS_EXTENSIONS and bool(CLIENT_PATH.search(relative))

    def is_safe_env_location(self, file_path: Path):
        """Server-only .env files that git ignores are the right place for secrets."""

        return is_env_file(file_path.name) and self.is_gitignored(file_path)

    def finding(self, relative, line, evidence, title, severity, confidence, explanation, recommendation, cwe):
        return self.make_finding(
            title=title,
            severity=severity,
            confidence=confidence,
            file=relative,
            line=line,
            evidence=clip(evidence),
            explanation=explanation,
            recommendation=recommendation,
            cwe=cwe,
        )

    # -------------------------
    # Per-file checks
    # -------------------------

    def scan_file(self, file_path: Path, content: str):

        relative = self.relative(file_path)
        name = file_path.name.lower()
        suffix = file_path.suffix.lower()

        if suffix == ".sql":
            return self.scan_sql(file_path, relative, content)

        if suffix == ".rules" or name in {"firestore.rules", "storage.rules"}:
            return self.scan_firebase_rules(relative, content)

        if name == "database.rules.json":
            return self.scan_realtime_rules(relative, content)

        # Docs often mention key names as warnings; only scan code and config.
        if suffix in DOC_EXTENSIONS:
            return []

        return self.scan_keys(file_path, relative, content)

    def scan_keys(self, file_path, relative, content):

        findings = []
        index = LineIndex(content)
        code = strip_comments(content, file_path)
        safe_env = self.is_safe_env_location(file_path)
        is_client = self.is_client_file(relative, code)

        # Supabase service_role JWTs / sb_secret_ keys committed to the repo.
        if not safe_env:

            for match in JWT.finditer(content):

                payload = decode_jwt_payload(match.group(0))

                if not payload or payload.get("role") != "service_role":
                    continue

                line = index.line_of(match.start())

                findings.append(self.finding(
                    relative, line,
                    index.text(line).replace(match.group(0), mask_secret(match.group(0))),
                    "Supabase service_role key committed to the repository",
                    "CRITICAL", 0.95,
                    "This key's payload says role=service_role. It bypasses "
                    "every Row Level Security policy and gives full read/write "
                    "access to the whole database.",
                    "Rotate the key in the Supabase dashboard now, move it to "
                    "a server-only environment variable, and never import it "
                    "into browser code.",
                    "CWE-798",
                ))

            for match in SUPABASE_SECRET_KEY.finditer(content):

                line = index.line_of(match.start())

                findings.append(self.finding(
                    relative, line,
                    index.text(line).replace(match.group(0), mask_secret(match.group(0))),
                    "Supabase secret key committed to the repository",
                    "CRITICAL", 0.95,
                    "sb_secret_ keys have elevated (service_role) privileges "
                    "and bypass Row Level Security.",
                    "Revoke the key in the Supabase dashboard, use a server-only "
                    "env variable, and never expose it to the browser.",
                    "CWE-798",
                ))

        # Secrets in env variables that bundlers inline into browser code.
        for match in PUBLIC_SECRET_ENV.finditer(code):

            line = index.line_of(match.start())

            findings.append(self.finding(
                relative, line, index.text(line),
                "Secret exposed through a public browser env variable",
                "CRITICAL", 0.8,
                f"{match.group(0)} uses a prefix that Next.js / Vite / CRA / "
                "Expo inline into the JavaScript bundle, so every visitor can "
                "read this secret.",
                "Remove the public prefix, read the secret only in server code "
                "(API routes, server actions, edge functions), and rotate it.",
                "CWE-200",
            ))

        if is_client:

            match = SERVICE_ROLE_USAGE.search(code)

            if match:
                line = index.line_of(match.start())

                findings.append(self.finding(
                    relative, line, index.text(line),
                    "Supabase service_role key used in client-side code",
                    "HIGH", 0.7,
                    "This file runs in the browser but references the service "
                    "role / admin client. Anything the browser can use, users "
                    "can extract and use to bypass RLS.",
                    "Use the anon/publishable key with RLS in client code. Move "
                    "privileged operations to a server route or edge function "
                    "that checks the user first.",
                    "CWE-602",
                ))

            match = FIREBASE_ADMIN.search(code)

            if match:
                line = index.line_of(match.start())

                findings.append(self.finding(
                    relative, line, index.text(line),
                    "firebase-admin imported in client-side code",
                    "HIGH", 0.7,
                    "The Admin SDK ignores Security Rules and needs service "
                    "account credentials; it must never run in the browser.",
                    "Use the client Firebase SDK in the browser and keep "
                    "firebase-admin in server code or Cloud Functions.",
                    "CWE-602",
                ))

        return findings

    # -------------------------
    # Supabase SQL
    # -------------------------

    def scan_sql(self, file_path, relative, content):

        findings = []
        code = strip_comments(content, file_path)
        index = LineIndex(content)
        self._sql_files += 1

        for match in CREATE_TABLE.finditer(code):

            schema = (match.group("schema") or "public").lower()

            if schema in NON_PUBLIC_SCHEMAS:
                continue

            table = match.group("table").lower()
            line = index.line_of(match.start())
            self._tables.setdefault(table, (relative, line, index.text(line)))

        for match in ENABLE_RLS.finditer(code):
            self._rls_tables.add(match.group("table").lower())

        for match in DISABLE_RLS.finditer(code):

            line = index.line_of(match.start())

            findings.append(self.finding(
                relative, line, index.text(line),
                "Row Level Security disabled on a table",
                "HIGH", 0.85,
                "With RLS disabled, anyone holding the public anon key (i.e. "
                "every visitor) can read and write every row in this table "
                "through the Supabase API.",
                "Re-enable RLS and add policies scoped to auth.uid().",
                "CWE-284",
            ))

        for match in POLICY.finditer(code):

            statement = match.group(0)

            if not ALWAYS_TRUE.search(statement):
                continue

            command = POLICY_COMMAND.search(statement)
            command = command.group(1).lower() if command else "all"
            line = index.line_of(match.start())
            authenticated_only = re.search(r"\bto\s+authenticated\b", statement, re.IGNORECASE)
            who = "any logged-in user" if authenticated_only else "anyone"

            if command == "select":
                title, severity, confidence = f"RLS policy lets {who} read every row", "MEDIUM", 0.6
                impact = "read every row in this table"
            else:
                title, severity, confidence = f"RLS policy lets {who} modify every row", "HIGH", 0.8
                impact = f"run {command.upper()} on every row in this table"

            findings.append(self.finding(
                relative, line, index.text(line),
                title, severity, confidence,
                f"The policy condition is always true, so {who} can {impact}. "
                "RLS is enabled but provides no protection here.",
                "Scope the policy to the row owner, e.g. USING (auth.uid() = "
                "user_id) and WITH CHECK (auth.uid() = user_id). Keep "
                "USING (true) only for data that is truly public and read-only.",
                "CWE-284",
            ))

        for match in GRANT_ANON.finditer(code):

            line = index.line_of(match.start())

            findings.append(self.finding(
                relative, line, index.text(line),
                "Write privileges granted to anonymous users",
                "HIGH", 0.7,
                "The anon role is what unauthenticated visitors use. Granting it "
                "write privileges means only RLS stands between visitors and "
                "your data.",
                "Revoke write grants from anon/public and grant only what each "
                "role needs.",
                "CWE-732",
            ))

        for match in SECURITY_DEFINER.finditer(code):

            if re.search(r"set\s+search_path", match.group(0), re.IGNORECASE):
                continue

            line = index.line_of(match.start())

            findings.append(self.finding(
                relative, line, index.text(line),
                "SECURITY DEFINER function without a fixed search_path",
                "LOW", 0.6,
                "SECURITY DEFINER functions run with the owner's privileges and "
                "bypass RLS. Without a fixed search_path they can be hijacked, "
                "and if exposed via the API they can leak data.",
                "Add SET search_path = '' (and fully qualify names), and check "
                "the caller's identity inside the function.",
                "CWE-269",
            ))

        return findings

    # -------------------------
    # Firebase rules
    # -------------------------

    def scan_firebase_rules(self, relative, content):

        findings = []
        code = strip_comments(content, Path(relative + ".js"))
        index = LineIndex(content)
        recursive = bool(RECURSIVE_MATCH.search(code))

        for match in TEST_MODE.finditer(code):

            line = index.line_of(match.start())

            findings.append(self.finding(
                relative, line, index.text(line),
                "Firebase rules in test mode (open until a date)",
                "HIGH", 0.85,
                "Test-mode rules let anyone read and write all data until the "
                "timestamp passes; after that the app breaks.",
                "Replace with rules that check request.auth.uid against the "
                "document owner for every collection.",
                "CWE-284",
            ))

        for match in ALLOW_RULE.finditer(code):

            operations = {op.strip() for op in match.group("ops").split(",")}
            condition = (match.group("condition") or "true").strip()
            line = index.line_of(match.start())
            writes = operations & {"write", "create", "update", "delete"}

            if condition == "true":
                findings.append(self.finding(
                    relative, line, index.text(line),
                    "Firebase rule allows public " + ("write" if writes else "read"),
                    "CRITICAL" if writes else "HIGH",
                    0.9,
                    "This rule has no condition, so anyone on the internet can "
                    + ("modify or delete this data." if writes else "read this data."),
                    "Require request.auth != null AND an ownership check such as "
                    "request.auth.uid == resource.data.userId.",
                    "CWE-284",
                ))

            elif recursive and SIGNED_IN_ONLY.match(condition):
                findings.append(self.finding(
                    relative, line, index.text(line),
                    "Firebase rule lets any signed-in user access all data",
                    "MEDIUM", 0.65,
                    "A recursive wildcard match only checks that the user is "
                    "signed in. Anyone can create an account and then read or "
                    "change every other user's documents.",
                    "Write per-collection rules that compare request.auth.uid "
                    "with the document's owner field.",
                    "CWE-639",
                ))

        return findings

    def scan_realtime_rules(self, relative, content):

        findings = []
        index = LineIndex(content)

        for match in RTDB_RULE.finditer(content):

            line = index.line_of(match.start())
            write = match.group("op") == "write"
            public = "auth" not in match.group("value")

            if public:
                title = f"Realtime Database allows public {match.group('op')}"
                severity = "CRITICAL" if write else "HIGH"
                explanation = "Anyone on the internet can " + ("change" if write else "read") + " this data."
            else:
                title = f"Realtime Database {match.group('op')} only requires sign-in"
                severity = "MEDIUM"
                explanation = "Any signed-in user can access this path, including other users' data."

            findings.append(self.finding(
                relative, line, index.text(line),
                title, severity, 0.8 if public else 0.6,
                explanation,
                "Use rules like \"auth != null && auth.uid === $uid\" scoped to each user's path.",
                "CWE-284",
            ))

        return findings

    # -------------------------
    # Project-wide: tables without RLS
    # -------------------------

    def scan_project(self):

        findings = []

        for table, (relative, line, text) in sorted(self._tables.items()):

            if table in self._rls_tables:
                continue

            findings.append(self.finding(
                relative, line, text,
                f"Table '{table}' created without Row Level Security",
                "HIGH", 0.75,
                "No ALTER TABLE ... ENABLE ROW LEVEL SECURITY was found for "
                "this table in any migration. Tables in the public schema are "
                "exposed through the Supabase API to anyone with the anon key.",
                f"Add: alter table {table} enable row level security; then "
                "create policies scoped to auth.uid(). (If RLS was enabled in "
                "the dashboard, add it to a migration so it is tracked.)",
                "CWE-284",
            ))

        return findings


if __name__ == "__main__":
    SupabaseFirebaseBreaker.cli()
