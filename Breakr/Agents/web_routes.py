"""
Route discovery and protection heuristics shared by
AuthBreaker and APIBreaker.

Supported route styles:
- Express / Fastify / Koa-router     app.get("/x", ...), router.post(...)
- Flask / FastAPI decorators         @app.route(...), @router.post(...)
- NestJS controllers                 @Get(), @Post(":id")
- Next.js App Router                 app/**/route.ts  export async function POST
- Next.js Pages API                  pages/api/**     export default handler
- Next.js Server Actions             "use server" files, exported functions

"Protection" is detected three ways:
1. inside the handler (session lookups, token checks, guards...)
2. for the whole file (router.use(auth), APIRouter(dependencies=...))
3. across files (app.use("/admin", requireAdmin, adminRouter) marks the
   file that adminRouter is imported from as protected)
"""

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
import re

from Agents.base_breaker import (
    JS_EXTENSIONS,
    PYTHON_EXTENSIONS,
    read_text_file,
    strip_comments,
)


STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE", "ANY", "ALL"}

# Routes that are meant to be reachable without logging in.
PUBLIC_ROUTE = re.compile(
    r"log-?in|sign-?in|sign-?up|register|log-?out|sign-?out|forgot|reset|"
    r"verify|confirm|callback|oauth|webhook|token|refresh|health|status|"
    r"ping|contact|subscribe|newsletter|public|csrf|captcha|otp|magic",
    re.IGNORECASE,
)

SENSITIVE_ROUTE = re.compile(
    r"admin|user|account|payment|billing|invoice|order|customer|profile|"
    r"database|\bdb\b|internal|private|secret|export|report|settings|"
    r"member|employee|salary|transaction|wallet|credential|key|upload|"
    r"delete|config",
    re.IGNORECASE,
)

AUTHENTICATION = re.compile(
    r"authenticat"
    r"|login_required|loginrequired|require_?login|ensure_?logged_?in"
    r"|require_?auth|require_?user|with_?auth|withapiauth|auth_required"
    r"|token_required|jwt_required|verify_jwt_in_request"
    r"|verify_?(?:jwt|token|id_?token|session|auth|user|access)"
    r"|jwt\.verify|jwtverify|decode_?token"
    r"|getserversession|get_?session\s*\(|auth\s*\(\s*\)|currentuser\s*\("
    r"|get_current_(?:active_)?user|current_user\b|g\.user\b"
    r"|depends\(\s*(?:get_current|auth|verify|oauth2|security|require|current)"
    r"|oauth2passwordbearer|httpbearer|apikeyheader"
    r"|\.auth\.get(?:user|session|claims)|getauth\s*\(|verifyidtoken"
    r"|checkauth|isloggedin|is_logged_in|requiresession"
    r"|withpageauthrequired|withapiauthrequired"
    r"|@useguards|authguard|@preauthorize|@secured"
    r"|permission_classes|@permission_required"
    r"|request\.user|req\.user\b|req\.auth\b|request\.auth\b"
    r"|req\.session\.(?:user|userid|user_id)|session\[[\"']user"
    r"|x-api-key|headers\.authorization|headers\[[\"']authorization"
    r"|headers\.get\(\s*[\"']authorization",
    re.IGNORECASE,
)

AUTHORIZATION = re.compile(
    r"\broles?\b|isadmin|is_admin|is_staff|is_superuser|hasrole|has_role"
    r"|checkrole|check_role|requirerole|require_role|requireadmin"
    r"|require_admin|admin_required|adminonly|admin_only|@roles|rolesguard"
    r"|permission|authori[sz]|\bcan\s*\(|ability|policy"
    r"|\bowner(?:id|_id)?\b"
    r"|user_?id\s*(?:===?|!==?)\s*(?:req|request|current|session|user)",
    re.IGNORECASE,
)

# Middleware names in .use(...) calls that look like auth.
_AUTH_MIDDLEWARE = re.compile(
    r"auth|protect|verify|jwt|token|guard|login|clerk|passport|ensure|"
    r"require|admin|role|permission|restrict",
    re.IGNORECASE,
)

_AUTHZ_MIDDLEWARE = re.compile(
    r"admin|role|permission|authori[sz]|restrict",
    re.IGNORECASE,
)

_NOT_MIDDLEWARE = re.compile(
    r"(routes?|router|controller|handlers?|api)$",
    re.IGNORECASE,
)

# Common middleware whose names contain auth-ish words but enforce nothing.
_NOT_AUTH_MIDDLEWARE = re.compile(
    r"initiali[sz]e|csrf|cors|helmet|limit|static|json|urlencoded|"
    r"cookie|bodyparser|morgan|logger|compression",
    re.IGNORECASE,
)


@dataclass
class Route:
    methods: tuple
    path: str
    index: int
    block_start: int
    line: int
    framework: str

    @property
    def method_label(self):
        return "/".join(self.methods)

    @property
    def is_state_changing(self):
        return any(
            method in STATE_CHANGING_METHODS
            for method in self.methods
        )

    @property
    def is_read(self):
        return "GET" in self.methods

    @property
    def is_public(self):
        return bool(PUBLIC_ROUTE.search(self.path))

    @property
    def is_sensitive(self):
        return bool(SENSITIVE_ROUTE.search(self.path))

    @property
    def is_admin(self):
        return "admin" in self.path.lower()


# -------------------------
# Route patterns
# -------------------------

_EXPRESS = re.compile(
    r"\b(?:app|server|fastify|\w*[rR]outer|routes?)\s*\.\s*"
    r"(?P<method>get|post|put|patch|delete|all)\s*\(\s*"
    r"(?P<q>[\"'`])(?P<path>/[^\"'`]*|\*)(?P=q)"
)

_EXPRESS_CHAIN = re.compile(
    r"(?<!@)\b\w+\s*\.\s*route\s*\(\s*(?P<q>[\"'`])(?P<path>/[^\"'`]*)(?P=q)\s*\)"
)

_DECORATOR = re.compile(
    r"^[ \t]*@(?P<obj>\w+(?:\.\w+)*)\.(?P<method>get|post|put|patch|delete|route|api_route)"
    r"\(\s*(?:(?:path|rule)\s*=\s*)?(?P<q>[\"'])(?P<path>[^\"']*)(?P=q)(?P<rest>[^\n]*)",
    re.MULTILINE,
)

_DECORATOR_METHODS = re.compile(r"methods\s*=\s*[\[(]([^\])]*)[\])]", re.IGNORECASE)

_NEST = re.compile(
    r"^[ \t]*@(?P<method>Get|Post|Put|Patch|Delete|All)\(\s*"
    r"(?:(?P<q>[\"'`])(?P<path>[^\"'`]*)(?P=q))?\s*\)",
    re.MULTILINE,
)

_NEST_CONTROLLER = re.compile(r"@Controller\(\s*(?:[\"'`]([^\"'`]*)[\"'`])?")

_NEXT_APP = re.compile(
    r"^export\s+(?:async\s+)?function\s+(?P<method>GET|POST|PUT|PATCH|DELETE)\b"
    r"|^export\s+const\s+(?P<method2>GET|POST|PUT|PATCH|DELETE)\s*=",
    re.MULTILINE,
)

_USE_SERVER = re.compile(r"\A\s*[\"']use server[\"']")

_SERVER_ACTION = re.compile(
    r"^export\s+(?:async\s+)?function\s+(?P<name>\w+)"
    r"|^export\s+const\s+(?P<name2>\w+)\s*=\s*async",
    re.MULTILINE,
)

_EXPORT_DEFAULT = re.compile(r"^export\s+default\b", re.MULTILINE)


def _line_of(code: str, index: int) -> int:
    return code.count("\n", 0, index) + 1


def _decorator_block_start(code: str, index: int) -> int:
    """Walk upwards over stacked @decorator lines directly above index."""

    start = code.rfind("\n", 0, index) + 1

    while start > 0:

        previous_start = code.rfind("\n", 0, start - 1) + 1
        previous_line = code[previous_start:start - 1].strip()

        if previous_line.startswith("@"):
            start = previous_start
        else:
            break

    return start


def _next_route_path(relative_path: str, marker: str) -> str:
    """app/api/users/[id]/route.ts -> /api/users/[id]"""

    parts = list(PurePosixPath(relative_path).parts)

    if marker not in parts:
        return "/" + relative_path

    parts = parts[parts.index(marker) + 1:]

    if parts and marker == "app":
        parts = parts[:-1]

    if parts and marker == "pages":
        parts[-1] = PurePosixPath(parts[-1]).stem
        if parts[-1] == "index":
            parts = parts[:-1]

    parts = [
        part
        for part in parts
        if not (part.startswith("(") and part.endswith(")"))
    ]

    return "/" + "/".join(parts)


def find_routes(code: str, relative_path: str):
    """Return every route defined in a (comment-stripped) file."""

    routes = []
    seen_lines = set()
    name = PurePosixPath(relative_path).name.lower()
    parts = [part.lower() for part in PurePosixPath(relative_path).parts]

    def add(methods, path, index, block_start, framework):
        line = _line_of(code, index)

        if line in seen_lines:
            return

        seen_lines.add(line)

        routes.append(
            Route(
                methods=tuple(methods),
                path=path,
                index=index,
                block_start=block_start,
                line=line,
                framework=framework,
            )
        )

    # Python decorators (Flask, FastAPI, Quart, Sanic...)
    for match in _DECORATOR.finditer(code):

        method = match.group("method").upper()

        if method in {"ROUTE", "API_ROUTE"}:
            listed = _DECORATOR_METHODS.search(match.group("rest"))
            methods = (
                re.findall(r"[A-Za-z]+", listed.group(1).upper())
                if listed
                else ["GET"]
            )
        else:
            methods = [method]

        add(
            methods,
            match.group("path") or "/",
            match.start("method"),
            _decorator_block_start(code, match.start()),
            "python",
        )

    # NestJS
    if "@Controller" in code:

        controller = _NEST_CONTROLLER.search(code)
        prefix = (controller.group(1) or "") if controller else ""

        for match in _NEST.finditer(code):

            path = "/".join(
                part.strip("/")
                for part in (prefix, match.group("path") or "")
                if part
            )

            add(
                [match.group("method").upper()],
                "/" + path,
                match.start("method"),
                _decorator_block_start(code, match.start()),
                "nestjs",
            )

    # Express-style
    for match in _EXPRESS.finditer(code):
        add(
            [match.group("method").upper()],
            match.group("path"),
            match.start(),
            code.rfind("\n", 0, match.start()) + 1,
            "express",
        )

    for match in _EXPRESS_CHAIN.finditer(code):
        add(
            ["ALL"],
            match.group("path"),
            match.start(),
            code.rfind("\n", 0, match.start()) + 1,
            "express",
        )

    # Next.js App Router
    if name.startswith("route.") and "app" in parts:

        path = _next_route_path(relative_path.lower(), "app")

        for match in _NEXT_APP.finditer(code):
            add(
                [match.group("method") or match.group("method2")],
                path,
                match.start(),
                match.start(),
                "nextjs",
            )

    # Next.js Pages API routes
    if "pages" in parts and "api" in parts[parts.index("pages"):]:

        match = _EXPORT_DEFAULT.search(code)

        if match:
            add(
                ["ANY"],
                _next_route_path(relative_path.lower(), "pages"),
                match.start(),
                0,
                "nextjs",
            )

    # Next.js Server Actions: every exported function is a POST endpoint
    if _USE_SERVER.search(code):

        for match in _SERVER_ACTION.finditer(code):

            action = match.group("name") or match.group("name2")

            add(
                ["POST"],
                f"server action {action}()",
                match.start(),
                match.start(),
                "nextjs-server-action",
            )

    routes.sort(key=lambda route: route.index)

    return routes


def handler_window(code: str, routes, position: int, limit: int = 6000) -> str:
    """
    Approximate a route's handler: from its decorator stack to the
    start of the next route (or `limit` characters).
    """

    route = routes[position]

    end = (
        routes[position + 1].block_start
        if position + 1 < len(routes)
        else len(code)
    )

    end = max(end, route.index + 1)

    return code[route.block_start:min(end, route.index + limit)]


# -------------------------
# File-level protection
# -------------------------

_USE_CALL = re.compile(r"\.use\(([^;]*?)\)\s*;?\s*$", re.MULTILINE)

_FASTAPI_DEPENDENCIES = re.compile(
    r"(?:APIRouter|FastAPI)\([^)]*dependencies\s*=",
    re.DOTALL,
)

_BEFORE_REQUEST = re.compile(r"@\w+\.before_(?:app_)?request")


def _split_args(arguments: str):
    """Split call arguments on top-level commas."""

    parts, depth, current = [], 0, []

    for char in arguments:

        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1

        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    if current:
        parts.append("".join(current).strip())

    return parts


def _middleware_names(arguments: str):
    """Identifier-like names of non-string arguments to .use()."""

    names = []

    for argument in _split_args(arguments):

        if not argument or argument[0] in "\"'`":
            continue

        names.append(
            re.split(r"[\s(]", argument, maxsplit=1)[0]
        )

    return names


def use_call_protection(arguments: str):
    """
    Look at one .use(...) call.
    Returns (authn, authz, router_names).
    """

    authn = authz = False
    routers = []

    for name in _middleware_names(arguments):

        if _NOT_MIDDLEWARE.search(name.split(".")[-1]):
            routers.append(name)
            continue

        if name in {"session", "cookieSession", "expressSession"}:
            continue

        if _NOT_AUTH_MIDDLEWARE.search(name):
            continue

        if _AUTH_MIDDLEWARE.search(name):
            authn = True

        if _AUTHZ_MIDDLEWARE.search(name):
            authz = True

    return authn, authz, routers


def file_level_protection(code: str):
    """
    Detect protection that applies to every route in a file.
    Returns (authn, authz).
    """

    authn = authz = False

    for match in _USE_CALL.finditer(code):

        call_authn, call_authz, routers = use_call_protection(match.group(1))

        # router.use(requireAuth) with no router argument protects this file.
        if routers:
            continue

        authn = authn or call_authn
        authz = authz or call_authz

    if _FASTAPI_DEPENDENCIES.search(code):
        authn = True

    for match in _BEFORE_REQUEST.finditer(code):

        hook = code[match.start():match.start() + 800]

        if AUTHENTICATION.search(hook):
            authn = True

        if AUTHORIZATION.search(hook):
            authz = True

    first_controller = code.find("@Controller")
    guards = code.find("@UseGuards")

    if 0 <= guards < first_controller:
        authn = True

    return authn, authz


# -------------------------
# Cross-file protection
# -------------------------

_JS_IMPORT = re.compile(
    r"import\s+(?P<default>\w+)?\s*,?\s*(?:\{(?P<named>[^}]*)\})?\s*from\s*[\"'](?P<module>[^\"']+)[\"']"
    r"|(?:const|let|var)\s+(?P<required>\w+)\s*=\s*require\(\s*[\"'](?P<rmodule>[^\"']+)[\"']\s*\)"
)

_INCLUDE_ROUTER = re.compile(
    r"include_router\(\s*(?P<module>\w+)\.\w+(?P<rest>[^)]*)\)",
)

_JS_RESOLVE_SUFFIXES = (
    "", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx",
    "/index.js", "/index.ts", "/index.mjs",
)


def _resolve_js_module(importer: str, module: str, files: set):

    if not module.startswith("."):
        return None

    base = PurePosixPath(importer).parent / module

    parts = []
    for part in base.parts:
        if part == "..":
            if parts:
                parts.pop()
        elif part != ".":
            parts.append(part)

    base_path = "/".join(parts)

    for suffix in _JS_RESOLVE_SUFFIXES:
        candidate = base_path + suffix
        if candidate in files:
            return candidate

    return None


@lru_cache(maxsize=8)
def project_protection(project_path: str, files: tuple):
    """
    Map relative file path -> (authn, authz) for router files that
    are mounted behind auth middleware somewhere else.

    Also returns whether a Next.js middleware file performs auth.
    """

    root = Path(project_path)
    file_set = set(files)
    protected = {}
    next_middleware_auth = False

    for relative in files:

        path = PurePosixPath(relative)
        suffix = path.suffix.lower()

        if suffix not in JS_EXTENSIONS and suffix not in PYTHON_EXTENSIONS:
            continue

        content = read_text_file(root / relative)

        if not content:
            continue

        code = strip_comments(content, Path(relative))

        # Next.js middleware.ts / src/middleware.ts
        if path.stem == "middleware" and len(path.parts) <= 2 and suffix in JS_EXTENSIONS:
            if AUTHENTICATION.search(code) or re.search(
                r"getToken|clerkMiddleware|withAuth|supabase|session|auth",
                code,
                re.IGNORECASE,
            ):
                next_middleware_auth = True

        if suffix in JS_EXTENSIONS and ".use(" in code:

            imports = {}

            for match in _JS_IMPORT.finditer(code):

                module = match.group("module") or match.group("rmodule")
                names = []

                if match.group("default"):
                    names.append(match.group("default"))

                if match.group("required"):
                    names.append(match.group("required"))

                if match.group("named"):
                    names.extend(
                        name.split(" as ")[-1].strip()
                        for name in match.group("named").split(",")
                        if name.strip()
                    )

                target = _resolve_js_module(relative, module, file_set)

                if target:
                    for name in names:
                        imports[name] = target

            for match in _USE_CALL.finditer(code):

                authn, authz, routers = use_call_protection(match.group(1))

                if not (authn or authz):
                    continue

                for router in routers:

                    target = imports.get(router.split(".")[0])

                    if target:
                        previous = protected.get(target, (False, False))
                        protected[target] = (
                            previous[0] or authn or authz,
                            previous[1] or authz,
                        )

        if suffix in PYTHON_EXTENSIONS and "include_router" in code:

            for match in _INCLUDE_ROUTER.finditer(code):

                rest = match.group("rest")

                if "dependencies" not in rest:
                    continue

                authz = bool(AUTHORIZATION.search(rest))

                for candidate in files:
                    if PurePosixPath(candidate).stem == match.group("module"):
                        protected[candidate] = (True, authz)

    return protected, next_middleware_auth
