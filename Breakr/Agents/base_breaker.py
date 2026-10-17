"""
Shared foundation for every Breakr agent.

An agent subclasses BaseBreaker and implements scan_file()
(and optionally scan_project() for project-wide checks).

BaseBreaker takes care of:
- walking the project while skipping dependencies, build
  output, binaries, lockfiles and minified bundles
- reading files safely
- blanking out comments so commented-out code is not reported
- turning regex Rules into Finding objects with line numbers
"""

from bisect import bisect_left
from dataclasses import dataclass
from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path, PurePosixPath
import os
import re
import subprocess

from Models.Finding import Finding


# -------------------------
# What to skip
# -------------------------

IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "bower_components",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "site-packages",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".output",
    ".vercel",
    ".turbo",
    ".cache",
    ".parcel-cache",
    "dist",
    "build",
    "out",
    "coverage",
    "vendor",
    "target",
    ".terraform",
    ".idea",
    ".vscode",
}

IGNORED_FILE_PATTERNS = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "composer.lock",
    "cargo.lock",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.chunk.js",
    "*.bundle.js",
]

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".o", ".a",
    ".pyc", ".pyo", ".whl", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".ogg", ".webm",
    ".sqlite", ".sqlite3", ".db", ".lockb",
}

MAX_FILE_SIZE = 1_000_000

# Test code, fixtures and examples: still scanned, but findings there
# are less likely to be exploitable and get a lower confidence.
TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|fixtures?|__fixtures__|mocks?|__mocks__|examples?|e2e|cypress)(/|$)"
    r"|\.(test|spec|stories)\.\w+$|_test\.(py|go)$|(^|/)test_\w+\.py$|(^|/)conftest\.py$"
    r"|(^|/)(seeds?|seeders?)(/|$)|(^|/)seed\w*\.\w+$",
    re.IGNORECASE,
)


# -------------------------
# File groups agents can target
# -------------------------

JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
PYTHON_EXTENSIONS = {".py"}
COMPONENT_EXTENSIONS = {".vue", ".svelte", ".astro"}
OTHER_CODE_EXTENSIONS = {".php", ".rb", ".go", ".java", ".kt", ".cs"}

CODE_EXTENSIONS = (
    JS_EXTENSIONS
    | PYTHON_EXTENSIONS
    | COMPONENT_EXTENSIONS
    | OTHER_CODE_EXTENSIONS
)

TEMPLATE_EXTENSIONS = {
    ".html", ".htm", ".ejs", ".hbs", ".handlebars", ".mustache",
    ".jinja", ".jinja2", ".j2", ".njk", ".twig", ".erb", ".liquid",
}

CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".xml", ".env", "dockerfile",
}


# -------------------------
# Technology groups used for agent selection
# -------------------------

BACKEND_TECHNOLOGIES = {
    "Express", "Fastify", "Koa", "NestJS", "Next.js", "Nuxt",
    "SvelteKit", "Remix", "Flask", "Django", "FastAPI",
}

FRONTEND_TECHNOLOGIES = {
    "React", "Next.js", "Vue", "Nuxt", "Angular", "Svelte",
    "SvelteKit", "Remix", "Astro",
}

WEB_TECHNOLOGIES = BACKEND_TECHNOLOGIES | {"Node.js", "Python"}


# -------------------------
# Comment stripping
# -------------------------

# Group 1 = string literal (kept), group 2 = comment (blanked).
# Matching strings first stops "//" inside URLs from being
# treated as a comment.
_C_STYLE_TOKENS = re.compile(
    r"(\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)"
    r"|(//[^\n]*|/\*.*?\*/)",
    re.DOTALL,
)

_HASH_TOKENS = re.compile(
    r"(\"\"\"(?:\\.|[^\\])*?\"\"\"|'''(?:\\.|[^\\])*?'''"
    r"|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*')"
    r"|(#[^\n]*)",
    re.DOTALL,
)

_SQL_TOKENS = re.compile(
    r"('(?:''|[^'])*')"
    r"|(--[^\n]*|/\*.*?\*/)",
    re.DOTALL,
)

_MARKUP_COMMENTS = re.compile(r"<!--.*?-->", re.DOTALL)

_C_STYLE_SUFFIXES = (
    JS_EXTENSIONS
    | {".java", ".kt", ".cs", ".go", ".c", ".cc", ".cpp", ".h",
       ".swift", ".scss", ".rules", ".php"}
)

_HASH_SUFFIXES = {
    ".py", ".rb", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".toml",
    ".cfg", ".conf", ".r", ".tf", ".ps1",
}


def _blank(text: str) -> str:
    """Replace every character except newlines with a space."""

    return re.sub(r"[^\n]", " ", text)


def _strip_with(pattern, content: str) -> str:

    def replace(match):
        if match.group(1) is not None:
            return match.group(1)
        return _blank(match.group(2))

    return pattern.sub(replace, content)


def _blank_string_contents(match):
    """Keep a string literal's quotes (and f/r prefix context) but blank its body."""

    if match.group(1) is None:
        return _blank(match.group(2))

    literal = match.group(1)
    quote = 3 if literal[:3] in ('"""', "'''") else 1

    return literal[:quote] + _blank(literal[quote:-quote]) + literal[-quote:]


def strip_strings(code: str, path: Path) -> str:
    """
    Blank the contents of string literals (and comments) so rules that
    look for code constructs don't fire on text inside strings.
    Offsets and line numbers are preserved.
    """

    suffix = path.suffix.lower()

    if suffix in _C_STYLE_SUFFIXES or suffix in COMPONENT_EXTENSIONS:
        return _C_STYLE_TOKENS.sub(_blank_string_contents, code)

    if suffix in _HASH_SUFFIXES:
        return _HASH_TOKENS.sub(_blank_string_contents, code)

    return code


def is_env_file(name: str) -> bool:
    name = name.lower()
    return name == ".env" or name.startswith(".env.")


def strip_comments(content: str, path: Path) -> str:
    """
    Blank out comments while keeping every character offset and
    line number identical, so matches still map to real lines.
    """

    suffix = path.suffix.lower()
    name = path.name.lower()

    if suffix in COMPONENT_EXTENSIONS:
        content = _MARKUP_COMMENTS.sub(lambda m: _blank(m.group(0)), content)
        return _strip_with(_C_STYLE_TOKENS, content)

    if suffix in _C_STYLE_SUFFIXES:
        return _strip_with(_C_STYLE_TOKENS, content)

    if (
        suffix in _HASH_SUFFIXES
        or name == "dockerfile"
        or name.startswith("dockerfile.")
        or is_env_file(name)
        or name in {".gitignore", ".dockerignore", "requirements.txt"}
    ):
        return _strip_with(_HASH_TOKENS, content)

    if suffix == ".sql":
        return _strip_with(_SQL_TOKENS, content)

    if suffix in TEMPLATE_EXTENSIONS or suffix in {".xml", ".svg"}:
        return _MARKUP_COMMENTS.sub(lambda m: _blank(m.group(0)), content)

    return content


# -------------------------
# Project walking and reading
# -------------------------

def is_ignored_file(name: str) -> bool:
    name = name.lower()

    if Path(name).suffix in BINARY_EXTENSIONS:
        return True

    return any(
        fnmatch(name, pattern)
        for pattern in IGNORED_FILE_PATTERNS
    )


def walk_project(project_path: Path, excluded_paths=()):
    """
    Return every project file as a sorted list of POSIX-style
    paths relative to project_path. Ignored directories are
    pruned instead of walked, which keeps node_modules cheap.
    """

    project_path = Path(project_path).resolve()

    excluded = {
        Path(path).resolve()
        for path in excluded_paths
    }

    files = []

    for root, directories, file_names in os.walk(project_path):

        root_path = Path(root)

        directories[:] = [
            directory
            for directory in directories
            if directory not in IGNORED_DIRECTORIES
            and not directory.endswith(".egg-info")
            and (root_path / directory).resolve() not in excluded
        ]

        for file_name in file_names:

            full_path = root_path / file_name

            if full_path.resolve() in excluded:
                continue

            files.append(
                full_path.relative_to(project_path).as_posix()
            )

    return sorted(files)


def read_text_file(path: Path):
    """Return file text, or None for binaries, huge files and read errors."""

    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None

        data = path.read_bytes()

    except OSError:
        return None

    if b"\x00" in data[:8192]:
        return None

    return data.decode("utf-8", errors="ignore")


MINIFIABLE_EXTENSIONS = {".js", ".mjs", ".cjs", ".css"}


def looks_minified(content: str) -> bool:
    """Built bundles have very long lines; real source rarely averages >300 chars."""

    if len(content) < 2000:
        return False

    return len(content) / (content.count("\n") + 1) > 300


@lru_cache(maxsize=2048)
def _git_check_ignore(project_path: str, relative: str):
    """True/False from `git check-ignore`, or None if git can't answer."""

    try:
        result = subprocess.run(
            ["git", "-C", project_path, "check-ignore", "-q", "--", relative],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode in (0, 1):
        return result.returncode == 0

    return None  # 128: not a git repository


def _gitignore_fallback(project_path: Path, relative: str) -> bool:
    """Approximate git's rules using every .gitignore from the file up to the root."""

    path = PurePosixPath(relative)
    ignored = False

    for depth in range(len(path.parts) - 1, -1, -1):

        folder = PurePosixPath(*path.parts[:depth])
        gitignore = project_path / folder / ".gitignore"

        try:
            lines = gitignore.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        target = PurePosixPath(*path.parts[depth:]).as_posix()

        for raw in lines:

            pattern = raw.strip()

            if not pattern or pattern.startswith("#"):
                continue

            negated = pattern.startswith("!")
            pattern = pattern.lstrip("!").lstrip("/").rstrip("/")

            if fnmatch(target, pattern) or fnmatch(path.name, pattern) or target.startswith(pattern + "/"):
                ignored = not negated

    return ignored


def is_gitignored(project_path: Path, relative: str) -> bool:
    """Is this file excluded from git (and therefore not committed)?"""

    answer = _git_check_ignore(str(project_path), relative)

    if answer is None:
        return _gitignore_fallback(Path(project_path), relative)

    return answer


def file_matches(path: Path, extensions) -> bool:
    """Match a path against a set of suffixes / special names."""

    if extensions is None:
        return True

    name = path.name.lower()

    if path.suffix.lower() in extensions or name in extensions:
        return True

    if ".env" in extensions and is_env_file(name):
        return True

    if "dockerfile" in extensions and name.startswith("dockerfile"):
        return True

    return False


class LineIndex:
    """Fast character offset -> line number lookups."""

    def __init__(self, content: str):
        self.newlines = [
            match.start()
            for match in re.finditer("\n", content)
        ]
        self.lines = content.split("\n")

    def line_of(self, index: int) -> int:
        return bisect_left(self.newlines, index) + 1

    def text(self, line_number: int) -> str:
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1].rstrip("\r")
        return ""


def clip(text: str, limit: int = 180) -> str:
    text = text.strip()

    if len(text) <= limit:
        return text

    return text[:limit - 3] + "..."


def mask_secret(value: str) -> str:
    """Keep a short prefix so the secret is recognisable, hide the rest."""

    if len(value) <= 6:
        return "*" * len(value)

    return value[:4] + "*" * min(len(value) - 4, 12)


# -------------------------
# Rules
# -------------------------

@dataclass
class Rule:
    """
    A single regex check.

    pattern       regex run against the comment-stripped file
    extensions    only run on these file types (None = every file
                  the agent reads)
    exclude       skip the match when this regex matches the line
    code_only     ignore matches inside string literals (for rules
                  that look for code constructs, not string values)
    """

    title: str
    pattern: str
    severity: str
    confidence: float
    explanation: str
    recommendation: str
    cwe: str = ""
    extensions: frozenset | set | None = None
    exclude: str | None = None
    ignore_case: bool = True
    code_only: bool = False

    def __post_init__(self):

        flags = re.MULTILINE

        if self.ignore_case:
            flags |= re.IGNORECASE

        self.regex = re.compile(self.pattern, flags)

        self.exclude_regex = (
            re.compile(self.exclude, re.IGNORECASE)
            if self.exclude
            else None
        )


# -------------------------
# Base agent
# -------------------------

class BaseBreaker:

    # Display name used in findings and reports
    name = "BaseBreaker"

    # One line shown by --list-agents
    description = ""

    # Triage guide in Prompts/ that the AI reads when verifying findings
    prompt_file = ""

    # Selection: always run, or run when a technology / file is detected
    always_run = False
    trigger_technologies: set = set()
    trigger_files: tuple = ()

    # File types scan_file() receives (None = all text files)
    extensions = None

    def __init__(self, project_path: str, files=None, options=None):
        self.project_path = Path(project_path).resolve()
        self._files = files
        self.options = options or {}

    # -------------------------
    # Selection
    # -------------------------

    @classmethod
    def selection_reason(cls, profile):
        """
        Return why this agent should run on the project,
        or None if it is not relevant.
        """

        if cls.always_run:
            return "always runs"

        matched = sorted(
            set(profile.technologies) & cls.trigger_technologies
        )

        if matched:
            return ", ".join(matched) + " detected"

        for pattern in cls.trigger_files:
            for file in profile.files:

                name = file.rsplit("/", 1)[-1].lower()

                if fnmatch(name, pattern) or fnmatch(file.lower(), pattern):
                    return f"{name} found"

        return None

    # -------------------------
    # Files
    # -------------------------

    @property
    def files(self):
        if self._files is None:
            self._files = walk_project(self.project_path)
        return self._files

    def iter_files(self, extensions=None):
        """Yield absolute paths of files this agent should read."""

        wanted = extensions if extensions is not None else self.extensions

        for relative in self.files:

            path = self.project_path / relative

            if is_ignored_file(path.name):
                continue

            if not file_matches(path, wanted):
                continue

            yield path

    def relative(self, path: Path) -> str:
        return path.relative_to(self.project_path).as_posix()

    def read(self, path: Path):
        content = read_text_file(path)

        # Skip built/minified bundles: not your source, and slow to scan.
        if content and path.suffix.lower() in MINIFIABLE_EXTENSIONS and looks_minified(content):
            return None

        return content

    def is_gitignored(self, path: Path) -> bool:
        return is_gitignored(self.project_path, self.relative(path))

    # -------------------------
    # Scanning
    # -------------------------

    def scan(self):
        findings = []

        for path in self.iter_files():

            content = self.read(path)

            if content is None:
                continue

            findings.extend(
                self.scan_file(path, content)
            )

        findings.extend(self.scan_project())

        return findings

    def scan_file(self, file_path: Path, content: str):
        """Return findings for one file. Override in agents."""
        return []

    def scan_project(self):
        """Project-wide checks that are not tied to one file. Optional."""
        return []

    # -------------------------
    # Findings
    # -------------------------

    def make_finding(self, **fields):
        return Finding(
            agent=self.name,
            **fields
        )

    def rule_finding(self, rule: Rule, path: Path, line: int, evidence: str):
        return self.make_finding(
            title=rule.title,
            severity=rule.severity,
            confidence=rule.confidence,
            file=self.relative(path),
            line=line,
            evidence=clip(evidence),
            explanation=rule.explanation,
            recommendation=rule.recommendation,
            cwe=rule.cwe,
        )

    def refine(self, finding, rule, match, code):
        """
        Hook to adjust or drop a rule finding using context.
        Return None to discard it.
        """
        return finding

    def scan_rules(self, path: Path, content: str, rules, code=None):
        """Run Rules against a file and return one finding per rule per line."""

        if code is None:
            code = strip_comments(content, path)

        index = LineIndex(content)
        code_without_strings = None

        findings = []
        seen = set()

        for rule in rules:

            if not file_matches(path, rule.extensions):
                continue

            searched = code

            if rule.code_only:
                if code_without_strings is None:
                    code_without_strings = strip_strings(code, path)
                searched = code_without_strings

            for match in rule.regex.finditer(searched):

                line = index.line_of(match.start())

                if (rule.title, line) in seen:
                    continue

                text = index.text(line)

                if rule.exclude_regex and rule.exclude_regex.search(text):
                    continue

                finding = self.refine(
                    self.rule_finding(rule, path, line, text),
                    rule,
                    match,
                    searched,
                )

                if finding is None:
                    continue

                seen.add((rule.title, line))
                findings.append(finding)

        return findings

    # -------------------------
    # Standalone runs: python -m Agents.<module> [path]
    # -------------------------

    @classmethod
    def cli(cls):
        import sys

        target = sys.argv[1] if len(sys.argv) > 1 else "."

        findings = cls(target).scan()

        print(f"\n{cls.name.upper()}")
        print("=" * 40)

        if not findings:
            print("\nNo findings.")
            return

        print(f"\nPotential findings: {len(findings)}\n")

        for finding in sorted(findings, key=Finding.sort_key):

            print(f"[{finding.severity}] {finding.title}")
            print(f"  Location: {finding.file}:{finding.line}")
            print(f"  Confidence: {finding.confidence}")
            print(f"  Evidence: {finding.evidence}\n")
