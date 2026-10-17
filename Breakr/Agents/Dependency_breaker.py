"""
DependencyBreaker

Reads package.json, requirements*.txt, pyproject.toml and Pipfile
(plus package-lock / yarn / pnpm / poetry / uv lockfiles for the
versions actually installed) and reports:

- dependencies with a known vulnerability (built-in advisory list,
  or live OSV.dev data with --osv)
- dependencies that are not pinned at all (*, latest, git URLs)
- JavaScript projects with no lockfile
"""

from pathlib import Path, PurePosixPath
import json
import re
import tomllib
import urllib.error
import urllib.request

from Agents.base_breaker import BaseBreaker, read_text_file


# -------------------------
# Built-in advisories
# -------------------------
# (ecosystem, package, [(introduced, fixed), ...], severity, ids, summary)
# A version is affected when introduced <= version < fixed.
# This is a small curated list of high-impact issues, not a full
# database. Use --osv (or npm audit / pip-audit) for full coverage.

NO_FIX = "999999"

ADVISORIES = [
    # npm
    ("npm", "next", [("11.1.4", "12.3.5"), ("13.0.0", "13.5.9"), ("14.0.0", "14.2.25"), ("15.0.0", "15.2.3")],
     "CRITICAL", "CVE-2025-29927", "Middleware authorization bypass via the x-middleware-subrequest header"),
    ("npm", "lodash", [("0", "4.17.21")],
     "HIGH", "CVE-2021-23337, CVE-2020-8203", "Command injection in _.template and prototype pollution"),
    ("npm", "minimist", [("0", "0.2.4"), ("1.0.0", "1.2.6")],
     "HIGH", "CVE-2021-44906", "Prototype pollution"),
    ("npm", "axios", [("0", "0.30.0"), ("1.0.0", "1.8.2")],
     "MEDIUM", "CVE-2023-45857, CVE-2025-27152", "XSRF-TOKEN leak to third-party hosts and SSRF via absolute URLs"),
    ("npm", "jsonwebtoken", [("0", "9.0.0")],
     "HIGH", "CVE-2022-23529, CVE-2022-23539, CVE-2022-23540, CVE-2022-23541", "Insecure key handling and signature verification bypasses"),
    ("npm", "express", [("0", "4.20.0")],
     "MEDIUM", "CVE-2024-29041, CVE-2024-43796", "Open redirect and XSS in res.redirect"),
    ("npm", "body-parser", [("0", "1.20.3")],
     "MEDIUM", "CVE-2024-45590", "Denial of service with URL-encoded bodies"),
    ("npm", "cookie", [("0", "0.7.0")],
     "LOW", "CVE-2024-47764", "Cookie name/path/domain injection"),
    ("npm", "node-fetch", [("0", "2.6.7"), ("3.0.0", "3.1.1")],
     "MEDIUM", "CVE-2022-0235", "Leaks cookies/authorization headers to third-party sites on redirect"),
    ("npm", "follow-redirects", [("0", "1.15.6")],
     "MEDIUM", "CVE-2024-28849, CVE-2023-26159", "Proxy-Authorization header leak and URL parsing issues"),
    ("npm", "ws", [("2.1.0", "5.2.4"), ("6.0.0", "6.2.3"), ("7.0.0", "7.5.10"), ("8.0.0", "8.17.1")],
     "MEDIUM", "CVE-2024-37890", "Denial of service via many HTTP headers"),
    ("npm", "semver", [("0", "5.7.2"), ("6.0.0", "6.3.1"), ("7.0.0", "7.5.2")],
     "MEDIUM", "CVE-2022-25883", "Regular expression denial of service"),
    ("npm", "xml2js", [("0", "0.5.0")],
     "MEDIUM", "CVE-2023-0842", "Prototype pollution"),
    ("npm", "moment", [("0", "2.29.4")],
     "MEDIUM", "CVE-2022-24785, CVE-2022-31129", "Path traversal and regular expression denial of service"),
    ("npm", "handlebars", [("0", "4.7.7")],
     "HIGH", "CVE-2021-23369, CVE-2021-23383", "Remote code execution when compiling untrusted templates"),
    ("npm", "ejs", [("0", "3.1.10")],
     "HIGH", "CVE-2022-29078, CVE-2024-33883", "Server-side template injection / remote code execution"),
    ("npm", "jquery", [("0", "3.5.0")],
     "MEDIUM", "CVE-2020-11022, CVE-2020-11023", "XSS when passing HTML from untrusted sources"),
    ("npm", "vm2", [("0", NO_FIX)],
     "CRITICAL", "CVE-2023-37466, CVE-2023-37903", "Sandbox escape; the project is discontinued with no fix"),
    ("npm", "crypto-js", [("0", "4.2.0")],
     "HIGH", "CVE-2023-46233", "PBKDF2 defaults are 1,000x weaker than specified"),
    ("npm", "sequelize", [("0", "6.19.1")],
     "HIGH", "CVE-2023-25813", "SQL injection via replacements"),
    ("npm", "mongoose", [("0", "6.13.6"), ("7.0.0", "7.8.4"), ("8.0.0", "8.9.5")],
     "HIGH", "CVE-2024-53900, CVE-2025-23061", "Search injection via $where in populate() match"),
    ("npm", "serialize-javascript", [("0", "6.0.2")],
     "MEDIUM", "CVE-2024-11831", "Cross-site scripting"),
    ("npm", "dompurify", [("0", "2.5.4"), ("3.0.0", "3.2.4")],
     "MEDIUM", "CVE-2024-45801, CVE-2025-26791", "Sanitiser bypasses leading to XSS"),

    # PyPI
    ("PyPI", "django", [("0", "4.2.26"), ("5.0.0", "5.1.14"), ("5.2.0", "5.2.8")],
     "HIGH", "CVE-2025-64459, CVE-2024-42005, CVE-2022-34265", "SQL injection in QuerySet filtering / JSONField / Trunc"),
    ("PyPI", "flask", [("0", "2.2.5"), ("2.3.0", "2.3.2")],
     "MEDIUM", "CVE-2023-30861", "Session cookie can be cached and leaked by proxies"),
    ("PyPI", "werkzeug", [("0", "3.0.6")],
     "HIGH", "CVE-2024-34069, CVE-2024-49766, CVE-2024-49767", "Debugger remote code execution and resource exhaustion"),
    ("PyPI", "requests", [("0", "2.32.4")],
     "MEDIUM", "CVE-2024-35195, CVE-2024-47081", "verify=False persists across a Session; .netrc credential leak"),
    ("PyPI", "urllib3", [("0", "1.26.19"), ("2.0.0", "2.2.2")],
     "MEDIUM", "CVE-2024-37891", "Proxy-Authorization header kept on cross-origin redirects"),
    ("PyPI", "pyyaml", [("0", "5.4")],
     "HIGH", "CVE-2020-14343", "Arbitrary code execution via full_load / FullLoader"),
    ("PyPI", "jinja2", [("0", "3.1.6")],
     "MEDIUM", "CVE-2024-56201, CVE-2024-56326, CVE-2025-27516", "Sandbox breakouts"),
    ("PyPI", "pillow", [("0", "10.3.0")],
     "HIGH", "CVE-2023-50447, CVE-2024-28219", "Arbitrary code execution in ImageMath.eval and buffer overflow"),
    ("PyPI", "cryptography", [("0", "42.0.4")],
     "MEDIUM", "CVE-2023-50782, CVE-2024-26130", "RSA decryption timing oracle and crash on malformed input"),
    ("PyPI", "fastapi", [("0", "0.109.1")],
     "MEDIUM", "CVE-2024-24762", "Regular expression denial of service in form parsing"),
    ("PyPI", "python-multipart", [("0", "0.0.18")],
     "MEDIUM", "CVE-2024-24762, CVE-2024-53981", "Denial of service while parsing multipart forms"),
    ("PyPI", "starlette", [("0", "0.40.0")],
     "MEDIUM", "CVE-2024-47874", "Denial of service via multipart forms without size limits"),
    ("PyPI", "aiohttp", [("0", "3.10.11")],
     "HIGH", "CVE-2024-23334, CVE-2024-52304", "Static file path traversal and request smuggling"),
    ("PyPI", "pyjwt", [("0", "2.4.0")],
     "HIGH", "CVE-2022-29217", "Algorithm confusion allows forged tokens"),
    ("PyPI", "paramiko", [("0", "3.4.0")],
     "MEDIUM", "CVE-2023-48795", "Terrapin SSH prefix truncation attack"),
    ("PyPI", "gunicorn", [("0", "23.0.0")],
     "HIGH", "CVE-2024-1135, CVE-2024-6827", "HTTP request smuggling"),
]

JS_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")

UNPINNED_SPEC = re.compile(r"^(?:\*|x|latest|next|)$|^>=?\s*[\d.]+$", re.IGNORECASE)
REMOTE_SPEC = re.compile(r"^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:)", re.IGNORECASE)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def parse_version(text):
    """'^4.17.0' -> (4, 17, 0). Returns None when there is no version."""

    if not text:
        return None

    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(text))

    if not match:
        return None

    return tuple(int(group or 0) for group in match.groups())


def normalize_name(ecosystem, name):
    name = name.strip()

    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()

    return name.lower()


def is_exact_npm(spec):
    return bool(re.fullmatch(r"=?v?\d+\.\d+\.\d+(?:[-+][\w.]+)?", spec.strip()))


def affected(version, ranges):
    for introduced, fixed in ranges:
        if parse_version(introduced) <= version < parse_version(fixed):
            return fixed
    return None


class Dependency:

    def __init__(self, ecosystem, name, spec, manifest, line):
        self.ecosystem = ecosystem
        self.name = name
        self.spec = spec or ""
        self.manifest = manifest
        self.line = line
        self.locked_version = None

    @property
    def exact(self):
        if self.locked_version:
            return True
        if self.ecosystem == "npm":
            return is_exact_npm(self.spec)
        return self.spec.strip().startswith(("==", "==="))

    @property
    def version(self):
        """Best known version: lockfile, else the lowest version the spec allows."""

        if self.locked_version:
            return parse_version(self.locked_version)

        spec = self.spec

        if self.ecosystem == "PyPI":
            lower = re.search(r"(?:===?|~=|>=|>)\s*([\d][\w.]*)", spec)
            return parse_version(lower.group(1)) if lower else None

        if spec.strip().startswith("<"):
            return None

        return parse_version(spec)

    @property
    def version_text(self):
        if self.locked_version:
            return self.locked_version
        version = self.version
        return ".".join(map(str, version)) if version else self.spec


class DependencyBreaker(BaseBreaker):

    name = "DependencyBreaker"
    description = (
        "Known-vulnerable npm/PyPI packages, unpinned dependencies and "
        "missing lockfiles (--osv for live OSV.dev data)"
    )
    prompt_file = "Dependency.txt"
    trigger_files = (
        "package.json", "requirements*.txt", "pyproject.toml", "pipfile",
    )

    def scan(self):

        dependencies = []
        findings = []

        for relative in self.files:

            name = PurePosixPath(relative).name.lower()
            path = self.project_path / relative

            if name == "package.json":
                found, extra = self.parse_package_json(path, relative)
            elif re.fullmatch(r"requirements.*\.txt", name):
                found, extra = self.parse_requirements(path, relative)
            elif name == "pyproject.toml":
                found, extra = self.parse_pyproject(path, relative)
            elif name == "pipfile":
                found, extra = self.parse_pipfile(path, relative)
            else:
                continue

            dependencies.extend(found)
            findings.extend(extra)

        if self.options.get("osv"):
            osv_findings = self.check_osv(dependencies)

            if osv_findings is not None:
                return findings + osv_findings

        return findings + self.check_advisories(dependencies)

    # -------------------------
    # Manifest parsing
    # -------------------------

    @staticmethod
    def find_line(content, pattern):
        match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
        return content.count("\n", 0, match.start()) + 1 if match else 1

    def parse_package_json(self, path, relative):

        content = read_text_file(path)
        findings = []

        try:
            data = json.loads(content or "")
        except json.JSONDecodeError:
            return [], []

        locked = self.load_js_lockfile(path.parent)
        dependencies = []

        for section in ("dependencies", "devDependencies", "optionalDependencies"):

            for name, spec in (data.get(section) or {}).items():

                if not isinstance(spec, str):
                    continue

                line = self.find_line(content, r'"' + re.escape(name) + r'"\s*:')
                dependency = Dependency("npm", name, spec, relative, line)
                dependency.locked_version = locked.get(name)
                dependencies.append(dependency)

                if section == "devDependencies":
                    continue

                if REMOTE_SPEC.match(spec.strip()):
                    findings.append(self.unpinned_finding(
                        relative, line, f'"{name}": "{spec}"',
                        f"{name} is installed from a URL/git reference instead of the registry",
                        "Git and URL dependencies can change underneath you and bypass "
                        "registry security checks.",
                    ))
                elif UNPINNED_SPEC.match(spec.strip()):
                    findings.append(self.unpinned_finding(
                        relative, line, f'"{name}": "{spec}"',
                        f"{name} accepts any future version",
                        "A compromised or breaking release would be installed "
                        "automatically on the next install.",
                    ))

        if dependencies and not self.has_js_lockfile(path.parent):
            findings.append(
                self.make_finding(
                    title="No lockfile for JavaScript dependencies",
                    severity="MEDIUM",
                    confidence=0.7,
                    file=relative,
                    line=1,
                    evidence="No package-lock.json, yarn.lock, pnpm-lock.yaml or bun.lock found",
                    explanation=(
                        "Without a lockfile every install can resolve different "
                        "(possibly malicious or vulnerable) versions of your "
                        "dependencies and their sub-dependencies."
                    ),
                    recommendation=(
                        "Commit the lockfile your package manager generates and "
                        "use npm ci / yarn --frozen-lockfile / pnpm install "
                        "--frozen-lockfile in CI and deployments."
                    ),
                    cwe="CWE-1357",
                )
            )

        return dependencies, findings

    def parse_requirements(self, path, relative):

        content = read_text_file(path) or ""
        dependencies = []
        unpinned = []
        first_unpinned_line = 1

        for line_number, raw in enumerate(content.splitlines(), start=1):

            line = raw.split("#", 1)[0].strip()

            if not line or line.startswith(("-", "git+", "http")):
                continue

            match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)", line)

            if not match:
                continue

            name, spec = match.group(1), match.group(2).split(";", 1)[0].strip()
            dependencies.append(Dependency("PyPI", name, spec, relative, line_number))

            if not spec.startswith(("==", "===")) and "@" not in spec:
                if not unpinned:
                    first_unpinned_line = line_number
                unpinned.append(name + (spec and f" {spec}"))

        findings = []

        if unpinned:
            findings.append(
                self.make_finding(
                    title="Unpinned Python dependencies",
                    severity="LOW",
                    confidence=0.6,
                    file=relative,
                    line=first_unpinned_line,
                    evidence=", ".join(unpinned[:8]) + (" ..." if len(unpinned) > 8 else ""),
                    explanation=(
                        f"{len(unpinned)} requirement(s) are not pinned with ==, "
                        "so deployments can silently pick up new (possibly "
                        "vulnerable or malicious) releases."
                    ),
                    recommendation=(
                        "Pin exact versions for applications (pip freeze, "
                        "pip-tools, uv pip compile, or Poetry/uv lockfiles), "
                        "ideally with --require-hashes."
                    ),
                    cwe="CWE-1357",
                )
            )

        return dependencies, findings

    def parse_pyproject(self, path, relative):

        content = read_text_file(path) or ""

        try:
            data = tomllib.loads(content)
        except tomllib.TOMLDecodeError:
            return [], []

        specs = []

        for requirement in data.get("project", {}).get("dependencies", []) or []:

            match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)", requirement)

            if match:
                specs.append((match.group(1), match.group(2).split(";", 1)[0].strip()))

        poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}

        for name, value in poetry.items():

            if name.lower() == "python":
                continue

            spec = value.get("version", "") if isinstance(value, dict) else str(value)

            # Poetry ^1.2 / ~1.2 mean ">= 1.2"
            specs.append((name, re.sub(r"^[\^~]", ">=", spec)))

        locked = self.load_python_lockfile(path.parent)
        dependencies = []

        for name, spec in specs:

            line = self.find_line(content, r"[\"']?" + re.escape(name) + r"\b")
            dependency = Dependency("PyPI", name, spec, relative, line)
            dependency.locked_version = locked.get(normalize_name("PyPI", name))
            dependencies.append(dependency)

        return dependencies, []

    def parse_pipfile(self, path, relative):

        content = read_text_file(path) or ""

        try:
            data = tomllib.loads(content)
        except tomllib.TOMLDecodeError:
            return [], []

        dependencies = []

        for name, value in (data.get("packages") or {}).items():

            spec = value.get("version", "") if isinstance(value, dict) else str(value)
            spec = "" if spec == "*" else spec
            line = self.find_line(content, r"^\s*[\"']?" + re.escape(name) + r"[\"']?\s*=")
            dependencies.append(Dependency("PyPI", name, spec, relative, line))

        return dependencies, []

    # -------------------------
    # Lockfiles
    # -------------------------

    def ancestors(self, directory: Path):
        """directory and its parents, stopping at the project root."""

        current = directory.resolve()

        while True:
            yield current

            if current == self.project_path or self.project_path not in current.parents:
                return

            current = current.parent

    def has_js_lockfile(self, directory: Path):
        return any(
            (folder / lockfile).exists()
            for folder in self.ancestors(directory)
            for lockfile in JS_LOCKFILES
        )

    def load_js_lockfile(self, directory: Path):
        """name -> installed version, from the nearest JS lockfile."""

        for folder in self.ancestors(directory):

            lock = folder / "package-lock.json"

            if not lock.exists():
                lock = folder / "npm-shrinkwrap.json"

            if lock.exists():
                try:
                    data = json.loads(lock.read_text(encoding="utf-8", errors="ignore"))
                except (OSError, json.JSONDecodeError):
                    return {}

                versions = {}

                for key, info in (data.get("packages") or {}).items():
                    if key.startswith("node_modules/") and "/node_modules/" not in key[13:]:
                        versions[key[13:]] = info.get("version")

                for name, info in (data.get("dependencies") or {}).items():
                    versions.setdefault(name, info.get("version"))

                return versions

            yarn = folder / "yarn.lock"

            if yarn.exists():
                content = read_text_file(yarn) or ""
                versions = {}

                for match in re.finditer(
                    r'^"?(@?[^@\s"]+)@[^\n]*:\s*\n\s+version:?\s+"?([^"\s]+)',
                    content,
                    re.MULTILINE,
                ):
                    versions.setdefault(match.group(1), match.group(2))

                return versions

            pnpm = folder / "pnpm-lock.yaml"

            if pnpm.exists():
                content = read_text_file(pnpm) or ""
                versions = {}

                for match in re.finditer(
                    r"^\s{2}'?/?(@?[^@\s/']+(?:/[^@\s']+)?)@(\d[^:(\s']*)",
                    content,
                    re.MULTILINE,
                ):
                    versions.setdefault(match.group(1), match.group(2))

                return versions

        return {}

    def load_python_lockfile(self, directory: Path):
        """normalized name -> version from poetry.lock or uv.lock."""

        for lock_name in ("poetry.lock", "uv.lock"):

            lock = directory / lock_name

            if not lock.exists():
                continue

            try:
                data = tomllib.loads(lock.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, tomllib.TOMLDecodeError):
                continue

            return {
                normalize_name("PyPI", package["name"]): package.get("version")
                for package in data.get("package", [])
                if "name" in package
            }

        return {}

    # -------------------------
    # Vulnerability checks
    # -------------------------

    def check_advisories(self, dependencies):

        index = {}

        for advisory in ADVISORIES:
            index.setdefault((advisory[0], advisory[1]), []).append(advisory)

        findings = []

        for dependency in dependencies:

            version = dependency.version

            if version is None:
                continue

            key = (dependency.ecosystem, normalize_name(dependency.ecosystem, dependency.name))

            for _, package, ranges, severity, ids, summary in index.get(key, []):

                fixed = affected(version, ranges)

                if not fixed:
                    continue

                fix_text = (
                    "No fixed version exists; replace this package."
                    if fixed == NO_FIX
                    else f"Upgrade to {fixed} or later (or the latest release)."
                )

                if dependency.exact:
                    title = f"Vulnerable dependency: {package} {dependency.version_text}"
                    confidence = 0.9
                else:
                    title = f"Dependency range allows vulnerable {package} versions"
                    confidence = 0.55
                    severity = "MEDIUM" if severity in {"CRITICAL", "HIGH"} else "LOW"
                    summary += (
                        f". The range '{dependency.spec}' allows affected "
                        "versions and no lockfile pins the installed one"
                    )

                findings.append(
                    self.make_finding(
                        title=title,
                        severity=severity,
                        confidence=confidence,
                        file=dependency.manifest,
                        line=dependency.line,
                        evidence=f"{dependency.name} {dependency.spec or dependency.version_text} ({ids})",
                        explanation=summary + ".",
                        recommendation=fix_text,
                        cwe="CWE-1395",
                    )
                )

        return findings

    def check_osv(self, dependencies):
        """Query OSV.dev. Returns None on network failure so callers can fall back."""

        queries, targets = [], []

        for dependency in dependencies:

            if dependency.version is None:
                continue

            queries.append({
                "package": {"name": dependency.name, "ecosystem": dependency.ecosystem},
                "version": dependency.version_text,
            })
            targets.append(dependency)

        if not queries:
            return []

        results = []

        try:
            for start in range(0, len(queries), 500):

                request = urllib.request.Request(
                    OSV_BATCH_URL,
                    data=json.dumps({"queries": queries[start:start + 500]}).encode(),
                    headers={"Content-Type": "application/json"},
                )

                with urllib.request.urlopen(request, timeout=20) as response:
                    results.extend(json.load(response).get("results", []))

        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as error:
            print(f"  ! OSV lookup failed ({error}); using built-in advisories instead.")
            return None

        findings = []

        for dependency, result in zip(targets, results):

            ids = [vuln["id"] for vuln in result.get("vulns", []) or []]

            if not ids:
                continue

            findings.append(
                self.make_finding(
                    title=f"Vulnerable dependency: {dependency.name} {dependency.version_text}",
                    severity="HIGH" if len(ids) >= 3 else "MEDIUM",
                    confidence=0.9 if dependency.exact else 0.55,
                    file=dependency.manifest,
                    line=dependency.line,
                    evidence=", ".join(ids[:6]) + (" ..." if len(ids) > 6 else ""),
                    explanation=(
                        f"OSV.dev lists {len(ids)} known vulnerabilit"
                        f"{'y' if len(ids) == 1 else 'ies'} affecting this version. "
                        f"Details: https://osv.dev/vulnerability/{ids[0]}"
                        + ("" if dependency.exact else
                           " (version inferred from the lowest version the range allows)")
                    ),
                    recommendation="Upgrade to a version that fixes these advisories.",
                    cwe="CWE-1395",
                )
            )

        return findings

    def unpinned_finding(self, file, line, evidence, title, explanation):
        return self.make_finding(
            title=f"Unpinned dependency: {title}",
            severity="LOW",
            confidence=0.7,
            file=file,
            line=line,
            evidence=evidence,
            explanation=explanation,
            recommendation="Use a published version range (e.g. ^1.2.3) and commit a lockfile.",
            cwe="CWE-1357",
        )


if __name__ == "__main__":
    DependencyBreaker.cli()
