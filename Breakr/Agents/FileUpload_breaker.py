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


JS = frozenset(JS_EXTENSIONS)
PY = frozenset(PYTHON_EXTENSIONS)

PATH_SANITISED = re.compile(
    r"secure_filename|basename|safe_join|realpath|is_relative_to|"
    r"normalize\(|startsWith\(|startswith\(|sanitize[-_]?filename|"
    r"\.resolve\(\)\.\w*parents|commonpath",
    re.IGNORECASE,
)

TYPE_VALIDATION = re.compile(
    r"content_type|mimetype|mime|allowed_file|ALLOWED_EXTENSIONS|splitext|"
    r"suffix|imghdr|python-magic|\bmagic\.|filetype|endswith\(|fileFilter|"
    r"file-type|fileTypeFromBuffer",
    re.IGNORECASE,
)

SIZE_LIMIT = re.compile(
    r"MAX_CONTENT_LENGTH|max_?(?:file_?)?size|maxFileSize|limits|content_length|"
    r"\.size\b|len\(\s*(?:await\s+)?\w+\.read|DATA_UPLOAD_MAX_MEMORY_SIZE|FILE_UPLOAD_MAX_MEMORY_SIZE",
    re.IGNORECASE,
)

PATH_TRAVERSAL = dict(
    severity="HIGH",
    explanation=(
        "A file path is built from request data. Sending ../../ sequences "
        "(or an absolute path) lets an attacker read or overwrite files "
        "outside the intended folder, such as .env or source code."
    ),
    recommendation=(
        "Never use user input as a path. Map IDs to stored filenames, or "
        "take the basename, join it to a fixed directory, resolve it and "
        "verify the result is still inside that directory (safe_join / "
        "send_from_directory in Flask)."
    ),
    cwe="CWE-22",
)

USER_FILENAME = dict(
    severity="HIGH",
    explanation=(
        "The uploaded file is saved using the filename the client sent. "
        "Attackers can choose names like ../../app.py or shell.php to "
        "overwrite files or plant executable content."
    ),
    recommendation=(
        "Generate your own filename (UUID + validated extension), or at "
        "least use secure_filename / path.basename, and store uploads "
        "outside the web root."
    ),
    cwe="CWE-73",
)

RULES = [

    # -------------------------
    # Path traversal
    # -------------------------

    Rule(
        title="Path traversal: request data used in a file operation",
        pattern=(
            r"\b(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|"
            r"writeFileSync|appendFile|unlink|unlinkSync|rmSync|readdir|sendFile|download)"
            r"\([^)\n]*req\.(?:params|query|body)"
        ),
        confidence=0.7,
        extensions=JS,
        **PATH_TRAVERSAL,
    ),
    Rule(
        title="Path traversal: request data used in path.join/resolve",
        pattern=r"path\.(?:join|resolve)\([^)\n]*req\.(?:params|query|body)",
        confidence=0.55,
        extensions=JS,
        exclude=r"readFile|createReadStream|writeFile|unlink|sendFile|download",
        **{**PATH_TRAVERSAL, "severity": "MEDIUM"},
    ),
    Rule(
        title="Path traversal: request data used in open()",
        pattern=(
            r"\bopen\(\s*(?:f[\"'][^\"'\n]*\{[^}]*request\.|[^)\n]*request\."
            r"(?:args|form|values|json|GET|POST|query_params|path_params))"
        ),
        confidence=0.7,
        extensions=PY,
        **PATH_TRAVERSAL,
    ),
    Rule(
        title="Path traversal: request data used in a file path",
        pattern=(
            r"(?:os\.path\.join|send_file|Path)\([^)\n]*request\."
            r"(?:args|form|values|json|GET|POST|query_params|path_params)"
        ),
        confidence=0.6,
        extensions=PY,
        exclude=r"\bopen\(",
        **{**PATH_TRAVERSAL, "severity": "MEDIUM"},
    ),
    Rule(
        title="Path traversal: file served from a formatted path",
        pattern=r"(?:FileResponse|send_file)\(\s*(?:f[\"'][^\"'\n]*\{|os\.path\.join\([^)\n]*,\s*\w+\s*\))",
        confidence=0.45,
        extensions=PY,
        **{**PATH_TRAVERSAL, "severity": "MEDIUM"},
    ),

    # -------------------------
    # User-controlled filenames
    # -------------------------

    Rule(
        title="Uploaded file saved with the client's filename",
        pattern=r"cb\(\s*null\s*,\s*(?:[^)\n]*\+\s*)?file\.originalname\s*\)",
        confidence=0.65,
        extensions=JS,
        exclude=r"basename|sanitize|uuid|randomUUID",
        **USER_FILENAME,
    ),
    Rule(
        title="Uploaded file saved with the client's filename",
        pattern=r"\.mv\([^)\n]*\.name\b",
        confidence=0.7,
        extensions=JS,
        exclude=r"basename|sanitize|uuid|randomUUID",
        **USER_FILENAME,
    ),
    Rule(
        title="Uploaded file saved with the client's filename",
        pattern=(
            r"\.save\(\s*(?:os\.path\.join\([^)\n]*|f[\"'][^\"'\n]*\{[^}\n]*|[^)\n]*\+\s*)?\w+\.filename"
            r"|(?:aiofiles\.)?open\(\s*(?:os\.path\.join\([^)\n]*|f[\"'][^\"'\n]*\{[^}\n]*)\w+\.filename"
        ),
        confidence=0.7,
        extensions=PY,
        exclude=r"secure_filename|basename|uuid",
        **USER_FILENAME,
    ),

    # -------------------------
    # Serving and extracting
    # -------------------------

    Rule(
        title="Uploaded files served from a static directory",
        pattern=r"express\.static\([^)\n]*upload|app\.mount\([^)\n]*upload[^)\n]*StaticFiles",
        severity="LOW",
        confidence=0.5,
        explanation=(
            "Uploads are served directly as static files. An uploaded .html "
            "or .svg file will run scripts on your domain (stored XSS)."
        ),
        recommendation=(
            "Serve uploads from a separate domain/bucket, or with "
            "Content-Disposition: attachment and a forced safe Content-Type."
        ),
        cwe="CWE-434",
        extensions=frozenset(JS | PY),
    ),
    Rule(
        title="SVG uploads allowed",
        pattern=r"[\"']image/svg\+xml[\"']|[\"']\.?svg[\"']\s*[,\]}]",
        severity="LOW",
        confidence=0.4,
        explanation="SVG files can contain JavaScript; serving user-uploaded SVGs on your domain enables stored XSS.",
        recommendation="Reject SVG uploads or sanitise them (e.g. DOMPurify with the SVG profile) and serve them as attachments.",
        cwe="CWE-434",
        extensions=frozenset(JS | PY),
    ),
    Rule(
        title="Archive extracted without path validation (Zip Slip)",
        pattern=r"\.extractall\(|\.extractAllTo\(|unzipper\.Extract\(",
        severity="MEDIUM",
        confidence=0.5,
        explanation=(
            "Archive entries can contain ../ paths. Extracting an uploaded "
            "archive without checking each entry can overwrite files "
            "anywhere the process can write."
        ),
        recommendation=(
            "Validate every member's resolved path stays inside the target "
            "directory, or use tarfile's filter='data' (Python 3.12+)."
        ),
        cwe="CWE-22",
        extensions=frozenset(JS | PY),
        exclude=r"filter\s*=",
    ),
]

UPLOAD_CONTEXT = re.compile(
    r"upload|multer|request\.files|request\.FILES|UploadFile|formidable|busboy|fileFilter|accept=",
    re.IGNORECASE,
)

MULTER_CALL = re.compile(r"\bmulter\(")
EXPRESS_FILEUPLOAD_CALL = re.compile(r"\bfileUpload\(")
PY_UPLOAD = re.compile(r"request\.files|request\.FILES|\bUploadFile\b|FileStorage")


class FileUploadBreaker(BaseBreaker):

    name = "FileUploadBreaker"
    description = (
        "Path traversal, uploads without size/type limits, client-chosen "
        "filenames, uploads served as static files, Zip Slip"
    )
    prompt_file = "FileUpload.txt"
    trigger_technologies = WEB_TECHNOLOGIES
    extensions = JS_EXTENSIONS | PYTHON_EXTENSIONS

    def refine(self, finding, rule, match, code):

        # ".svg" alone is everywhere; only care in files that handle uploads.
        if rule.title == "SVG uploads allowed" and not UPLOAD_CONTEXT.search(code):
            return None

        if rule.cwe in {"CWE-22", "CWE-73"} and PATH_SANITISED.search(code):
            finding.severity = "LOW"
            finding.confidence = round(finding.confidence * 0.5, 2)
            finding.explanation += (
                " The file uses a path/filename sanitiser; confirm it is "
                "applied to this exact value."
            )

        return finding

    def scan_file(self, file_path: Path, content: str):

        code = strip_comments(content, file_path)
        findings = self.scan_rules(file_path, content, RULES, code)
        index = LineIndex(content)
        relative = self.relative(file_path)

        def upload_finding(position, title, explanation, recommendation, cwe):
            line = index.line_of(position)
            return self.make_finding(
                title=title,
                severity="MEDIUM",
                confidence=0.55,
                file=relative,
                line=line,
                evidence=clip(index.text(line)),
                explanation=explanation,
                recommendation=recommendation,
                cwe=cwe,
            )

        # -------------------------
        # Node: multer / express-fileupload configuration
        # -------------------------

        for pattern in (MULTER_CALL, EXPRESS_FILEUPLOAD_CALL):

            for match in pattern.finditer(code):

                # The options object usually sits in the call or just above it.
                context = code[max(0, match.start() - 600):match.start() + 600]

                if not SIZE_LIMIT.search(context):
                    findings.append(upload_finding(
                        match.start(),
                        "File upload without a size limit",
                        "No file size limit is configured, so attackers can "
                        "fill the disk or memory with huge uploads.",
                        "Set limits: { fileSize: ... } (multer) or limits in "
                        "express-fileupload, plus a request body size limit.",
                        "CWE-400",
                    ))

                if pattern is MULTER_CALL and not TYPE_VALIDATION.search(context):
                    findings.append(upload_finding(
                        match.start(),
                        "File upload without type validation",
                        "Any file type is accepted, including HTML, SVG, or "
                        "executable scripts that may later be served or run.",
                        "Add a fileFilter that allowlists extensions AND checks "
                        "the file's magic bytes (e.g. the file-type package).",
                        "CWE-434",
                    ))

        # -------------------------
        # Python: Flask / FastAPI / Django uploads
        # -------------------------

        if file_path.suffix.lower() == ".py":

            match = PY_UPLOAD.search(code)

            if match:

                if not TYPE_VALIDATION.search(code):
                    findings.append(upload_finding(
                        match.start(),
                        "File upload without type validation",
                        "Uploaded files are accepted without checking their "
                        "extension or content type.",
                        "Allowlist extensions and verify the content (magic "
                        "bytes) before saving; never trust the client's "
                        "Content-Type alone.",
                        "CWE-434",
                    ))

                if not SIZE_LIMIT.search(code) and not self._project_has_size_limit():
                    findings.append(upload_finding(
                        match.start(),
                        "File upload without a size limit",
                        "No upload size limit was found in this file or the "
                        "app config, so huge uploads can exhaust disk or memory.",
                        "Set MAX_CONTENT_LENGTH (Flask), "
                        "DATA_UPLOAD_MAX_MEMORY_SIZE (Django), or check the "
                        "size while reading (FastAPI).",
                        "CWE-400",
                    ))

        return findings

    def _project_has_size_limit(self):

        if not hasattr(self, "_size_limit_cache"):

            self._size_limit_cache = False

            for path in self.iter_files(extensions={".py", ".cfg", ".toml", ".env", ".ini"}):

                content = self.read(path)

                if content and re.search(
                    r"MAX_CONTENT_LENGTH|DATA_UPLOAD_MAX_MEMORY_SIZE|FILE_UPLOAD_MAX_MEMORY_SIZE",
                    content,
                ):
                    self._size_limit_cache = True
                    break

        return self._size_limit_cache


if __name__ == "__main__":
    FileUploadBreaker.cli()
