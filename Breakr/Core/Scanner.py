from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
import json
import re

from Agents.base_breaker import has_ignore_marker, walk_project, read_text_file
from Models.ProjectProfile import ProjectProfile


# npm package -> technology
NPM_TECHNOLOGIES = {
    "react": "React",
    "next": "Next.js",
    "vue": "Vue",
    "nuxt": "Nuxt",
    "svelte": "Svelte",
    "@sveltejs/kit": "SvelteKit",
    "@angular/core": "Angular",
    "@remix-run/node": "Remix",
    "@remix-run/react": "Remix",
    "astro": "Astro",
    "express": "Express",
    "fastify": "Fastify",
    "koa": "Koa",
    "@nestjs/core": "NestJS",
    "@supabase/supabase-js": "Supabase",
    "@supabase/ssr": "Supabase",
    "@supabase/auth-helpers-nextjs": "Supabase",
    "firebase": "Firebase",
    "firebase-admin": "Firebase",
    "mongoose": "MongoDB",
    "mongodb": "MongoDB",
    "pg": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mysql": "MySQL",
    "mysql2": "MySQL",
    "prisma": "Prisma",
    "@prisma/client": "Prisma",
    "sequelize": "Sequelize",
    "drizzle-orm": "Drizzle",
    "next-auth": "NextAuth",
    "@auth/core": "NextAuth",
    "@clerk/nextjs": "Clerk",
    "@clerk/clerk-react": "Clerk",
    "jsonwebtoken": "JWT",
    "graphql": "GraphQL",
}

# Python package / import name -> technology
PYTHON_TECHNOLOGIES = {
    "flask": "Flask",
    "django": "Django",
    "djangorestframework": "Django",
    "fastapi": "FastAPI",
    "starlette": "FastAPI",
    "supabase": "Supabase",
    "firebase-admin": "Firebase",
    "firebase_admin": "Firebase",
    "sqlalchemy": "SQLAlchemy",
    "pymongo": "MongoDB",
    "motor": "MongoDB",
    "psycopg": "PostgreSQL",
    "psycopg2": "PostgreSQL",
    "psycopg2-binary": "PostgreSQL",
    "asyncpg": "PostgreSQL",
    "pymysql": "MySQL",
    "pyjwt": "JWT",
    "jwt": "JWT",
}

PYTHON_IMPORT = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w]*)", re.MULTILINE)

MAX_PYTHON_FILES_FOR_IMPORTS = 400


class ProjectScanner:

    def __init__(self, project_path: str, excluded_paths=(), exclude_globs=(), include_ignored=False):
        self.project_path = Path(project_path).resolve()
        self.excluded_paths = excluded_paths

        # Scan files marked "breakr: ignore-file" anyway (--include-ignored)
        self.include_ignored = include_ignored
        self.ignored_files = []

        # User --exclude patterns, e.g. "tests/*" or "legacy"
        self.exclude_globs = [
            glob.strip().strip("/")
            for glob in exclude_globs
            if glob.strip()
        ]

    def is_excluded(self, file: str) -> bool:
        return any(
            fnmatch(file, glob)
            or fnmatch(file, glob + "/*")
            or file.startswith(glob + "/")
            for glob in self.exclude_globs
        )

    def validate_project(self):
        """Make sure the supplied path is a valid project directory."""

        if not self.project_path.exists():
            raise FileNotFoundError(
                f"Project not found: {self.project_path}"
            )

        if not self.project_path.is_dir():
            raise NotADirectoryError(
                f"Path is not a directory: {self.project_path}"
            )

    def scan_files(self):
        """Find project files while ignoring dependencies and build output."""

        self.validate_project()

        files = [
            file
            for file in walk_project(self.project_path, self.excluded_paths)
            if not self.is_excluded(file)
        ]

        if self.include_ignored:
            self.ignored_files = []
            return files

        # Files that opt out with a "breakr: ignore-file" comment.
        self.ignored_files = [
            file
            for file in files
            if has_ignore_marker(self.project_path / file)
        ]

        ignored = set(self.ignored_files)

        return [file for file in files if file not in ignored]

    def detect_project_type(self, files):
        """Detect languages and frameworks from file names and extensions."""

        project_types = set()

        names = {
            PurePosixPath(file).name.lower()
            for file in files
        }

        suffixes = {
            PurePosixPath(file).suffix.lower()
            for file in files
        }

        def has_config(prefix):
            return any(name.startswith(prefix) for name in names)

        if "package.json" in names:
            project_types.add("Node.js")

        if (
            names & {"requirements.txt", "pyproject.toml", "setup.py", "pipfile"}
            or ".py" in suffixes
        ):
            project_types.add("Python")

        if suffixes & {".ts", ".tsx"} or "tsconfig.json" in names:
            project_types.add("TypeScript")

        if suffixes & {".jsx", ".tsx"}:
            project_types.add("React")

        if has_config("next.config."):
            project_types.add("Next.js")

        if ".vue" in suffixes:
            project_types.add("Vue")

        if has_config("nuxt.config."):
            project_types.add("Nuxt")

        if ".svelte" in suffixes:
            project_types.add("Svelte")

        if has_config("svelte.config."):
            project_types.add("SvelteKit")

        if "angular.json" in names:
            project_types.add("Angular")

        if has_config("astro.config."):
            project_types.add("Astro")

        if "manage.py" in names:
            project_types.add("Django")

        if names & {"firebase.json", "firestore.rules", "database.rules.json", "storage.rules"}:
            project_types.add("Firebase")

        if any(file.lower().startswith("supabase/") for file in files):
            project_types.add("Supabase")

        if "dockerfile" in names or has_config("docker-compose"):
            project_types.add("Docker")

        if ".sql" in suffixes:
            project_types.add("SQL")

        return sorted(project_types)

    def detect_from_package_json(self, files=None):
        """Detect frameworks and services from every package.json."""

        if files is None:
            files = self.scan_files()

        detected = set()

        for file in files:

            if PurePosixPath(file).name.lower() != "package.json":
                continue

            try:
                package_data = json.loads(
                    read_text_file(self.project_path / file) or ""
                )
            except json.JSONDecodeError:
                continue

            dependencies = {}

            for section in ("dependencies", "devDependencies"):
                dependencies.update(package_data.get(section) or {})

            for package, technology in NPM_TECHNOLOGIES.items():
                if package in dependencies:
                    detected.add(technology)

        return sorted(detected)

    def detect_from_python(self, files=None):
        """Detect Python frameworks from requirement files and imports."""

        if files is None:
            files = self.scan_files()

        detected = set()
        python_files = 0

        for file in files:

            name = PurePosixPath(file).name.lower()

            if (
                re.fullmatch(r"requirements.*\.txt", name)
                or name in {"pyproject.toml", "pipfile", "setup.py", "setup.cfg"}
            ):
                content = (read_text_file(self.project_path / file) or "").lower()

                for package, technology in PYTHON_TECHNOLOGIES.items():
                    if re.search(r"(?<![\w-])" + re.escape(package) + r"(?![\w-])", content):
                        detected.add(technology)

            elif name.endswith(".py") and python_files < MAX_PYTHON_FILES_FOR_IMPORTS:

                python_files += 1
                content = read_text_file(self.project_path / file) or ""

                for module in PYTHON_IMPORT.findall(content):
                    technology = PYTHON_TECHNOLOGIES.get(module.lower())
                    if technology:
                        detected.add(technology)

        return sorted(detected)

    def create_profile(self):

        files = self.scan_files()

        project_types = self.detect_project_type(files)

        technologies = sorted(
            set(project_types)
            | set(self.detect_from_package_json(files))
            | set(self.detect_from_python(files))
        )

        return ProjectProfile(
            project_path=str(self.project_path),
            files=files,
            project_types=project_types,
            technologies=technologies,
            ignored_files=list(self.ignored_files),
        )


if __name__ == "__main__":

    import sys

    scanner = ProjectScanner(sys.argv[1] if len(sys.argv) > 1 else ".")

    profile = scanner.create_profile()

    print("\nPROJECT PROFILE")
    print("=" * 40)

    print(f"Project: {profile.project_path}")

    print("\nProject Types:")
    for item in profile.project_types:
        print(f"- {item}")

    print("\nTechnologies:")
    for item in profile.technologies:
        print(f"- {item}")

    print("\nFiles:")
    print(f"- {len(profile.files)} files found")
