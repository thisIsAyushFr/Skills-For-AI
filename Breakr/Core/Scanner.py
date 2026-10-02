from pathlib import Path
import json
from Models.ProjectProfile import ProjectProfile

class ProjectScanner:

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()

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
        """Find project files while ignoring unnecessary directories."""

        self.validate_project()

        ignored_directories = {
            ".git",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            "env",
            ".next",
            "dist",
            "build",
        }

        files = []

        for path in self.project_path.rglob("*"):

            if not path.is_file():
                continue

            # Ignore files inside unwanted directories
            if any(
                part in ignored_directories
                for part in path.relative_to(self.project_path).parts
            ):
                continue

            files.append(
                str(path.relative_to(self.project_path))
            )

        return files

    def detect_project_type(self, files):
        """Detect technologies based on project files."""

        project_types = set()

        file_names = {
            Path(file).name.lower()
            for file in files
        }

        # Node.js
        if "package.json" in file_names:
            project_types.add("Node.js")

        # Python
        if (
            "requirements.txt" in file_names
            or "pyproject.toml" in file_names
            or "setup.py" in file_names
            or any(file.endswith(".py") for file in files)
        ):
            project_types.add("Python")

        # React
        if any(
            file.endswith((".jsx", ".tsx"))
            for file in files
        ):
            project_types.add("React")

        # Next.js
        if any(
            name.startswith("next.config.")
            for name in file_names
        ):
            project_types.add("Next.js")

        # Vue
        if any(
            file.endswith(".vue")
            for file in files
        ):
            project_types.add("Vue")

        # Angular
        if "angular.json" in file_names:
            project_types.add("Angular")

        # FastAPI
        if any(
            "fastapi" in file.lower()
            for file in files
        ):
            project_types.add("FastAPI")

        # Flask
        if any(
            "flask" in file.lower()
            for file in files
        ):
            project_types.add("Flask")

        # Django
        if any(
            "django" in file.lower()
            for file in files
        ):
            project_types.add("Django")

        return sorted(project_types)

    def detect_from_package_json(self):
        """Detect frameworks and services from package.json."""

        package_file = self.project_path / "package.json"

        if not package_file.exists():
            return []

        try:
            with open(
                package_file,
                "r",
                encoding="utf-8"
            ) as file:
                package_data = json.load(file)

        except (json.JSONDecodeError, OSError):
            return []

        dependencies = {}

        dependencies.update(
            package_data.get("dependencies", {})
        )

        dependencies.update(
            package_data.get("devDependencies", {})
        )

        detected = set()

        # Frontend frameworks
        if "react" in dependencies:
            detected.add("React")

        if "next" in dependencies:
            detected.add("Next.js")

        if "vue" in dependencies:
            detected.add("Vue")

        if (
            "angular" in dependencies
            or "@angular/core" in dependencies
        ):
            detected.add("Angular")

        # Backend
        if "express" in dependencies:
            detected.add("Express")

        # Backend / cloud services
        if "@supabase/supabase-js" in dependencies:
            detected.add("Supabase")

        if "firebase" in dependencies:
            detected.add("Firebase")

        # MongoDB
        if (
            "mongoose" in dependencies
            or "mongodb" in dependencies
        ):
            detected.add("MongoDB")

        # PostgreSQL
        if (
            "pg" in dependencies
            or "postgres" in dependencies
        ):
            detected.add("PostgreSQL")

        # MySQL
        if (
            "mysql" in dependencies
            or "mysql2" in dependencies
        ):
            detected.add("MySQL")

        return sorted(detected)
    
    def create_profile(self):
        files = self.scan_files()

        project_types = self.detect_project_type(files)

        package_types = self.detect_from_package_json()

        technologies = sorted(
            set(project_types + package_types)
        )

        return ProjectProfile(
            project_path=str(self.project_path),
            files=files,
            project_types=project_types,
            technologies=technologies,
        )

if __name__ == "__main__":

    scanner = ProjectScanner(".")

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