from dataclasses import dataclass, field


@dataclass
class ProjectProfile:
    project_path: str
    files: list[str] = field(default_factory=list)
    project_types: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)

    def has_file(self, *names: str) -> bool:
        """True if any project file has one of these names (case-insensitive)."""

        wanted = {name.lower() for name in names}

        return any(
            file.rsplit("/", 1)[-1].lower() in wanted
            for file in self.files
        )

    def to_dict(self):
        return {
            "project_path": self.project_path,
            "files": self.files,
            "project_types": self.project_types,
            "technologies": self.technologies,
        }
