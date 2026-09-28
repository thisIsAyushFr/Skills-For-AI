from dataclasses import dataclass, field


@dataclass
class ProjectProfile:
    project_path: str
    files: list[str] = field(default_factory=list)
    project_types: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "project_path": self.project_path,
            "files": self.files,
            "project_types": self.project_types,
            "technologies": self.technologies,
        }