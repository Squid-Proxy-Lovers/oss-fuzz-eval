"""Index OSS-Fuzz projects and discover candidate oracle harnesses."""

from __future__ import annotations

import re
from pathlib import Path

from oss_fuzz_rl.language_adapters import adapter_for_language, normalize_language
from oss_fuzz_rl.models import ProjectInfo

LANGUAGE_RE = re.compile(r"^\s*language\s*:\s*([^\s#]+)", re.MULTILINE)


def read_project_language(project_dir: Path) -> str:
    project_yaml = project_dir / "project.yaml"
    if not project_yaml.is_file():
        return "c++"
    content = project_yaml.read_text(encoding="utf-8", errors="ignore")
    match = LANGUAGE_RE.search(content)
    if not match:
        return "c++"
    return normalize_language(match.group(1))


def index_projects(oss_fuzz_dir: Path) -> list[ProjectInfo]:
    projects_dir = oss_fuzz_dir / "projects"
    if not projects_dir.is_dir():
        raise FileNotFoundError(f"OSS-Fuzz projects directory not found: {projects_dir}")

    projects: list[ProjectInfo] = []
    for project_dir in sorted(path for path in projects_dir.iterdir() if path.is_dir()):
        language = read_project_language(project_dir)
        adapter = adapter_for_language(language)
        harnesses = tuple(adapter.discover_harnesses(project_dir))
        projects.append(
            ProjectInfo(
                name=project_dir.name,
                language=language,
                rel_path=f"projects/{project_dir.name}",
                harnesses=harnesses,
            )
        )
    return projects


def find_project(oss_fuzz_dir: Path, name: str) -> ProjectInfo:
    for project in index_projects(oss_fuzz_dir):
        if project.name == name:
            return project
    raise KeyError(f"project not found: {name}")
