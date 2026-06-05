"""Create masked task workspaces from OSS-Fuzz project integrations."""

from __future__ import annotations

import fnmatch
import shutil
from pathlib import Path

from oss_fuzz_rl.models import HarnessInfo

BUILD_FILES = ("build.sh", "Dockerfile")


def copy_masked_project(
    source_project: Path,
    destination_project: Path,
    masked_harnesses: tuple[HarnessInfo, ...],
) -> list[str]:
    """Copy a project and redact direct oracle harness leaks.

    Returns public notes describing redactions, without including oracle source.
    """

    if destination_project.exists():
        shutil.rmtree(destination_project)
    shutil.copytree(source_project, destination_project, ignore=_copy_ignore(masked_harnesses))

    notes: list[str] = []
    names = _masked_names(masked_harnesses)
    for build_file in BUILD_FILES:
        path = destination_project / build_file
        if path.is_file():
            removed = redact_registration_file(path, names)
            if removed:
                notes.append(f"redacted {removed} oracle-specific lines from {build_file}")

    for harness in masked_harnesses:
        rel = Path(harness.rel_path)
        for suffix in (".dict", ".options", "_seed_corpus.zip"):
            sidecar = destination_project / rel.with_suffix(
                suffix if suffix.startswith(".") else ""
            ).as_posix()
            if suffix.startswith("_"):
                sidecar = destination_project / f"{rel.with_suffix('').as_posix()}{suffix}"
            if sidecar.exists() and sidecar.is_file():
                sidecar.unlink()
                notes.append(f"removed oracle sidecar {sidecar.relative_to(destination_project)}")
    return notes


def _copy_ignore(masked_harnesses: tuple[HarnessInfo, ...]):
    rel_paths = {Path(h.rel_path).as_posix() for h in masked_harnesses}
    basename_patterns = _sidecar_basenames(masked_harnesses)

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored: set[str] = set()
        dir_path = Path(directory)
        for name in names:
            rel = (dir_path / name).as_posix()
            rel_from_project = _rel_from_project(rel)
            if rel_from_project in rel_paths:
                ignored.add(name)
                continue
            if any(fnmatch.fnmatch(name, pattern) for pattern in basename_patterns):
                ignored.add(name)
        return ignored

    return ignore


def _rel_from_project(path_text: str) -> str:
    marker = "/projects/"
    if marker in path_text:
        parts = path_text.split(marker, 1)[1].split("/", 1)
        if len(parts) == 2:
            return parts[1]
    return Path(path_text).name


def _sidecar_basenames(masked_harnesses: tuple[HarnessInfo, ...]) -> set[str]:
    patterns: set[str] = set()
    for harness in masked_harnesses:
        stem = Path(harness.rel_path).stem
        patterns.add(f"{stem}.dict")
        patterns.add(f"{stem}.options")
        patterns.add(f"{stem}_seed_corpus.zip")
    return patterns


def _masked_names(masked_harnesses: tuple[HarnessInfo, ...]) -> set[str]:
    names: set[str] = set()
    for harness in masked_harnesses:
        path = Path(harness.rel_path)
        names.add(path.name)
        names.add(path.stem)
        names.add(harness.target_name)
    return {name for name in names if name}


def redact_registration_file(path: Path, names: set[str]) -> int:
    """Remove lines that directly name masked oracle harnesses."""

    content = path.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines(keepends=True)
    kept: list[str] = []
    removed = 0
    for line in lines:
        if _line_references_any_name(line, names) and _looks_oracle_specific(line, names):
            kept.append(_redaction_comment(line))
            removed += 1
        else:
            kept.append(line)
    if removed:
        path.write_text("".join(kept), encoding="utf-8")
    return removed


def _line_references_any_name(line: str, names: set[str]) -> bool:
    return any(name in line for name in names)


def _looks_oracle_specific(line: str, names: set[str]) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    return any(name in stripped for name in names)


def _redaction_comment(line: str) -> str:
    newline = "\n" if line.endswith("\n") else ""
    return f"# OSS-Fuzz RL eval redacted one oracle-specific build line.{newline}"
