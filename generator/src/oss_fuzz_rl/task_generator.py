"""Generate masked RL task bundles from an OSS-Fuzz checkout."""

from __future__ import annotations

import hashlib
import random
import shutil
from pathlib import Path

from oss_fuzz_rl.jsonio import write_json
from oss_fuzz_rl.language_adapters import adapter_for_language
from oss_fuzz_rl.models import OracleMetadata, ProjectInfo, TaskBundle
from oss_fuzz_rl.project_index import index_projects
from oss_fuzz_rl.redactor import copy_masked_project
from oss_fuzz_rl.source_workspace import materialize_source, select_primary_source_command


def generate_tasks(
    oss_fuzz_dir: Path,
    out_dir: Path,
    *,
    project_name: str | None = None,
    limit: int | None = None,
    seed: int = 0,
    harnesses_per_task: int = 1,
) -> list[Path]:
    """Generate task bundles and return their directories."""

    rng = random.Random(seed)
    projects = [
        project
        for project in index_projects(oss_fuzz_dir)
        if project.harnesses
        and select_primary_source_command(oss_fuzz_dir / project.rel_path / "Dockerfile")
    ]
    if project_name:
        projects = [project for project in projects if project.name == project_name]
        if not projects:
            raise KeyError(
                f"project has no discoverable harnesses or does not exist: {project_name}"
            )

    tasks: list[tuple[ProjectInfo, tuple[int, ...]]] = []
    for project in projects:
        indices = list(range(len(project.harnesses)))
        rng.shuffle(indices)
        for start in range(0, len(indices), harnesses_per_task):
            selected = tuple(indices[start : start + harnesses_per_task])
            if len(selected) == harnesses_per_task:
                tasks.append((project, selected))
    rng.shuffle(tasks)
    if limit is not None:
        tasks = tasks[:limit]

    out_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []
    for project, selected_indices in tasks:
        task_path = _write_task(oss_fuzz_dir, out_dir, project, selected_indices)
        generated.append(task_path)
    return generated


def _write_task(
    oss_fuzz_dir: Path,
    out_dir: Path,
    project: ProjectInfo,
    selected_indices: tuple[int, ...],
) -> Path:
    masked = tuple(project.harnesses[i] for i in selected_indices)
    task_id = _task_id(project.name, masked)
    task_dir = out_dir / task_id
    if task_dir.exists():
        shutil.rmtree(task_dir)
    workspace_dir = task_dir / "workspace"
    workspace_dir.mkdir(parents=True)
    (task_dir / "oracle" / "files").mkdir(parents=True)

    source_project = oss_fuzz_dir / project.rel_path
    source_command = select_primary_source_command(source_project / "Dockerfile")
    if source_command is None:
        raise ValueError(f"project has no parseable source checkout: {project.name}")
    source_scrub_removed: list[str] = []
    source_workspace = materialize_source(source_command, workspace_dir, source_scrub_removed)

    context_project = workspace_dir / "oss-fuzz-project"
    redaction_notes = copy_masked_project(source_project, context_project, project.harnesses)
    oracle_integration = task_dir / "oracle" / "oss-fuzz-project"
    shutil.copytree(source_project, oracle_integration)

    for harness in masked:
        src = source_project / harness.rel_path
        dst = task_dir / "oracle" / "files" / harness.rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    adapter = adapter_for_language(project.language)
    oracle_profile = adapter.profile_sources(source_project, [h.rel_path for h in masked])
    oracle = OracleMetadata(task_id=task_id, harnesses=masked, ast_profile=oracle_profile)
    public_project = ProjectInfo(
        name=project.name,
        language=project.language,
        rel_path=project.rel_path,
        harnesses=(),
    )
    bundle = TaskBundle(task_id=task_id, project=public_project, masked_harnesses=())

    write_json(task_dir / "task.json", bundle.to_json())
    write_json(task_dir / "oracle" / "oracle.json", oracle.to_json())
    write_json(
        task_dir / "redactions.json",
        {
            "task_id": task_id,
            "project": project.name,
            "source": {
                "kind": source_command.kind,
                "url": source_command.url,
                "dest": source_command.dest_name,
                "workspace": source_workspace.relative_to(task_dir).as_posix(),
                "scrub_removed_count": len(source_scrub_removed),
            },
            "public_notes": redaction_notes,
            "masked_count": len(masked),
        },
    )
    (task_dir / "prompt.md").write_text(_prompt_for_project(project), encoding="utf-8")
    return task_dir


def _task_id(project_name: str, masked: tuple) -> str:
    joined = "|".join(f"{h.rel_path}:{h.source_sha256}" for h in masked)
    digest = hashlib.sha256(joined.encode()).hexdigest()[:12]
    visible_name = "-".join(Path(h.rel_path).stem for h in masked)
    visible_name = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in visible_name)[:64]
    return f"{project_name}--{visible_name}--{digest}"


def _prompt_for_project(project: ProjectInfo) -> str:
    return f"""# OSS-Fuzz Harness Task

You are working on the upstream source for OSS-Fuzz project `{project.name}`.

Your goal is to add one meaningful fuzzing harness and the minimal build
registration needed for OSS-Fuzz to build and run it. You are not given a target
function. Inspect the source tree, infer a useful subsystem/API surface, write
the harness, and make it conform to the OSS-Fuzz format for language
`{project.language}`.

The workspace contains:

- The upstream project source cloned from the OSS-Fuzz Dockerfile.
- `oss-fuzz-project/`, a redacted OSS-Fuzz integration context with existing
  fuzz harness files and direct harness registrations removed.

Requirements:

- Keep edits scoped to the provided workspace.
- Add or update only the harness source and minimal build registration needed.
- The resulting fuzz target must build as an OSS-Fuzz target.
- The target must run under the project language's OSS-Fuzz engine/sanitizer
  constraints.
- The harness should convert fuzzer input into structured inputs when the API
  needs them.
- Avoid harness-only crashes, unbounded resource use, network access, and
  nondeterminism.
- Finish only when done by calling `task-end`.

Do not assume this is a text similarity task. Reward is based on OSS-Fuzz
conformance, build/run behavior, static harness structure, subsystem focus, and
coverage/Fuzz Introspector behavior compared with hidden oracle harnesses.
"""
