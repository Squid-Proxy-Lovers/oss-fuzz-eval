"""Optional OSS-Fuzz build/check/coverage execution hooks."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from oss_fuzz_rl.models import CoverageMetrics
from oss_fuzz_rl.source_workspace import (
    local_source_context_name,
    rewrite_source_checkout_to_local_copy,
    select_primary_source_command,
)

LOCAL_SOURCE_CONTEXT_DIR = ".oss-fuzz-rl-source"


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass(frozen=True)
class OSSFuzzRunResult:
    build_image: CommandResult | None
    build_fuzzers: CommandResult | None
    check_build: CommandResult | None
    coverage: CommandResult | None
    coverage_metrics: CoverageMetrics
    eval_dir: Path | None

    @property
    def build_passed(self) -> bool:
        return bool(self.build_fuzzers and self.build_fuzzers.ok)

    @property
    def runtime_passed(self) -> bool:
        return bool(self.check_build and self.check_build.ok)


def run_oss_fuzz_checks(
    *,
    oss_fuzz_dir: Path,
    project_name: str,
    candidate_project_dir: Path,
    source_workspace_dir: Path | None = None,
    keep_eval_dir: bool = False,
    coverage_seconds: int = 30,
) -> OSSFuzzRunResult:
    """Run OSS-Fuzz build/check/coverage in a temporary materialized checkout."""

    if (candidate_project_dir / "oss-fuzz-project").is_dir():
        source_workspace_dir = source_workspace_dir or candidate_project_dir
        candidate_project_dir = candidate_project_dir / "oss-fuzz-project"

    temp = tempfile.TemporaryDirectory(prefix="oss-fuzz-rl-")
    eval_root = Path(temp.name) / "oss-fuzz"
    _materialize_minimal_checkout(
        oss_fuzz_dir,
        eval_root,
        project_name,
        candidate_project_dir,
        source_workspace_dir=source_workspace_dir,
    )

    build_image = _run(
        ("python3", "infra/helper.py", "build_image", "--no-pull", project_name),
        eval_root,
    )
    build_fuzzers = None
    check_build = None
    coverage = None
    coverage_metrics = CoverageMetrics()
    if build_image.ok:
        build_fuzzers = _run(
            ("python3", "infra/helper.py", "build_fuzzers", "--sanitizer=address", project_name),
            eval_root,
        )
    if build_fuzzers and build_fuzzers.ok:
        check_build = _run(("python3", "infra/helper.py", "check_build", project_name), eval_root)
    if check_build and check_build.ok:
        coverage = _run(
            (
                "python3",
                "infra/helper.py",
                "introspector",
                "--coverage-only",
                f"--seconds={coverage_seconds}",
                "--out",
                str(eval_root / "rl-coverage"),
                project_name,
            ),
            eval_root,
            timeout=60 * 60,
        )
        summary_path = eval_root / "rl-coverage" / "report" / "linux" / "summary.json"
        coverage_metrics = read_coverage_metrics(summary_path)

    if keep_eval_dir:
        temp.cleanup = lambda: None  # type: ignore[method-assign]
        eval_dir: Path | None = eval_root
    else:
        eval_dir = None
        temp.cleanup()
    return OSSFuzzRunResult(
        build_image=build_image,
        build_fuzzers=build_fuzzers,
        check_build=check_build,
        coverage=coverage,
        coverage_metrics=coverage_metrics,
        eval_dir=eval_dir,
    )


def read_coverage_metrics(summary_path: Path) -> CoverageMetrics:
    if not summary_path.is_file():
        return CoverageMetrics()
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return CoverageMetrics()

    totals = data.get("data", [{}])[0].get("totals", {}) if isinstance(data, dict) else {}
    lines = totals.get("lines", {})
    functions = totals.get("functions", {})
    regions = totals.get("regions", {})
    return CoverageMetrics(
        lines_covered=int(lines.get("covered", 0)),
        lines_total=int(lines.get("count", 0)),
        functions_covered=int(functions.get("covered", 0)),
        functions_total=int(functions.get("count", 0)),
        regions_covered=int(regions.get("covered", 0)),
        regions_total=int(regions.get("count", 0)),
        raw=data,
    )


def _materialize_minimal_checkout(
    oss_fuzz_dir: Path,
    eval_root: Path,
    project_name: str,
    candidate_project_dir: Path,
    *,
    source_workspace_dir: Path | None = None,
) -> None:
    eval_root.mkdir(parents=True)
    for name in ("infra",):
        shutil.copytree(oss_fuzz_dir / name, eval_root / name, symlinks=True)
    (eval_root / "projects").mkdir()
    eval_project_dir = eval_root / "projects" / project_name
    shutil.copytree(candidate_project_dir, eval_project_dir, symlinks=True)
    if source_workspace_dir is not None:
        inject_local_source_checkout(eval_project_dir, source_workspace_dir)


def inject_local_source_checkout(project_dir: Path, source_workspace_dir: Path) -> bool:
    """Copy local task source into the Docker context and rewrite its checkout."""

    dockerfile = project_dir / "Dockerfile"
    source_command = select_primary_source_command(dockerfile)
    if source_command is None:
        return False

    local_source = source_workspace_dir / source_command.dest_name
    if not local_source.is_dir():
        return False

    context_root = project_dir / LOCAL_SOURCE_CONTEXT_DIR
    context_source = context_root / local_source_context_name(source_command)
    if context_source.exists():
        shutil.rmtree(context_source)
    context_source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(local_source, context_source, symlinks=True)
    return rewrite_source_checkout_to_local_copy(
        dockerfile,
        source_command,
        local_context_dir=LOCAL_SOURCE_CONTEXT_DIR,
    )


def _run(command: tuple[str, ...], cwd: Path, timeout: int = 30 * 60) -> CommandResult:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return CommandResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
