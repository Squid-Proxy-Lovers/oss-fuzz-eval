"""Reward computation for completed OSS-Fuzz harness tasks."""

from __future__ import annotations

import math
from pathlib import Path

from oss_fuzz_rl.episode import EpisodeTrace
from oss_fuzz_rl.jsonio import read_json
from oss_fuzz_rl.language_adapters import adapter_for_language
from oss_fuzz_rl.models import (
    AstProfile,
    ComponentScore,
    CoverageMetrics,
    OracleMetadata,
    RewardReport,
    TaskBundle,
)
from oss_fuzz_rl.oss_fuzz_runner import run_oss_fuzz_checks
from oss_fuzz_rl.project_index import read_project_language


def score_task(
    task_dir: Path,
    *,
    candidate_project_dir: Path | None = None,
    trace: EpisodeTrace | None = None,
    oss_fuzz_dir: Path | None = None,
    run_oss_fuzz: bool = False,
    require_task_end: bool = False,
) -> RewardReport:
    """Score a completed task workspace."""

    task = TaskBundle.from_json(read_json(task_dir / "task.json"))
    oracle = OracleMetadata.from_json(read_json(task_dir / "oracle" / "oracle.json"))
    candidate_project_dir = candidate_project_dir or (task_dir / "workspace")
    trace = trace or EpisodeTrace.empty()

    notes: list[str] = []
    artifacts: dict[str, str] = {}
    if require_task_end and not trace.has_task_end:
        return _zero(task.task_id, "missing task-end")
    if trace.attempted_oracle_access:
        return _zero(task.task_id, "episode attempted to access hidden oracle artifacts")

    language = read_project_language(candidate_project_dir)
    adapter = adapter_for_language(language)
    discovered_harnesses = tuple(adapter.discover_harnesses(candidate_project_dir))
    candidate_harnesses = changed_or_new_harnesses(discovered_harnesses, task)
    candidate_profile = adapter.profile_sources(
        candidate_project_dir, [h.rel_path for h in candidate_harnesses]
    )

    build_passed = False
    runtime_passed = False
    candidate_coverage = CoverageMetrics()
    if run_oss_fuzz:
        if oss_fuzz_dir is None:
            raise ValueError("--run-oss-fuzz requires --oss-fuzz-dir")
        oss_fuzz_project_dir = candidate_project_dir / "oss-fuzz-project"
        run_project_dir = (
            oss_fuzz_project_dir if oss_fuzz_project_dir.is_dir() else candidate_project_dir
        )
        run_result = run_oss_fuzz_checks(
            oss_fuzz_dir=oss_fuzz_dir,
            project_name=task.project.name,
            candidate_project_dir=run_project_dir,
        )
        build_passed = run_result.build_passed and bool(candidate_harnesses)
        runtime_passed = run_result.runtime_passed and bool(candidate_harnesses)
        candidate_coverage = run_result.coverage_metrics
        if run_result.eval_dir:
            artifacts["eval_dir"] = str(run_result.eval_dir)
    else:
        build_passed = static_build_registration_present(candidate_project_dir, candidate_harnesses)
        runtime_passed = bool(candidate_harnesses)
        notes.append("static scoring only; pass --run-oss-fuzz for build/check/coverage gates")

    components = (
        conformance_component(candidate_project_dir, candidate_harnesses, build_passed),
        runtime_component(runtime_passed, candidate_harnesses),
        ast_reference_component(candidate_profile, oracle.ast_profile),
        focus_component(candidate_profile),
    )
    structural = sum(component.value for component in components)
    fi_score = fuzz_introspector_performance_score(candidate_coverage, oracle.coverage)
    scalar = structural + (0.5 * fi_score)

    if not build_passed:
        scalar = min(scalar, 0.10)
        notes.append("build gate capped reward at 0.10")
    elif not runtime_passed:
        scalar = min(scalar, 0.45)
        notes.append("runtime gate capped reward at 0.45")

    scalar = max(0.0, min(2.0, scalar))
    return RewardReport(
        task_id=task.task_id,
        scalar_reward=round(scalar, 6),
        hard_zero=False,
        build_passed=build_passed,
        runtime_passed=runtime_passed,
        fuzz_introspector_score=round(fi_score, 6),
        components=components,
        notes=tuple(notes),
        artifacts=artifacts,
    )


def changed_or_new_harnesses(discovered_harnesses: tuple, task: TaskBundle) -> tuple:
    """Return harnesses created or changed by the candidate episode."""

    baseline_hashes = {h.rel_path: h.source_sha256 for h in task.project.harnesses}
    changed = []
    for harness in discovered_harnesses:
        if baseline_hashes.get(harness.rel_path) != harness.source_sha256:
            changed.append(harness)
    return tuple(changed)


def _zero(task_id: str, reason: str) -> RewardReport:
    return RewardReport(
        task_id=task_id,
        scalar_reward=0.0,
        hard_zero=True,
        build_passed=False,
        runtime_passed=False,
        fuzz_introspector_score=0.0,
        components=(),
        notes=(reason,),
    )


def static_build_registration_present(project_dir: Path, harnesses: tuple) -> bool:
    if not harnesses:
        return False
    build_text = ""
    for path in _candidate_build_files(project_dir):
        build_text += "\n" + path.read_text(encoding="utf-8", errors="ignore")
    if not build_text:
        return False
    wildcard_markers = (
        "fuzz_*",
        "*Fuzzer.java",
        "fuzz*.go",
        "fuzz_targets",
        "find $SRC",
        "compile_python_fuzzer",
        "compile_javascript_fuzzer",
        "cargo fuzz build",
    )
    if any(marker in build_text for marker in wildcard_markers):
        return True
    return any(
        h.target_name in build_text or Path(h.rel_path).name in build_text for h in harnesses
    )


def conformance_component(
    project_dir: Path, harnesses: tuple, build_registered: bool
) -> ComponentScore:
    max_value = 0.30
    if not harnesses:
        return ComponentScore("conformance", 0.0, max_value, "no discoverable fuzz harness")
    entrypoints = sum(1 for h in harnesses if h.entrypoint)
    entrypoint_score = min(1.0, entrypoints / max(1, len(harnesses)))
    build_score = 1.0 if build_registered else 0.0
    sidecar_score = 1.0 if any(project_dir.rglob("project.yaml")) else 0.5
    value = max_value * (
        (0.45 * entrypoint_score) + (0.45 * build_score) + (0.10 * sidecar_score)
    )
    reason = (
        f"{entrypoints}/{len(harnesses)} harnesses have entrypoints; "
        f"build_registered={build_registered}"
    )
    return ComponentScore("conformance", round(value, 6), max_value, reason)


def runtime_component(runtime_passed: bool, harnesses: tuple) -> ComponentScore:
    max_value = 0.20
    if runtime_passed:
        return ComponentScore(
            "runtime",
            max_value,
            max_value,
            "runtime/check_build passed or static proxy passed",
        )
    if harnesses:
        return ComponentScore("runtime", 0.05, max_value, "harness exists but runtime gate failed")
    return ComponentScore("runtime", 0.0, max_value, "no harness to run")


def ast_reference_component(candidate: AstProfile, oracle: AstProfile) -> ComponentScore:
    max_value = 0.30
    call_sim = multiset_jaccard(candidate.call_names, oracle.call_names)
    input_sim = set_jaccard(candidate.input_apis, oracle.input_apis)
    lifecycle_sim = 0.5 * set_jaccard(candidate.setup_apis, oracle.setup_apis) + 0.5 * set_jaccard(
        candidate.cleanup_apis, oracle.cleanup_apis
    )
    complexity_sim = bounded_similarity(
        candidate.branch_count + candidate.loop_count,
        oracle.branch_count + oracle.loop_count,
    )
    value = max_value * (
        (0.45 * call_sim)
        + (0.20 * input_sim)
        + (0.20 * lifecycle_sim)
        + (0.15 * complexity_sim)
    )
    reason = (
        f"call_sim={call_sim:.3f}, input_sim={input_sim:.3f}, "
        f"lifecycle_sim={lifecycle_sim:.3f}, complexity_sim={complexity_sim:.3f}"
    )
    return ComponentScore("ast_reference", round(value, 6), max_value, reason)


def focus_component(profile: AstProfile) -> ComponentScore:
    max_value = 0.20
    unique_calls = len(set(profile.call_names))
    total_calls = len(profile.call_names)
    if total_calls == 0:
        return ComponentScore("target_focus", 0.0, max_value, "no API calls in candidate harness")
    diversity = unique_calls / total_calls
    size_penalty = (
        1.0 if profile.source_bytes <= 12_000 else max(0.2, 12_000 / profile.source_bytes)
    )
    focus = 1.0 - abs(diversity - 0.35)
    focus = max(0.0, min(1.0, focus)) * size_penalty
    if unique_calls <= 2:
        focus *= 0.6
    reason = (
        f"unique_calls={unique_calls}, total_calls={total_calls}, "
        f"source_bytes={profile.source_bytes}"
    )
    return ComponentScore("target_focus", round(max_value * focus, 6), max_value, reason)


def _candidate_build_files(project_dir: Path) -> list[Path]:
    names = {"build.sh", "Dockerfile"}
    return sorted(path for path in project_dir.rglob("*") if path.is_file() and path.name in names)


def fuzz_introspector_performance_score(
    candidate: CoverageMetrics, oracle: CoverageMetrics, tolerance: float = 0.01
) -> float:
    """Return a raw FI/coverage score in [0, 2]."""

    if candidate.lines_covered <= 0:
        return 0.0
    if oracle.lines_covered <= 0:
        return 2.0 if candidate.lines_covered > 0 else 1.0
    ratio = candidate.lines_covered / oracle.lines_covered
    if math.isclose(ratio, 1.0, rel_tol=tolerance, abs_tol=tolerance):
        return 1.0
    if ratio < 1.0:
        return max(0.0, ratio)
    return min(2.0, 1.0 + (ratio - 1.0))


def multiset_jaccard(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    if not left and not right:
        return 1.0
    left_counts = {item: left.count(item) for item in set(left)}
    right_counts = {item: right.count(item) for item in set(right)}
    keys = set(left_counts) | set(right_counts)
    intersection = sum(min(left_counts.get(key, 0), right_counts.get(key, 0)) for key in keys)
    union = sum(max(left_counts.get(key, 0), right_counts.get(key, 0)) for key in keys)
    return intersection / union if union else 0.0


def set_jaccard(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    left_set = set(left)
    right_set = set(right)
    if not left_set and not right_set:
        return 1.0
    union = left_set | right_set
    if not union:
        return 0.0
    return len(left_set & right_set) / len(union)


def bounded_similarity(value: int, reference: int) -> float:
    if value == reference:
        return 1.0
    if reference <= 0:
        return 0.5 if value <= 2 else 0.0
    return max(0.0, 1.0 - (abs(value - reference) / max(reference, value, 1)))
