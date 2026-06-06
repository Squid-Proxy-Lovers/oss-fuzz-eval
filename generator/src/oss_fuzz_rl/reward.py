"""Reward computation for completed OSS-Fuzz harness tasks."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from oss_fuzz_rl.episode import EpisodeTrace
from oss_fuzz_rl.jsonio import read_json, write_json
from oss_fuzz_rl.language_adapters import adapter_for_language
from oss_fuzz_rl.models import (
    AstProfile,
    CoverageMetrics,
    HarnessInfo,
    JsonDict,
    OracleMetadata,
    RewardConfig,
    RewardGroupScore,
    RewardMicrocomponent,
    RewardReport,
    TaskBundle,
)
from oss_fuzz_rl.oss_fuzz_runner import run_oss_fuzz_checks
from oss_fuzz_rl.project_index import read_project_language

REWARD_SCHEMA_VERSION = "reward.v3"
REWARD_CONFIG_SCHEMA_VERSION = "reward_config.v3"
REWARD_GROUPS = (
    "episode_control",
    "integration_plausibility",
    "harness_quality",
    "reference_intent",
    "coverage_behavior",
    "stability_behavior",
)
MICROCOMPONENT_GROUPS = {
    "task_end": "episode_control",
    "oracle_access_clean": "episode_control",
    "harness_discovered": "integration_plausibility",
    "build_registered": "integration_plausibility",
    "fuzzer_build": "integration_plausibility",
    "runtime_check": "integration_plausibility",
    "entrypoint_validity": "harness_quality",
    "input_dataflow": "harness_quality",
    "input_api_use": "harness_quality",
    "lifecycle_api_use": "harness_quality",
    "target_focus": "harness_quality",
    "call_similarity": "reference_intent",
    "input_similarity": "reference_intent",
    "lifecycle_similarity": "reference_intent",
    "complexity_similarity": "reference_intent",
    "import_similarity": "reference_intent",
    "coverage_available": "coverage_behavior",
    "line_coverage_absolute": "coverage_behavior",
    "function_coverage_absolute": "coverage_behavior",
    "region_coverage_absolute": "coverage_behavior",
    "line_coverage_vs_oracle": "coverage_behavior",
    "function_coverage_vs_oracle": "coverage_behavior",
    "region_coverage_vs_oracle": "coverage_behavior",
    "no_crashes": "stability_behavior",
    "no_timeouts": "stability_behavior",
}
DEFAULT_CAPS = {
    "build_failed": 0.05,
    "runtime_failed": 0.25,
    "coverage_unavailable": 0.35,
    "no_input_derived_project_call": 0.35,
}
RELATIVE_COVERAGE_MICROCOMPONENT_WEIGHTS = {
    "coverage_available": 0.0,
    "line_coverage_absolute": 0.0,
    "function_coverage_absolute": 0.0,
    "region_coverage_absolute": 0.0,
    "line_coverage_vs_oracle": 1.0,
    "function_coverage_vs_oracle": 1.0,
    "region_coverage_vs_oracle": 1.0,
}
NON_REWARD_MICROCOMPONENT_WEIGHTS = {
    "task_end": 0.0,
    "oracle_access_clean": 0.0,
    "harness_discovered": 0.0,
    "build_registered": 0.0,
    "fuzzer_build": 0.0,
    "runtime_check": 0.0,
}
INITIAL_DYNAMIC_GROUP_WEIGHTS = {
    "harness_quality": 0.35,
    "integration_plausibility": 0.15,
    "reference_intent": 0.15,
    "coverage_behavior": 0.25,
    "stability_behavior": 0.07,
    "episode_control": 0.03,
}
MATURE_DYNAMIC_GROUP_WEIGHTS = {
    "harness_quality": 0.20,
    "integration_plausibility": 0.08,
    "reference_intent": 0.08,
    "coverage_behavior": 0.50,
    "stability_behavior": 0.12,
    "episode_control": 0.02,
}
INPUT_NAMES = ("data", "Data", "size", "Size", "bytes", "Bytes", "input", "Input")
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:.>-]*)\s*\(")
ASSIGNMENT_RE = re.compile(
    r"(?:^|[;{]\s*)(?:[A-Za-z_][A-Za-z0-9_:<>*&\s]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*="
)
DECL_ASSIGNMENT_RE = re.compile(
    r"\b(?:auto|char|unsigned|uint8_t|size_t|std::string|String|bytes|byte\[\]|"
    r"[A-Za-z_][A-Za-z0-9_:<>]*)\s+[*&\s]*([A-Za-z_][A-Za-z0-9_]*)\s*="
)
NOISE_CALL_NAMES = {
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "memcpy",
    "memmove",
    "memset",
    "strlen",
    "sizeof",
    "new",
    "delete",
    "if",
    "for",
    "while",
    "switch",
    "return",
}


@dataclass(frozen=True)
class RewardMetrics:
    task_id: str
    run_oss_fuzz: bool
    require_task_end: bool
    has_task_end: bool
    oracle_access_clean: bool
    language: str
    discovered_harness_count: int
    candidate_harnesses: tuple[HarnessInfo, ...]
    candidate_profile: AstProfile
    oracle_profile: AstProfile
    build_registered: bool
    build_passed: bool
    runtime_passed: bool
    candidate_coverage: CoverageMetrics
    oracle_coverage: CoverageMetrics
    input_derived_project_call_present: bool
    tainted_project_api_calls: int
    project_api_calls: int
    notes: tuple[str, ...] = ()
    artifacts: dict[str, str] | None = None


def score_task(
    task_dir: Path,
    *,
    candidate_project_dir: Path | None = None,
    trace: EpisodeTrace | None = None,
    oss_fuzz_dir: Path | None = None,
    run_oss_fuzz: bool = False,
    require_task_end: bool = False,
    reward_config_path: Path | None = None,
    reward_config: RewardConfig | None = None,
) -> RewardReport:
    """Score a completed task workspace with the schema-versioned v3 reward."""

    if reward_config_path is not None and reward_config is not None:
        raise ValueError("pass either reward_config_path or reward_config, not both")

    task = TaskBundle.from_json(read_json(task_dir / "task.json"))
    oracle = OracleMetadata.from_json(read_json(task_dir / "oracle" / "oracle.json"))
    candidate_project_dir = candidate_project_dir or (task_dir / "workspace")
    trace = trace or EpisodeTrace.empty()
    config = reward_config or load_reward_config(reward_config_path)
    validate_reward_config(config)

    if require_task_end and not trace.has_task_end:
        return _hard_zero_report(
            task.task_id,
            config,
            trace=trace,
            require_task_end=require_task_end,
            oracle=oracle,
            reason="missing task-end",
        )
    if trace.attempted_oracle_access:
        return _hard_zero_report(
            task.task_id,
            config,
            trace=trace,
            require_task_end=require_task_end,
            oracle=oracle,
            reason="episode attempted to access hidden oracle artifacts",
        )
    if not run_oss_fuzz:
        raise ValueError(
            "scalar reward scoring requires dynamic OSS-Fuzz coverage; pass --run-oss-fuzz"
        )
    if oss_fuzz_dir is None:
        raise ValueError("--run-oss-fuzz requires --oss-fuzz-dir")
    if not _coverage_available(oracle.coverage):
        raise ValueError("oracle coverage is missing; run baseline-oracle before scoring")

    metrics = collect_reward_metrics(
        task=task,
        oracle=oracle,
        candidate_project_dir=candidate_project_dir,
        trace=trace,
        oss_fuzz_dir=oss_fuzz_dir,
        run_oss_fuzz=run_oss_fuzz,
        require_task_end=require_task_end,
    )
    return score_reward_v3(metrics, config, build_microcomponents(metrics))


def baseline_oracle_coverage(
    task_dir: Path,
    *,
    oss_fuzz_dir: Path,
    coverage_seconds: int = 30,
) -> CoverageMetrics:
    """Run the hidden oracle harness and persist project-code coverage metadata."""

    task = TaskBundle.from_json(read_json(task_dir / "task.json"))
    oracle_path = task_dir / "oracle" / "oracle.json"
    oracle = OracleMetadata.from_json(read_json(oracle_path))
    oracle_project_dir = task_dir / "oracle" / "oss-fuzz-project"
    if not oracle_project_dir.is_dir():
        raise ValueError(f"oracle OSS-Fuzz project directory is missing: {oracle_project_dir}")

    run_result = run_oss_fuzz_checks(
        oss_fuzz_dir=oss_fuzz_dir,
        project_name=task.project.name,
        candidate_project_dir=oracle_project_dir,
        source_workspace_dir=task_dir / "workspace",
        coverage_seconds=coverage_seconds,
    )
    if not run_result.build_passed:
        raise ValueError("oracle build_fuzzers failed; cannot baseline oracle coverage")
    if not run_result.runtime_passed:
        raise ValueError("oracle check_build failed; cannot baseline oracle coverage")
    if not _coverage_available(run_result.coverage_metrics):
        raise ValueError("oracle coverage run produced no coverage metrics")

    updated = OracleMetadata(
        task_id=oracle.task_id,
        harnesses=oracle.harnesses,
        ast_profile=oracle.ast_profile,
        coverage=run_result.coverage_metrics,
    )
    write_json(oracle_path, updated.to_json())
    return run_result.coverage_metrics


def load_reward_config(path: Path | None) -> RewardConfig:
    if path is not None:
        config = RewardConfig.from_json(read_json(path))
        validate_reward_config(config)
        return config
    return default_reward_config()


def default_reward_config(
    *,
    training_progress: float | None = None,
    successful_dynamic_training_episodes: int | None = None,
    anneal_episodes: int = 1,
) -> RewardConfig:
    if successful_dynamic_training_episodes is not None:
        if anneal_episodes <= 0:
            raise ValueError("anneal_episodes must be positive")
        progress = successful_dynamic_training_episodes / anneal_episodes
    else:
        progress = 1.0 if training_progress is None else training_progress
    progress = _clamp(progress)
    alpha = smoothstep(progress)
    weights = _interpolate_group_weights(alpha)
    microcomponent_weights = {
        **RELATIVE_COVERAGE_MICROCOMPONENT_WEIGHTS,
        **NON_REWARD_MICROCOMPONENT_WEIGHTS,
    }

    return RewardConfig(
        schema_version=REWARD_CONFIG_SCHEMA_VERSION,
        stage="dynamic",
        scalar_range=(0.0, 1.0),
        caps=dict(DEFAULT_CAPS),
        group_weights=weights,
        microcomponent_weights=microcomponent_weights,
        name="default-dynamic-continuous",
        training_progress=round(progress, 6),
        schedule_alpha=round(alpha, 6),
    )


def smoothstep(progress: float) -> float:
    p = _clamp(progress)
    return p * p * (3.0 - 2.0 * p)


def _interpolate_group_weights(alpha: float) -> dict[str, float]:
    weights = {
        group: (1.0 - alpha) * INITIAL_DYNAMIC_GROUP_WEIGHTS[group]
        + alpha * MATURE_DYNAMIC_GROUP_WEIGHTS[group]
        for group in REWARD_GROUPS
    }
    total = sum(weights.values())
    return {group: value / total for group, value in weights.items()}


def validate_reward_config(config: RewardConfig) -> None:
    if config.schema_version != REWARD_CONFIG_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported reward config schema_version: {config.schema_version!r}"
        )
    if config.stage != "dynamic":
        raise ValueError(
            "reward config stage must be 'dynamic'; static/phase configs are unsupported"
        )
    if len(config.scalar_range) != 2 or tuple(config.scalar_range) != (0.0, 1.0):
        raise ValueError("reward config scalar_range must be [0, 1]")
    missing_caps = set(DEFAULT_CAPS) - set(config.caps)
    if missing_caps:
        raise ValueError(f"reward config missing caps: {sorted(missing_caps)}")
    for name, value in config.caps.items():
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"reward cap {name!r} must be in [0, 1]")
    if set(config.group_weights) != set(REWARD_GROUPS):
        raise ValueError(f"reward config group_weights must contain {list(REWARD_GROUPS)}")
    for name, value in config.group_weights.items():
        if value < 0.0:
            raise ValueError(f"reward group weight {name!r} must be nonnegative")
    total_weight = sum(config.group_weights.values())
    if not math.isclose(total_weight, 1.0, rel_tol=0.0, abs_tol=1e-6):
        raise ValueError("reward config group_weights must sum to 1.0")
    if not 0.0 <= config.training_progress <= 1.0:
        raise ValueError("reward config training_progress must be in [0, 1]")
    if not 0.0 <= config.schedule_alpha <= 1.0:
        raise ValueError("reward config schedule_alpha must be in [0, 1]")
    known_microcomponents = set(MICROCOMPONENT_GROUPS)
    unknown_microcomponents = set(config.microcomponent_weights) - known_microcomponents
    if unknown_microcomponents:
        raise ValueError(
            f"reward config contains unknown microcomponent weights: "
            f"{sorted(unknown_microcomponents)}"
        )
    for name, value in config.microcomponent_weights.items():
        if value < 0.0:
            raise ValueError(f"reward microcomponent weight {name!r} must be nonnegative")


def collect_reward_metrics(
    *,
    task: TaskBundle,
    oracle: OracleMetadata,
    candidate_project_dir: Path,
    trace: EpisodeTrace,
    oss_fuzz_dir: Path | None,
    run_oss_fuzz: bool,
    require_task_end: bool,
) -> RewardMetrics:
    notes: list[str] = []
    artifacts: dict[str, str] = {}
    project_context_dir = _project_context_dir(candidate_project_dir)
    language = read_project_language(project_context_dir)
    adapter = adapter_for_language(language)
    discovered_harnesses = tuple(adapter.discover_harnesses(candidate_project_dir))
    candidate_harnesses = changed_or_new_harnesses(discovered_harnesses, task)
    candidate_profile = adapter.profile_sources(
        candidate_project_dir, [h.rel_path for h in candidate_harnesses]
    )
    build_registered = static_build_registration_present(candidate_project_dir, candidate_harnesses)
    input_flow = input_derived_project_calls(candidate_project_dir, candidate_harnesses)

    if not run_oss_fuzz:
        raise ValueError("collect_reward_metrics requires dynamic OSS-Fuzz execution")
    if oss_fuzz_dir is None:
        raise ValueError("--run-oss-fuzz requires --oss-fuzz-dir")

    oss_fuzz_project_dir = candidate_project_dir / "oss-fuzz-project"
    source_workspace_dir = candidate_project_dir if oss_fuzz_project_dir.is_dir() else None
    run_project_dir = (
        oss_fuzz_project_dir if oss_fuzz_project_dir.is_dir() else candidate_project_dir
    )
    run_result = run_oss_fuzz_checks(
        oss_fuzz_dir=oss_fuzz_dir,
        project_name=task.project.name,
        candidate_project_dir=run_project_dir,
        source_workspace_dir=source_workspace_dir,
    )
    build_passed = run_result.build_passed and bool(candidate_harnesses)
    runtime_passed = run_result.runtime_passed and bool(candidate_harnesses)
    candidate_coverage = run_result.coverage_metrics
    if run_result.eval_dir:
        artifacts["eval_dir"] = str(run_result.eval_dir)

    return RewardMetrics(
        task_id=task.task_id,
        run_oss_fuzz=run_oss_fuzz,
        require_task_end=require_task_end,
        has_task_end=trace.has_task_end,
        oracle_access_clean=not trace.attempted_oracle_access,
        language=language,
        discovered_harness_count=len(discovered_harnesses),
        candidate_harnesses=candidate_harnesses,
        candidate_profile=candidate_profile,
        oracle_profile=oracle.ast_profile,
        build_registered=build_registered,
        build_passed=build_passed,
        runtime_passed=runtime_passed,
        candidate_coverage=candidate_coverage,
        oracle_coverage=oracle.coverage,
        input_derived_project_call_present=input_flow["tainted_project_api_calls"] > 0,
        tainted_project_api_calls=input_flow["tainted_project_api_calls"],
        project_api_calls=input_flow["project_api_calls"],
        notes=tuple(notes),
        artifacts=artifacts,
    )


def build_microcomponents(metrics: RewardMetrics) -> tuple[RewardMicrocomponent, ...]:
    harness_count = len(metrics.candidate_harnesses)
    entrypoint_count = sum(1 for harness in metrics.candidate_harnesses if harness.entrypoint)
    candidate = metrics.candidate_profile
    oracle = metrics.oracle_profile
    coverage_available = _coverage_available(metrics.candidate_coverage)
    lifecycle_sim = _lifecycle_similarity(candidate, oracle)
    components = [
        _microcomponent(
            "task_end",
            1.0 if not metrics.require_task_end or metrics.has_task_end else 0.0,
            "task-end requirement satisfied",
            {
                "required": metrics.require_task_end,
                "observed": metrics.has_task_end,
            },
        ),
        _microcomponent(
            "oracle_access_clean",
            1.0 if metrics.oracle_access_clean else 0.0,
            "episode did not access hidden oracle artifacts",
        ),
        _microcomponent(
            "harness_discovered",
            1.0 if harness_count else 0.0,
            f"{harness_count} changed/new harnesses discovered",
            {
                "candidate_harnesses": harness_count,
                "discovered_harnesses": metrics.discovered_harness_count,
            },
        ),
        _microcomponent(
            "build_registered",
            1.0 if metrics.build_registered else 0.0,
            f"build registration detected={metrics.build_registered}",
        ),
        _microcomponent(
            "fuzzer_build",
            1.0 if metrics.build_passed else 0.0,
            f"fuzzer build gate passed={metrics.build_passed}",
        ),
        _microcomponent(
            "runtime_check",
            1.0 if metrics.runtime_passed else 0.0,
            f"runtime/check_build gate passed={metrics.runtime_passed}",
        ),
        _microcomponent(
            "entrypoint_validity",
            (entrypoint_count / harness_count) if harness_count else 0.0,
            f"{entrypoint_count}/{harness_count} candidate harnesses expose entrypoints",
        ),
        _microcomponent(
            "input_dataflow",
            1.0 if metrics.input_derived_project_call_present else 0.0,
            "fuzzer input reaches at least one non-noise project/library call",
            {
                "tainted_project_api_calls": metrics.tainted_project_api_calls,
                "project_api_calls": metrics.project_api_calls,
            },
        ),
        _microcomponent(
            "input_api_use",
            _input_api_score(candidate, oracle),
            "candidate input APIs compared to oracle",
            {
                "candidate_input_apis": list(candidate.input_apis),
                "oracle_input_apis": list(oracle.input_apis),
            },
        ),
        _microcomponent(
            "lifecycle_api_use",
            _lifecycle_use_score(candidate, oracle),
            "candidate setup/cleanup APIs compared to oracle",
            {
                "candidate_setup_apis": list(candidate.setup_apis),
                "candidate_cleanup_apis": list(candidate.cleanup_apis),
                "oracle_setup_apis": list(oracle.setup_apis),
                "oracle_cleanup_apis": list(oracle.cleanup_apis),
            },
        ),
        _microcomponent(
            "target_focus",
            _focus_normalized(candidate),
            "API diversity stays within focused-harness bounds",
            {
                "unique_calls": len(set(candidate.call_names)),
                "total_calls": len(candidate.call_names),
            },
        ),
        _microcomponent(
            "call_similarity",
            multiset_jaccard(candidate.call_names, oracle.call_names),
            "candidate call multiset compared to oracle",
        ),
        _microcomponent(
            "input_similarity",
            set_jaccard(candidate.input_apis, oracle.input_apis),
            "candidate input API set compared to oracle",
        ),
        _microcomponent(
            "lifecycle_similarity",
            lifecycle_sim,
            "candidate setup/cleanup API sets compared to oracle",
        ),
        _microcomponent(
            "complexity_similarity",
            bounded_similarity(
                candidate.branch_count + candidate.loop_count,
                oracle.branch_count + oracle.loop_count,
            ),
            "candidate branch/loop count compared to oracle",
            {
                "candidate_complexity": candidate.branch_count + candidate.loop_count,
                "oracle_complexity": oracle.branch_count + oracle.loop_count,
            },
        ),
        _microcomponent(
            "import_similarity",
            set_jaccard(candidate.imported_modules, oracle.imported_modules),
            "candidate imports/includes compared to oracle",
        ),
        _microcomponent(
            "coverage_available",
            1.0 if coverage_available else 0.0,
            f"coverage metrics available={coverage_available}",
        ),
        _microcomponent(
            "line_coverage_absolute",
            _ratio(
                metrics.candidate_coverage.lines_covered,
                metrics.candidate_coverage.lines_total,
            ),
            "absolute line coverage ratio",
            {
                "covered": metrics.candidate_coverage.lines_covered,
                "total": metrics.candidate_coverage.lines_total,
            },
        ),
        _microcomponent(
            "function_coverage_absolute",
            _ratio(
                metrics.candidate_coverage.functions_covered,
                metrics.candidate_coverage.functions_total,
            ),
            "absolute function coverage ratio",
            {
                "covered": metrics.candidate_coverage.functions_covered,
                "total": metrics.candidate_coverage.functions_total,
            },
        ),
        _microcomponent(
            "region_coverage_absolute",
            _ratio(
                metrics.candidate_coverage.regions_covered,
                metrics.candidate_coverage.regions_total,
            ),
            "absolute region coverage ratio",
            {
                "covered": metrics.candidate_coverage.regions_covered,
                "total": metrics.candidate_coverage.regions_total,
            },
        ),
        _microcomponent(
            "line_coverage_vs_oracle",
            _relative_coverage_progress(
                metrics.candidate_coverage.lines_covered,
                metrics.candidate_coverage.lines_total,
                metrics.oracle_coverage.lines_covered,
                metrics.oracle_coverage.lines_total,
            ),
            "line coverage progress relative to oracle and full coverage",
            _relative_coverage_metrics(
                metrics.candidate_coverage.lines_covered,
                metrics.candidate_coverage.lines_total,
                metrics.oracle_coverage.lines_covered,
                metrics.oracle_coverage.lines_total,
            ),
        ),
        _microcomponent(
            "function_coverage_vs_oracle",
            _relative_coverage_progress(
                metrics.candidate_coverage.functions_covered,
                metrics.candidate_coverage.functions_total,
                metrics.oracle_coverage.functions_covered,
                metrics.oracle_coverage.functions_total,
            ),
            "function coverage progress relative to oracle and full coverage",
            _relative_coverage_metrics(
                metrics.candidate_coverage.functions_covered,
                metrics.candidate_coverage.functions_total,
                metrics.oracle_coverage.functions_covered,
                metrics.oracle_coverage.functions_total,
            ),
        ),
        _microcomponent(
            "region_coverage_vs_oracle",
            _relative_coverage_progress(
                metrics.candidate_coverage.regions_covered,
                metrics.candidate_coverage.regions_total,
                metrics.oracle_coverage.regions_covered,
                metrics.oracle_coverage.regions_total,
            ),
            "region coverage progress relative to oracle and full coverage",
            _relative_coverage_metrics(
                metrics.candidate_coverage.regions_covered,
                metrics.candidate_coverage.regions_total,
                metrics.oracle_coverage.regions_covered,
                metrics.oracle_coverage.regions_total,
            ),
        ),
        _microcomponent(
            "no_crashes",
            1.0 if coverage_available and metrics.candidate_coverage.crashes == 0 else 0.0,
            "coverage/check run did not report crashes",
            {"crashes": metrics.candidate_coverage.crashes},
        ),
        _microcomponent(
            "no_timeouts",
            1.0 if coverage_available and metrics.candidate_coverage.timeouts == 0 else 0.0,
            "coverage/check run did not report timeouts",
            {"timeouts": metrics.candidate_coverage.timeouts},
        ),
    ]
    return tuple(components)


def score_reward_v3(
    metrics: RewardMetrics,
    config: RewardConfig,
    raw_components: tuple[RewardMicrocomponent, ...],
    *,
    hard_zero_reason: str | None = None,
) -> RewardReport:
    weighted_components = _apply_microcomponent_weights(raw_components, config)
    groups = _score_groups(weighted_components, config)
    scalar_before_caps = sum(group.weighted_value for group in groups)
    scalar = scalar_before_caps
    applied_caps: list[str] = []
    cap_reasons: list[str] = []

    if hard_zero_reason is not None:
        scalar = 0.0
        applied_caps.append("hard_zero")
        cap_reasons.append(hard_zero_reason)
    if hard_zero_reason is None and not metrics.build_passed:
        scalar = min(scalar, config.caps["build_failed"])
        applied_caps.append("build_failed")
        cap_reasons.append(f"build failed; reward capped at {config.caps['build_failed']:.2f}")
    if hard_zero_reason is None and metrics.build_passed and not metrics.runtime_passed:
        scalar = min(scalar, config.caps["runtime_failed"])
        applied_caps.append("runtime_failed")
        cap_reasons.append(
            f"runtime/check failed; reward capped at {config.caps['runtime_failed']:.2f}"
        )
    if (
        hard_zero_reason is None
        and metrics.build_passed
        and metrics.runtime_passed
        and not _coverage_available(metrics.candidate_coverage)
    ):
        scalar = min(scalar, config.caps["coverage_unavailable"])
        applied_caps.append("coverage_unavailable")
        cap_reasons.append(
            "candidate coverage unavailable after build/check; "
            f"reward capped at {config.caps['coverage_unavailable']:.2f}"
        )
    if hard_zero_reason is None and not metrics.input_derived_project_call_present:
        scalar = min(scalar, config.caps["no_input_derived_project_call"])
        applied_caps.append("no_input_derived_project_call")
        cap_reasons.append(
            "no input-derived project/library API call found; "
            f"reward capped at {config.caps['no_input_derived_project_call']:.2f}"
        )

    scalar = _clamp(scalar)
    notes = tuple(metrics.notes) + tuple(cap_reasons)
    caps: JsonDict = {
        "configured": dict(config.caps),
        "applied": applied_caps,
        "scalar_before_caps": round(scalar_before_caps, 6),
        "scalar_cap": round(scalar, 6) if applied_caps else None,
        "hard_zero": hard_zero_reason is not None,
        "reasons": cap_reasons,
    }
    return RewardReport(
        task_id=metrics.task_id,
        scalar_reward=round(scalar, 6),
        hard_zero=hard_zero_reason is not None,
        build_passed=metrics.build_passed,
        runtime_passed=metrics.runtime_passed,
        caps=caps,
        groups=groups,
        microcomponents=weighted_components,
        raw_metrics=_raw_metrics(metrics),
        reward_config=config,
        notes=notes,
        artifacts=dict(metrics.artifacts or {}),
    )


def changed_or_new_harnesses(
    discovered_harnesses: tuple[HarnessInfo, ...], task: TaskBundle
) -> tuple[HarnessInfo, ...]:
    """Return harnesses created or changed by the candidate episode."""

    baseline_hashes = {h.rel_path: h.source_sha256 for h in task.project.harnesses}
    changed = []
    for harness in discovered_harnesses:
        if baseline_hashes.get(harness.rel_path) != harness.source_sha256:
            changed.append(harness)
    return tuple(changed)


def static_build_registration_present(
    project_dir: Path, harnesses: tuple[HarnessInfo, ...]
) -> bool:
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
        harness.target_name in build_text or Path(harness.rel_path).name in build_text
        for harness in harnesses
    )


def input_derived_project_calls(
    project_dir: Path, harnesses: tuple[HarnessInfo, ...]
) -> JsonDict:
    """Shallow source taint from fuzz input names to non-noise API call arguments."""

    project_api_calls = 0
    tainted_project_api_calls = 0
    tainted_names: set[str] = set(INPUT_NAMES)

    for harness in harnesses:
        source_path = project_dir / harness.rel_path
        if not source_path.is_file():
            continue
        source = source_path.read_text(encoding="utf-8", errors="ignore")
        source_taint = set(tainted_names)
        _propagate_simple_taint(source, source_taint)
        for name, args in _iter_source_calls(source):
            if _is_noise_call(name):
                continue
            project_api_calls += 1
            if _mentions_any_name(args, source_taint):
                tainted_project_api_calls += 1

    return {
        "project_api_calls": project_api_calls,
        "tainted_project_api_calls": tainted_project_api_calls,
    }


def _propagate_simple_taint(source: str, tainted_names: set[str]) -> None:
    lines = source.splitlines()
    for _ in range(4):
        changed = False
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            if _mentions_any_name(stripped, tainted_names):
                for pattern in (DECL_ASSIGNMENT_RE, ASSIGNMENT_RE):
                    match = pattern.search(stripped)
                    if match and match.group(1) not in tainted_names:
                        tainted_names.add(match.group(1))
                        changed = True
            for name, args in _iter_source_calls(stripped):
                if name != "memcpy":
                    continue
                split_args = _split_args(args)
                if len(split_args) >= 3 and _mentions_any_name(
                    ",".join(split_args[1:]), tainted_names
                ):
                    dest = _clean_argument_name(split_args[0])
                    if dest and dest not in tainted_names:
                        tainted_names.add(dest)
                        changed = True
        if not changed:
            break


def _iter_source_calls(source: str) -> Iterable[tuple[str, str]]:
    for match in CALL_RE.finditer(source):
        raw_name = match.group(1)
        name = _normalize_source_call_name(raw_name)
        args = _extract_balanced_call_args(source, match.end() - 1)
        if args is not None:
            yield name, args


def _extract_balanced_call_args(source: str, open_paren_index: int) -> str | None:
    if open_paren_index >= len(source) or source[open_paren_index] != "(":
        return None
    depth = 0
    for index in range(open_paren_index, len(source)):
        char = source[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return source[open_paren_index + 1 : index]
    return None


def _split_args(args: str) -> list[str]:
    values: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(args):
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        elif char == "," and depth == 0:
            values.append(args[start:index].strip())
            start = index + 1
    tail = args[start:].strip()
    if tail:
        values.append(tail)
    return values


def _clean_argument_name(arg: str) -> str:
    arg = arg.strip().lstrip("*&").strip()
    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", arg)
    return match.group(1) if match else ""


def _mentions_any_name(text: str, names: Iterable[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def _normalize_source_call_name(call: str) -> str:
    call = call.strip().replace("->", ".").replace("::", ".")
    return call.rsplit(".", 1)[-1]


def _is_noise_call(name: str) -> bool:
    return name in NOISE_CALL_NAMES or name.startswith("__")


def multiset_jaccard(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    if not left and not right:
        return 1.0
    left_counts = {item: left.count(item) for item in set(left)}
    right_counts = {item: right.count(item) for item in set(right)}
    keys = set(left_counts) | set(right_counts)
    intersection = sum(min(left_counts.get(key, 0), right_counts.get(key, 0)) for key in keys)
    union = sum(max(left_counts.get(key, 0), right_counts.get(key, 0)) for key in keys)
    return intersection / union if union else 0.0


def set_jaccard(left: Iterable[str], right: Iterable[str]) -> float:
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


def _hard_zero_report(
    task_id: str,
    config: RewardConfig,
    *,
    trace: EpisodeTrace,
    require_task_end: bool,
    oracle: OracleMetadata,
    reason: str,
) -> RewardReport:
    metrics = RewardMetrics(
        task_id=task_id,
        run_oss_fuzz=True,
        require_task_end=require_task_end,
        has_task_end=trace.has_task_end,
        oracle_access_clean=not trace.attempted_oracle_access,
        language=oracle.ast_profile.language,
        discovered_harness_count=0,
        candidate_harnesses=(),
        candidate_profile=_empty_profile(oracle.ast_profile.language),
        oracle_profile=oracle.ast_profile,
        build_registered=False,
        build_passed=False,
        runtime_passed=False,
        candidate_coverage=CoverageMetrics(),
        oracle_coverage=oracle.coverage,
        input_derived_project_call_present=False,
        tainted_project_api_calls=0,
        project_api_calls=0,
        notes=(reason,),
        artifacts={},
    )
    return score_reward_v3(metrics, config, build_microcomponents(metrics), hard_zero_reason=reason)


def _microcomponent(
    name: str,
    value: float,
    reason: str,
    metrics: JsonDict | None = None,
) -> RewardMicrocomponent:
    normalized = _clamp(value)
    return RewardMicrocomponent(
        name=name,
        group=MICROCOMPONENT_GROUPS[name],
        value=round(normalized, 6),
        max_value=1.0,
        normalized=round(normalized, 6),
        weight=0.0,
        weighted_value=0.0,
        reason=reason,
        metrics=dict(metrics or {}),
    )


def _apply_microcomponent_weights(
    components: tuple[RewardMicrocomponent, ...], config: RewardConfig
) -> tuple[RewardMicrocomponent, ...]:
    raw_weight_by_name = {
        component.name: config.microcomponent_weights.get(component.name, 1.0)
        for component in components
    }
    group_weight_sums = {
        group: sum(
            raw_weight_by_name[component.name]
            for component in components
            if component.group == group
        )
        for group in REWARD_GROUPS
    }
    weighted = []
    for component in components:
        group_weight_sum = group_weight_sums[component.group]
        weight = (
            raw_weight_by_name[component.name] / group_weight_sum
            if group_weight_sum > 0.0
            else 0.0
        )
        weighted_value = component.normalized * weight
        weighted.append(
            RewardMicrocomponent(
                name=component.name,
                group=component.group,
                value=component.value,
                max_value=component.max_value,
                normalized=component.normalized,
                weight=round(weight, 6),
                weighted_value=round(weighted_value, 6),
                reason=component.reason,
                metrics=component.metrics,
            )
        )
    return tuple(weighted)


def _score_groups(
    components: tuple[RewardMicrocomponent, ...], config: RewardConfig
) -> tuple[RewardGroupScore, ...]:
    groups = []
    for group in REWARD_GROUPS:
        group_components = tuple(component for component in components if component.group == group)
        normalized = sum(component.weighted_value for component in group_components)
        group_weight = config.group_weights[group]
        groups.append(
            RewardGroupScore(
                name=group,
                weight=round(group_weight, 6),
                normalized=round(normalized, 6),
                weighted_value=round(normalized * group_weight, 6),
                microcomponents=tuple(component.name for component in group_components),
            )
        )
    return tuple(groups)


def _raw_metrics(metrics: RewardMetrics) -> JsonDict:
    return {
        "run_oss_fuzz": metrics.run_oss_fuzz,
        "require_task_end": metrics.require_task_end,
        "has_task_end": metrics.has_task_end,
        "oracle_access_clean": metrics.oracle_access_clean,
        "language": metrics.language,
        "candidate_harness_count": len(metrics.candidate_harnesses),
        "discovered_harness_count": metrics.discovered_harness_count,
        "candidate_harnesses": [harness.to_json() for harness in metrics.candidate_harnesses],
        "candidate_ast_profile": metrics.candidate_profile.to_json(),
        "oracle_ast_profile": metrics.oracle_profile.to_json(),
        "build_registered": metrics.build_registered,
        "build_passed": metrics.build_passed,
        "runtime_passed": metrics.runtime_passed,
        "candidate_coverage": metrics.candidate_coverage.to_json(),
        "oracle_coverage": metrics.oracle_coverage.to_json(),
        "input_derived_project_call_present": metrics.input_derived_project_call_present,
        "tainted_project_api_calls": metrics.tainted_project_api_calls,
        "project_api_calls": metrics.project_api_calls,
    }


def _project_context_dir(candidate_project_dir: Path) -> Path:
    oss_fuzz_project_dir = candidate_project_dir / "oss-fuzz-project"
    return oss_fuzz_project_dir if oss_fuzz_project_dir.is_dir() else candidate_project_dir


def _candidate_build_files(project_dir: Path) -> list[Path]:
    names = {"build.sh", "Dockerfile"}
    return sorted(path for path in project_dir.rglob("*") if path.is_file() and path.name in names)


def _coverage_available(coverage: CoverageMetrics) -> bool:
    return any(
        value > 0
        for value in (
            coverage.lines_covered,
            coverage.lines_total,
            coverage.functions_covered,
            coverage.functions_total,
            coverage.regions_covered,
            coverage.regions_total,
        )
    )


def _relative_coverage_progress(
    candidate_covered: int,
    candidate_total: int,
    oracle_covered: int,
    oracle_total: int,
) -> float:
    """Score absolute coverage breadth with oracle covered-count parity at 0.8."""

    candidate_ratio = _ratio(candidate_covered, candidate_total)
    if candidate_covered <= 0 or candidate_ratio <= 0.0:
        return 0.0

    oracle_denominator = _oracle_coverage_denominator(
        oracle_covered=oracle_covered,
        oracle_total=oracle_total,
        fallback_total=candidate_total,
    )
    if oracle_denominator <= 0 or oracle_covered <= 0:
        return candidate_ratio

    candidate_oracle_ratio = _ratio(candidate_covered, oracle_denominator)
    oracle_ratio = _oracle_coverage_ratio(
        oracle_covered=oracle_covered,
        oracle_total=oracle_total,
        fallback_total=oracle_denominator,
    )
    if oracle_ratio <= 0.0:
        return candidate_ratio
    oracle_progress = min(candidate_oracle_ratio / oracle_ratio, 1.0)
    improvement_above_oracle = 0.0
    if candidate_oracle_ratio > oracle_ratio and oracle_ratio < 1.0:
        improvement_above_oracle = (candidate_oracle_ratio - oracle_ratio) / (
            1.0 - oracle_ratio
        )
    return _clamp((0.8 * oracle_progress) + (0.2 * improvement_above_oracle))


def _relative_coverage_metrics(
    candidate_covered: int,
    candidate_total: int,
    oracle_covered: int,
    oracle_total: int,
) -> JsonDict:
    oracle_denominator = _oracle_coverage_denominator(
        oracle_covered=oracle_covered,
        oracle_total=oracle_total,
        fallback_total=candidate_total,
    )
    oracle_ratio = _oracle_coverage_ratio(
        oracle_covered=oracle_covered,
        oracle_total=oracle_total,
        fallback_total=oracle_denominator,
    )
    return {
        "candidate_covered": candidate_covered,
        "candidate_total": candidate_total,
        "candidate_ratio": round(_ratio(candidate_covered, candidate_total), 6),
        "oracle_covered": oracle_covered,
        "oracle_total": oracle_total,
        "oracle_ratio": round(oracle_ratio, 6),
        "oracle_denominator": oracle_denominator,
        "candidate_oracle_ratio": round(_ratio(candidate_covered, oracle_denominator), 6),
        "candidate_to_oracle_covered_ratio": round(
            _ratio(candidate_covered, oracle_covered), 6
        ),
        "oracle_parity_score": 0.8,
        "score_shape": (
            "0..0.8 up to oracle covered-count parity, "
            "0.8..1.0 above oracle covered-count parity toward oracle denominator"
        ),
    }


def _oracle_coverage_denominator(
    *,
    oracle_covered: int,
    oracle_total: int,
    fallback_total: int,
) -> int:
    if oracle_total > 0:
        return oracle_total
    if oracle_covered <= 0:
        return 0
    return max(fallback_total, oracle_covered)


def _oracle_coverage_ratio(
    *,
    oracle_covered: int,
    oracle_total: int,
    fallback_total: int,
) -> float:
    if oracle_total > 0:
        return _ratio(oracle_covered, oracle_total)
    if oracle_covered <= 0:
        return 0.0
    return _ratio(oracle_covered, fallback_total)


def _ratio(covered: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return _clamp(covered / total)


def _input_api_score(candidate: AstProfile, oracle: AstProfile) -> float:
    return set_jaccard(candidate.input_apis, oracle.input_apis)


def _lifecycle_use_score(candidate: AstProfile, oracle: AstProfile) -> float:
    if oracle.setup_apis or oracle.cleanup_apis:
        return _lifecycle_similarity(candidate, oracle)
    return 1.0 if not candidate.setup_apis and not candidate.cleanup_apis else 0.0


def _lifecycle_similarity(candidate: AstProfile, oracle: AstProfile) -> float:
    setup = set_jaccard(candidate.setup_apis, oracle.setup_apis)
    cleanup = set_jaccard(candidate.cleanup_apis, oracle.cleanup_apis)
    return (setup + cleanup) / 2.0


def _focus_normalized(profile: AstProfile) -> float:
    unique_calls = len(set(profile.call_names))
    total_calls = len(profile.call_names)
    if total_calls == 0:
        return 0.0
    diversity = unique_calls / total_calls
    focus = 1.0 - abs(diversity - 0.35)
    focus = _clamp(focus)
    if unique_calls <= 2:
        focus *= 0.6
    return _clamp(focus)


def _empty_profile(language: str) -> AstProfile:
    return AstProfile(
        language=language,
        files=(),
        entrypoints=(),
        imported_modules=(),
        call_names=(),
        input_apis=(),
        setup_apis=(),
        cleanup_apis=(),
        branch_count=0,
        loop_count=0,
        source_bytes=0,
    )


def _clamp(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value
