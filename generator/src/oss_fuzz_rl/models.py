"""Serializable data models for task generation and reward scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

JsonDict = dict[str, Any]


@dataclass(frozen=True)
class HarnessInfo:
    """Metadata for a fuzz harness discovered in an OSS-Fuzz project."""

    rel_path: str
    language: str
    target_name: str
    entrypoint: str | None
    source_sha256: str

    def to_json(self) -> JsonDict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: JsonDict) -> HarnessInfo:
        return cls(
            rel_path=str(data["rel_path"]),
            language=str(data["language"]),
            target_name=str(data["target_name"]),
            entrypoint=data.get("entrypoint"),
            source_sha256=str(data["source_sha256"]),
        )


@dataclass(frozen=True)
class ProjectInfo:
    """A project-level view of an OSS-Fuzz integration."""

    name: str
    language: str
    rel_path: str
    harnesses: tuple[HarnessInfo, ...] = field(default_factory=tuple)

    def to_json(self) -> JsonDict:
        return {
            "name": self.name,
            "language": self.language,
            "rel_path": self.rel_path,
            "harnesses": [h.to_json() for h in self.harnesses],
        }

    @classmethod
    def from_json(cls, data: JsonDict) -> ProjectInfo:
        return cls(
            name=str(data["name"]),
            language=str(data["language"]),
            rel_path=str(data["rel_path"]),
            harnesses=tuple(HarnessInfo.from_json(h) for h in data.get("harnesses", [])),
        )


@dataclass(frozen=True)
class AstProfile:
    """A normalized static profile used for reference and focus scoring."""

    language: str
    files: tuple[str, ...]
    entrypoints: tuple[str, ...]
    imported_modules: tuple[str, ...]
    call_names: tuple[str, ...]
    input_apis: tuple[str, ...]
    setup_apis: tuple[str, ...]
    cleanup_apis: tuple[str, ...]
    branch_count: int
    loop_count: int
    source_bytes: int

    def to_json(self) -> JsonDict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: JsonDict) -> AstProfile:
        return cls(
            language=str(data.get("language", "unknown")),
            files=tuple(data.get("files", [])),
            entrypoints=tuple(data.get("entrypoints", [])),
            imported_modules=tuple(data.get("imported_modules", [])),
            call_names=tuple(data.get("call_names", [])),
            input_apis=tuple(data.get("input_apis", [])),
            setup_apis=tuple(data.get("setup_apis", [])),
            cleanup_apis=tuple(data.get("cleanup_apis", [])),
            branch_count=int(data.get("branch_count", 0)),
            loop_count=int(data.get("loop_count", 0)),
            source_bytes=int(data.get("source_bytes", 0)),
        )


@dataclass(frozen=True)
class CoverageMetrics:
    """Coverage/performance metrics from OSS-Fuzz coverage or Fuzz Introspector."""

    lines_covered: int = 0
    lines_total: int = 0
    functions_covered: int = 0
    functions_total: int = 0
    regions_covered: int = 0
    regions_total: int = 0
    crashes: int = 0
    timeouts: int = 0
    raw: JsonDict = field(default_factory=dict)

    @property
    def line_coverage(self) -> float:
        if self.lines_total <= 0:
            return 0.0
        return self.lines_covered / self.lines_total

    def to_json(self) -> JsonDict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: JsonDict | None) -> CoverageMetrics:
        if not data:
            return cls()
        return cls(
            lines_covered=int(data.get("lines_covered", 0)),
            lines_total=int(data.get("lines_total", 0)),
            functions_covered=int(data.get("functions_covered", 0)),
            functions_total=int(data.get("functions_total", 0)),
            regions_covered=int(data.get("regions_covered", 0)),
            regions_total=int(data.get("regions_total", 0)),
            crashes=int(data.get("crashes", 0)),
            timeouts=int(data.get("timeouts", 0)),
            raw=dict(data.get("raw", {})),
        )


@dataclass(frozen=True)
class TaskBundle:
    """Public metadata for a generated task bundle."""

    task_id: str
    project: ProjectInfo
    masked_harnesses: tuple[HarnessInfo, ...]
    created_by: str = "oss-fuzz-rl-eval"

    def to_json(self) -> JsonDict:
        return {
            "task_id": self.task_id,
            "project": self.project.to_json(),
            "masked_harnesses": [h.to_json() for h in self.masked_harnesses],
            "created_by": self.created_by,
        }

    @classmethod
    def from_json(cls, data: JsonDict) -> TaskBundle:
        return cls(
            task_id=str(data["task_id"]),
            project=ProjectInfo.from_json(data["project"]),
            masked_harnesses=tuple(
                HarnessInfo.from_json(h) for h in data.get("masked_harnesses", [])
            ),
            created_by=str(data.get("created_by", "oss-fuzz-rl-eval")),
        )


@dataclass(frozen=True)
class OracleMetadata:
    """Hidden metadata used by the scorer and never shown to the policy."""

    task_id: str
    harnesses: tuple[HarnessInfo, ...]
    ast_profile: AstProfile
    coverage: CoverageMetrics = field(default_factory=CoverageMetrics)

    def to_json(self) -> JsonDict:
        return {
            "task_id": self.task_id,
            "harnesses": [h.to_json() for h in self.harnesses],
            "ast_profile": self.ast_profile.to_json(),
            "coverage": self.coverage.to_json(),
        }

    @classmethod
    def from_json(cls, data: JsonDict) -> OracleMetadata:
        return cls(
            task_id=str(data["task_id"]),
            harnesses=tuple(HarnessInfo.from_json(h) for h in data.get("harnesses", [])),
            ast_profile=AstProfile.from_json(data.get("ast_profile", {})),
            coverage=CoverageMetrics.from_json(data.get("coverage")),
        )


@dataclass(frozen=True)
class RewardMicrocomponent:
    """A single normalized v2 reward signal."""

    name: str
    group: str
    value: float
    max_value: float
    normalized: float
    weight: float
    weighted_value: float
    reason: str
    metrics: JsonDict = field(default_factory=dict)

    def to_json(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class RewardGroupScore:
    """A weighted group of reward microcomponents."""

    name: str
    weight: float
    normalized: float
    weighted_value: float
    microcomponents: tuple[str, ...]

    def to_json(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class RewardConfig:
    """Configuration for curriculum-weighted reward scoring."""

    schema_version: str
    stage: str
    scalar_range: tuple[float, float]
    caps: dict[str, float]
    group_weights: dict[str, float]
    microcomponent_weights: dict[str, float] = field(default_factory=dict)
    name: str | None = None
    training_progress: float = 1.0
    schedule_alpha: float = 1.0

    def to_json(self) -> JsonDict:
        data: JsonDict = {
            "schema_version": self.schema_version,
            "stage": self.stage,
            "scalar_range": list(self.scalar_range),
            "caps": dict(self.caps),
            "group_weights": dict(self.group_weights),
            "microcomponent_weights": dict(self.microcomponent_weights),
            "training_progress": self.training_progress,
            "schedule_alpha": self.schedule_alpha,
        }
        if self.name:
            data["name"] = self.name
        return data

    @classmethod
    def from_json(cls, data: JsonDict) -> RewardConfig:
        scalar_range_values = tuple(
            float(value) for value in data.get("scalar_range", [0, 1])
        )
        return cls(
            schema_version=str(data.get("schema_version", "")),
            stage=str(data.get("stage", "dynamic")),
            scalar_range=scalar_range_values,  # type: ignore[arg-type]
            caps={str(key): float(value) for key, value in data.get("caps", {}).items()},
            group_weights={
                str(key): float(value) for key, value in data.get("group_weights", {}).items()
            },
            microcomponent_weights={
                str(key): float(value)
                for key, value in data.get("microcomponent_weights", {}).items()
            },
            name=str(data["name"]) if data.get("name") else None,
            training_progress=float(data.get("training_progress", 1.0)),
            schedule_alpha=float(data.get("schedule_alpha", 1.0)),
        )


@dataclass(frozen=True)
class RewardReport:
    """Complete v3 scoring output for a task episode."""

    task_id: str
    scalar_reward: float
    hard_zero: bool
    build_passed: bool
    runtime_passed: bool
    caps: JsonDict
    groups: tuple[RewardGroupScore, ...]
    microcomponents: tuple[RewardMicrocomponent, ...]
    raw_metrics: JsonDict
    reward_config: RewardConfig
    notes: tuple[str, ...] = field(default_factory=tuple)
    artifacts: dict[str, str] = field(default_factory=dict)
    schema_version: str = "reward.v3"

    def to_json(self) -> JsonDict:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "scalar_reward": self.scalar_reward,
            "caps": dict(self.caps),
            "groups": {group.name: group.to_json() for group in self.groups},
            "microcomponents": [component.to_json() for component in self.microcomponents],
            "raw_metrics": dict(self.raw_metrics),
            "reward_config": self.reward_config.to_json(),
            "notes": list(self.notes),
            "artifacts": dict(self.artifacts),
        }


def path_from_json(data: str | Path) -> Path:
    return Path(data).expanduser().resolve()
