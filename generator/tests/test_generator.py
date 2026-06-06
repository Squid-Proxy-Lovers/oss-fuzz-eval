from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_fuzz_rl.cli import main as cli_main
from oss_fuzz_rl.episode import EpisodeTrace
from oss_fuzz_rl.models import CoverageMetrics
from oss_fuzz_rl.project_index import index_projects
from oss_fuzz_rl.reward import (
    _relative_coverage_metrics,
    _relative_coverage_progress,
    default_reward_config,
    score_task,
)
from oss_fuzz_rl.sanitizer import REDACTION_MARKER, sanitize_source_tree
from oss_fuzz_rl.source_workspace import parse_source_commands, select_primary_source_command
from oss_fuzz_rl.task_generator import generate_tasks


def make_fake_oss_fuzz(tmp_path: Path) -> Path:
    root = tmp_path / "oss-fuzz"
    project = root / "projects" / "demo"
    project.mkdir(parents=True)
    upstream = make_fake_upstream_repo(tmp_path)
    (root / "infra").mkdir()
    (project / "project.yaml").write_text("language: c++\n", encoding="utf-8")
    (project / "Dockerfile").write_text(
        "\n".join(
            [
                "FROM gcr.io/oss-fuzz-base/base-builder",
                f"RUN git clone --depth 1 {upstream.as_uri()} demo",
                "WORKDIR demo",
                "COPY build.sh demo_fuzzer.cc $SRC/",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (project / "build.sh").write_text(
        "$CXX $CXXFLAGS $SRC/demo_fuzzer.cc -o $OUT/demo_fuzzer $LIB_FUZZING_ENGINE\n",
        encoding="utf-8",
    )
    (project / "demo_fuzzer.cc").write_text(
        """
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 4) {
    parse_demo(data, size);
  }
  cleanup_demo();
  return 0;
}
""",
        encoding="utf-8",
    )
    return root


def make_fake_upstream_repo(tmp_path: Path) -> Path:
    upstream = tmp_path / "upstream-demo"
    (upstream / "src").mkdir(parents=True)
    (upstream / "fuzz").mkdir()
    (upstream / ".github" / "workflows").mkdir(parents=True)
    (upstream / "src" / "parser.c").write_text("int parse_demo(const char *p) { return p[0]; }\n")
    (upstream / "src" / "hidden_entrypoint.cc").write_text(
        """
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return size == 0 || data[0] == 0;
}
""",
        encoding="utf-8",
    )
    (upstream / "README.md").write_text(
        "Normal parser documentation.\nThis project has a fuzzing guide.\n",
        encoding="utf-8",
    )
    (upstream / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: [push]\n",
        encoding="utf-8",
    )
    (upstream / ".github" / "workflows" / "fuzz.yml").write_text(
        "name: fuzz\nrun: cargo fuzz run parser\n",
        encoding="utf-8",
    )
    (upstream / "fuzz" / "old_fuzz.cc").write_text("int old_fuzz() { return 0; }\n")
    (upstream / "src" / "existing_fuzzer.cc").write_text("int existing_fuzzer() { return 0; }\n")
    subprocess.run(["git", "init"], cwd=upstream, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=upstream, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            "init",
        ],
        cwd=upstream,
        check=True,
        capture_output=True,
    )
    return upstream


def test_index_discovers_harness(tmp_path: Path) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    projects = index_projects(oss_fuzz)
    assert len(projects) == 1
    assert projects[0].name == "demo"
    assert projects[0].harnesses[0].rel_path == "demo_fuzzer.cc"


def test_parse_dockerfile_source_clone(tmp_path: Path) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    dockerfile = oss_fuzz / "projects" / "demo" / "Dockerfile"
    commands = parse_source_commands(dockerfile)
    selected = select_primary_source_command(dockerfile)
    assert len(commands) == 1
    assert selected is not None
    assert selected.kind == "git"
    assert selected.dest_name == "demo"


def test_generate_clones_upstream_and_scrubs_fuzz_artifacts(tmp_path: Path) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    tasks = generate_tasks(oss_fuzz, tmp_path / "tasks", project_name="demo", limit=1)
    assert len(tasks) == 1
    task = tasks[0]
    source = task / "workspace" / "demo"
    integration = task / "workspace" / "oss-fuzz-project"
    assert (source / "src" / "parser.c").is_file()
    assert (source / "README.md").is_file()
    assert REDACTION_MARKER in (source / "README.md").read_text(encoding="utf-8")
    assert "fuzzing guide" not in (source / "README.md").read_text(encoding="utf-8")
    assert not (source / ".git").exists()
    assert (source / ".github").is_dir()
    assert (source / ".github" / "workflows" / "ci.yml").is_file()
    assert not (source / ".github" / "workflows" / "fuzz.yml").exists()
    assert not (source / "src" / "hidden_entrypoint.cc").exists()
    assert not (source / "fuzz").exists()
    assert not (source / "src" / "existing_fuzzer.cc").exists()
    assert not (integration / "demo_fuzzer.cc").exists()
    assert "demo_fuzzer" not in (integration / "build.sh").read_text(encoding="utf-8")
    assert (task / "oracle" / "files" / "demo_fuzzer.cc").is_file()


def test_sanitizer_redacts_guidance_without_removing_mixed_context(tmp_path: Path) -> None:
    root = tmp_path / "source"
    (root / "src").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / ".gitmodules").write_text("[submodule]\n", encoding="utf-8")
    (root / "README.md").write_text(
        "Normal API docs stay.\nOSS-Fuzz runs the parser harness.\n",
        encoding="utf-8",
    )
    (root / "CMakeLists.txt").write_text(
        "add_library(project src/parser.cc)\n"
        "add_executable(parser_fuzzer\n"
        "  fuzz/parser_fuzzer.cc\n"
        ")\n",
        encoding="utf-8",
    )
    (root / "docs" / "fuzzing.rst").write_text("How to run the fuzzer.\n", encoding="utf-8")
    (root / ".github" / "workflows" / "test.yml").write_text(
        "name: test\non: [push]\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\njobs:\n  fuzz:\n    run: cargo fuzz run parser\n",
        encoding="utf-8",
    )
    (root / "src" / "hidden.cc").write_text(
        """
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return data != nullptr && size > 0;
}
""",
        encoding="utf-8",
    )
    (root / "src" / "production.c").write_text(
        "#ifdef PROJECT_FUZZER\nint keep_building(void) { return 1; }\n#endif\n",
        encoding="utf-8",
    )

    report = sanitize_source_tree(root)

    assert not (root / ".git").exists()
    assert not (root / ".gitmodules").exists()
    assert (root / ".github").is_dir()
    assert (root / ".github" / "workflows" / "test.yml").is_file()
    assert not (root / ".github" / "workflows" / "ci.yml").exists()
    assert not (root / "docs" / "fuzzing.rst").exists()
    assert not (root / "src" / "hidden.cc").exists()
    assert "PROJECT_FUZZER" in (root / "src" / "production.c").read_text(encoding="utf-8")

    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "Normal API docs stay." in readme
    assert "OSS-Fuzz" not in readme
    assert REDACTION_MARKER in readme

    cmake = (root / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "add_library(project src/parser.cc)" in cmake
    assert "parser_fuzzer" not in cmake
    assert REDACTION_MARKER not in cmake
    assert "add_executable(" not in cmake

    records = {record.path: record for record in report.records}
    assert records[".github/workflows/ci.yml"].reason == "ci-fuzz-guidance-content"
    assert records["src/hidden.cc"].reason == "harness-entrypoint-content"
    assert records["README.md"].action == "redact"


def test_sanitizer_removes_cmake_fuzz_directives_without_breaking_syntax(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "CMakeLists.txt").write_text(
        "\n".join(
            [
                "cmake_minimum_required(VERSION 3.20)",
                "project(demo)",
                "option(BUILD_FUZZERS \"Build fuzz harnesses\" OFF)",
                "add_library(core src/core.c)",
                "if (BUILD_FUZZERS)",
                "  add_compile_definitions(BUILD_FOR_OSS_FUZZ=1)",
                "  add_library(demo_fuzzer fuzz/demo_fuzzer.cc)",
                "else()",
                "  add_executable(demo src/main.c)",
                "endif()",
                "add_executable(aresfuzz ${FUZZSOURCES})",
                "target_compile_definitions(aresfuzz PRIVATE CARES_NO_DEPRECATED)",
                "target_link_libraries(aresfuzz PRIVATE caresinternal)",
                "add_executable(normal src/normal.c)",
                "target_link_libraries(normal PRIVATE caresinternal)",
                "",
            ]
        ),
        encoding="utf-8",
    )

    report = sanitize_source_tree(root)

    cmake = (root / "CMakeLists.txt").read_text(encoding="utf-8")
    assert REDACTION_MARKER not in cmake
    assert "BUILD_FUZZERS" not in cmake
    assert "demo_fuzzer" not in cmake
    assert "aresfuzz" not in cmake
    assert "add_executable(demo src/main.c)" in cmake
    assert "target_link_libraries(normal PRIVATE caresinternal)" in cmake
    assert cmake.count("(") == cmake.count(")")
    assert report.counts_by_action()["redact"] == 1


def test_sanitizer_removes_meson_fuzz_options_without_markers(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "meson_options.txt").write_text(
        "option('memory-usage', type: 'integer', value: 0)\n"
        "option('ossfuzz', type: 'boolean', value: true,\n"
        "  description: 'Enable ossfuzz')\n"
        "option('programs', type: 'boolean', value: false)\n",
        encoding="utf-8",
    )

    sanitize_source_tree(root)

    meson = (root / "meson_options.txt").read_text(encoding="utf-8")
    assert REDACTION_MARKER not in meson
    assert "ossfuzz" not in meson
    assert "memory-usage" in meson
    assert "programs" in meson


def test_sanitizer_removes_go_fuzz_function_from_mixed_test_file(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "parser_test.go").write_text(
        """
package parser

import (
	"strings"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	require.Equal(t, "A", strings.ToUpper("a"))
}

// func FuzzCommented(f *testing.F) {
// }

func FuzzParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		consumer := fuzz.NewConsumer(data)
		value, err := consumer.GetString()
		if err == nil {
			_ = strings.ToUpper(value)
		}
	})
}

func helper() string {
	return strings.TrimSpace(" kept ")
}
""",
        encoding="utf-8",
    )

    report = sanitize_source_tree(root)

    source = (root / "parser_test.go").read_text(encoding="utf-8")
    assert "func TestParse" in source
    assert "func helper" in source
    assert "func FuzzParse" not in source
    assert "FuzzCommented" in source
    assert "go-fuzz-headers" not in source
    assert '"strings"' in source
    assert '"testing"' in source
    assert report.counts_by_action()["redact"] == 1


def test_sanitizer_deletes_fuzz_only_go_file(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "hidden_test.go").write_text(
        """
package parser

import "testing"

func FuzzParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {})
}
""",
        encoding="utf-8",
    )

    report = sanitize_source_tree(root)

    assert not (root / "hidden_test.go").exists()
    records = {record.path: record for record in report.records}
    assert records["hidden_test.go"].action == "delete"
    assert records["hidden_test.go"].reason == "harness-entrypoint-content"


def seed_oracle_coverage(task: Path) -> None:
    oracle_path = task / "oracle" / "oracle.json"
    data = json.loads(oracle_path.read_text(encoding="utf-8"))
    data["coverage"] = CoverageMetrics(
        lines_covered=50,
        lines_total=100,
        functions_covered=5,
        functions_total=10,
        regions_covered=20,
        regions_total=40,
    ).to_json()
    oracle_path.write_text(json.dumps(data), encoding="utf-8")


def fake_oss_fuzz_result(
    *,
    build_passed: bool = True,
    runtime_passed: bool = True,
    coverage: CoverageMetrics | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        build_passed=build_passed,
        runtime_passed=runtime_passed,
        coverage_metrics=coverage
        or CoverageMetrics(
            lines_covered=50,
            lines_total=100,
            functions_covered=5,
            functions_total=10,
            regions_covered=20,
            regions_total=40,
        ),
        eval_dir=None,
    )


def test_dynamic_score_oracle_replay_is_positive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    task = generate_tasks(oss_fuzz, tmp_path / "tasks", project_name="demo", limit=1)[0]
    seed_oracle_coverage(task)
    candidate = task / "workspace"
    integration = candidate / "oss-fuzz-project"
    oracle_file = task / "oracle" / "files" / "demo_fuzzer.cc"
    (integration / "demo_fuzzer.cc").write_text(
        oracle_file.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (integration / "build.sh").write_text(
        "$CXX $CXXFLAGS $SRC/demo_fuzzer.cc -o $OUT/demo_fuzzer $LIB_FUZZING_ENGINE\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "oss_fuzz_rl.reward.run_oss_fuzz_checks",
        lambda **_: fake_oss_fuzz_result(),
    )
    report = score_task(
        task,
        candidate_project_dir=candidate,
        oss_fuzz_dir=oss_fuzz,
        run_oss_fuzz=True,
    )
    assert report.scalar_reward > 0.5
    assert report.build_passed
    assert report.to_json()["schema_version"] == "reward.v3"
    assert report.to_json()["reward_config"]["name"] == "default-dynamic-continuous"
    assert report.caps["applied"] == []
    assert {group.name for group in report.groups} == {
        "episode_control",
        "integration_plausibility",
        "harness_quality",
        "reference_intent",
        "coverage_behavior",
        "stability_behavior",
    }
    assert {component.name for component in report.microcomponents} >= {
        "task_end",
        "fuzzer_build",
        "runtime_check",
        "input_dataflow",
        "call_similarity",
        "coverage_available",
        "no_crashes",
    }
    assert "size_sanity" not in {component.name for component in report.microcomponents}


def test_score_without_dynamic_coverage_is_usage_error(tmp_path: Path) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    task = generate_tasks(oss_fuzz, tmp_path / "tasks", project_name="demo", limit=1)[0]
    with pytest.raises(ValueError, match="requires dynamic OSS-Fuzz coverage"):
        score_task(task)


def test_missing_task_end_hard_zero(tmp_path: Path) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    task = generate_tasks(oss_fuzz, tmp_path / "tasks", project_name="demo", limit=1)[0]
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_text(json.dumps({"tool": "write", "input": {"filePath": "x"}}) + "\n")
    report = score_task(task, trace=EpisodeTrace.from_jsonl(trace_path), require_task_end=True)
    assert report.scalar_reward == 0.0
    assert report.hard_zero
    assert report.caps["applied"] == ["hard_zero"]


def test_missing_oracle_coverage_fails_scalar_scoring(tmp_path: Path) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    task = generate_tasks(oss_fuzz, tmp_path / "tasks", project_name="demo", limit=1)[0]
    with pytest.raises(ValueError, match="oracle coverage is missing"):
        score_task(task, oss_fuzz_dir=oss_fuzz, run_oss_fuzz=True)


def test_score_cli_accepts_reward_config_and_writes_v3_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    task = generate_tasks(oss_fuzz, tmp_path / "tasks", project_name="demo", limit=1)[0]
    seed_oracle_coverage(task)
    candidate = task / "workspace"
    integration = candidate / "oss-fuzz-project"
    oracle_file = task / "oracle" / "files" / "demo_fuzzer.cc"
    (integration / "demo_fuzzer.cc").write_text(
        oracle_file.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (integration / "build.sh").write_text(
        "$CXX $CXXFLAGS $SRC/demo_fuzzer.cc -o $OUT/demo_fuzzer $LIB_FUZZING_ENGINE\n",
        encoding="utf-8",
    )
    config = default_reward_config().to_json()
    config["name"] = "harness-quality-only"
    config["group_weights"] = {
        "episode_control": 0.0,
        "integration_plausibility": 0.0,
        "harness_quality": 1.0,
        "reference_intent": 0.0,
        "coverage_behavior": 0.0,
        "stability_behavior": 0.0,
    }
    config_path = tmp_path / "reward-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    out_path = tmp_path / "reward-report.json"
    monkeypatch.setattr(
        "oss_fuzz_rl.reward.run_oss_fuzz_checks",
        lambda **_: fake_oss_fuzz_result(),
    )

    assert (
        cli_main(
            [
                "score",
                "--task",
                str(task),
                "--workspace",
                str(candidate),
                "--oss-fuzz-dir",
                str(oss_fuzz),
                "--run-oss-fuzz",
                "--reward-config",
                str(config_path),
                "--json-out",
                str(out_path),
            ]
        )
        == 0
    )

    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == "reward.v3"
    assert report["reward_config"]["name"] == "harness-quality-only"
    assert report["groups"]["harness_quality"]["weight"] == 1.0
    assert report["caps"]["applied"] == []


def test_relative_coverage_progress_curve() -> None:
    assert _relative_coverage_progress(25, 100, 50, 100) == 0.4
    assert _relative_coverage_progress(50, 100, 50, 100) == 0.8
    assert _relative_coverage_progress(75, 100, 50, 100) == 0.9
    assert _relative_coverage_progress(100, 100, 50, 100) == 1.0


def test_relative_coverage_progress_penalizes_narrow_high_percentage_coverage() -> None:
    assert _relative_coverage_progress(90, 100, 900, 10_000) == pytest.approx(0.08)

    metrics = _relative_coverage_metrics(90, 100, 900, 10_000)
    assert metrics["candidate_ratio"] == 0.9
    assert metrics["candidate_oracle_ratio"] == 0.009
    assert metrics["candidate_to_oracle_covered_ratio"] == 0.1
    assert metrics["oracle_denominator"] == 10_000


def test_relative_coverage_progress_matches_libsass_wrong_target_regression() -> None:
    assert _relative_coverage_progress(478, 537, 4765, 20321) == pytest.approx(
        0.080252, abs=1e-6
    )
    assert _relative_coverage_progress(13, 17, 647, 2231) == pytest.approx(
        0.016074, abs=1e-6
    )
    assert _relative_coverage_progress(522, 644, 3251, 15607) == pytest.approx(
        0.128453, abs=1e-6
    )


def test_relative_coverage_progress_handles_missing_oracle_coverage() -> None:
    assert _relative_coverage_progress(0, 100, 0, 0) == 0.0
    assert _relative_coverage_progress(25, 100, 0, 0) == 0.25
    assert _relative_coverage_progress(100, 100, 0, 0) == 1.0


def test_dynamic_default_weights_use_continuous_schedule() -> None:
    initial = default_reward_config(training_progress=0.0)
    mature = default_reward_config(training_progress=1.0)
    midpoint = default_reward_config(successful_dynamic_training_episodes=5, anneal_episodes=10)

    assert sum(initial.group_weights.values()) == pytest.approx(1.0)
    assert sum(mature.group_weights.values()) == pytest.approx(1.0)
    assert sum(midpoint.group_weights.values()) == pytest.approx(1.0)
    assert initial.group_weights["coverage_behavior"] == pytest.approx(0.25)
    assert mature.group_weights["coverage_behavior"] == pytest.approx(0.50)
    assert midpoint.group_weights["coverage_behavior"] == pytest.approx(0.375)
    assert mature.schema_version == "reward_config.v3"
    assert mature.microcomponent_weights["coverage_available"] == 0.0
    assert mature.microcomponent_weights["line_coverage_vs_oracle"] == 1.0
    assert mature.microcomponent_weights["task_end"] == 0.0
