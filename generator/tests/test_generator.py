from __future__ import annotations

import json
import subprocess
from pathlib import Path

from oss_fuzz_rl.episode import EpisodeTrace
from oss_fuzz_rl.project_index import index_projects
from oss_fuzz_rl.reward import score_task
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
    assert REDACTION_MARKER in cmake

    records = {record.path: record for record in report.records}
    assert records[".github/workflows/ci.yml"].reason == "ci-fuzz-guidance-content"
    assert records["src/hidden.cc"].reason == "harness-entrypoint-content"
    assert records["README.md"].action == "redact"


def test_static_score_oracle_replay_is_positive(tmp_path: Path) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    task = generate_tasks(oss_fuzz, tmp_path / "tasks", project_name="demo", limit=1)[0]
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
    report = score_task(task, candidate_project_dir=candidate)
    assert report.scalar_reward > 0.5
    assert report.build_passed


def test_static_score_ignores_visible_baseline_harnesses(tmp_path: Path) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    task = generate_tasks(oss_fuzz, tmp_path / "tasks", project_name="demo", limit=1)[0]
    report = score_task(task)
    assert report.scalar_reward <= 0.10
    assert not report.build_passed


def test_missing_task_end_hard_zero(tmp_path: Path) -> None:
    oss_fuzz = make_fake_oss_fuzz(tmp_path)
    task = generate_tasks(oss_fuzz, tmp_path / "tasks", project_name="demo", limit=1)[0]
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_text(json.dumps({"tool": "write", "input": {"filePath": "x"}}) + "\n")
    report = score_task(task, trace=EpisodeTrace.from_jsonl(trace_path), require_task_end=True)
    assert report.scalar_reward == 0.0
    assert report.hard_zero
