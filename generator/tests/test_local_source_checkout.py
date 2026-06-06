from __future__ import annotations

from pathlib import Path

from oss_fuzz_rl.models import ProjectInfo
from oss_fuzz_rl.oss_fuzz_runner import (
    LOCAL_SOURCE_CONTEXT_DIR,
    _materialize_minimal_checkout,
    inject_local_source_checkout,
)
from oss_fuzz_rl.source_workspace import (
    local_source_context_name,
    parse_source_commands,
    rewrite_source_checkout_to_local_copy,
    select_primary_source_command,
)
from oss_fuzz_rl.task_generator import _prompt_for_project


def test_rewrite_source_checkout_to_local_copy_replaces_single_run(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "\n".join(
            [
                "FROM gcr.io/oss-fuzz-base/base-builder",
                "RUN git clone --depth 1 https://example.com/demo.git demo",
                "WORKDIR demo",
                "",
            ]
        ),
        encoding="utf-8",
    )
    command = select_primary_source_command(dockerfile)
    assert command is not None

    rewritten = rewrite_source_checkout_to_local_copy(dockerfile, command)

    content = dockerfile.read_text(encoding="utf-8")
    assert rewritten
    assert "https://example.com/demo.git" not in content
    assert f"COPY {LOCAL_SOURCE_CONTEXT_DIR}/demo/ $SRC/demo/" in content
    assert "WORKDIR demo" in content


def test_rewrite_source_checkout_preserves_surrounding_run_segments(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "\n".join(
            [
                "FROM gcr.io/oss-fuzz-base/base-builder",
                (
                    "RUN apt-get update && "
                    "git clone --depth 1 https://example.com/demo.git demo && "
                    "cd demo && ./bootstrap"
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    command = select_primary_source_command(dockerfile)
    assert command is not None

    rewritten = rewrite_source_checkout_to_local_copy(dockerfile, command)

    content = dockerfile.read_text(encoding="utf-8")
    assert rewritten
    assert "RUN apt-get update" in content
    assert f"COPY {LOCAL_SOURCE_CONTEXT_DIR}/demo/ $SRC/demo/" in content
    assert "RUN cd demo && ./bootstrap" in content
    assert "https://example.com/demo.git" not in content


def test_rewrite_source_checkout_replaces_duplicate_source_url_destinations(
    tmp_path: Path,
) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "\n".join(
            [
                "FROM gcr.io/oss-fuzz-base/base-builder-go",
                "RUN git clone https://example.com/demo.git demo",
                "RUN git clone --depth 1 https://example.com/demo.git $GOPATH/src/example/demo",
                "WORKDIR $SRC",
                "",
            ]
        ),
        encoding="utf-8",
    )
    command = select_primary_source_command(dockerfile)
    assert command is not None

    rewritten = rewrite_source_checkout_to_local_copy(dockerfile, command)

    content = dockerfile.read_text(encoding="utf-8")
    assert rewritten
    assert "https://example.com/demo.git" not in content
    assert f"COPY {LOCAL_SOURCE_CONTEXT_DIR}/demo/ $SRC/demo/" in content
    assert f"COPY {LOCAL_SOURCE_CONTEXT_DIR}/demo/ $GOPATH/src/example/demo/" in content


def test_parse_git_clone_skips_jobs_option_value(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM base\n"
        "RUN git clone --depth 1 --jobs $(nproc) https://example.com/corpus corpus_dir\n",
        encoding="utf-8",
    )

    commands = parse_source_commands(dockerfile)

    assert len(commands) == 1
    assert commands[0].url == "https://example.com/corpus"
    assert commands[0].dest == "corpus_dir"


def test_rewrite_source_checkout_uses_safe_context_name_for_variable_dest(
    tmp_path: Path,
) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "\n".join(
            [
                "FROM gcr.io/oss-fuzz-base/base-builder",
                "ENV LIBRARY_NAME=demo",
                "RUN git clone --depth 1 https://example.com/demo.git ${LIBRARY_NAME}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    command = select_primary_source_command(dockerfile)
    assert command is not None

    rewritten = rewrite_source_checkout_to_local_copy(dockerfile, command)

    content = dockerfile.read_text(encoding="utf-8")
    assert rewritten
    assert local_source_context_name(command) == "source"
    assert f"COPY {LOCAL_SOURCE_CONTEXT_DIR}/source/ $SRC/${{LIBRARY_NAME}}/" in content
    assert f"{LOCAL_SOURCE_CONTEXT_DIR}/${{LIBRARY_NAME}}" not in content


def test_inject_local_source_checkout_copies_source_and_rewrites_dockerfile(tmp_path: Path) -> None:
    project = tmp_path / "project"
    workspace = tmp_path / "workspace"
    project.mkdir()
    (workspace / "demo" / "src").mkdir(parents=True)
    (workspace / "demo" / "src" / "parser.c").write_text("int parse(void) { return 0; }\n")
    (project / "Dockerfile").write_text(
        "\n".join(
            [
                "FROM gcr.io/oss-fuzz-base/base-builder",
                "RUN git clone --depth 1 https://example.com/demo.git demo",
                "WORKDIR demo",
                "",
            ]
        ),
        encoding="utf-8",
    )

    injected = inject_local_source_checkout(project, workspace)

    assert injected
    assert (
        project / LOCAL_SOURCE_CONTEXT_DIR / "demo" / "src" / "parser.c"
    ).read_text() == "int parse(void) { return 0; }\n"
    dockerfile = (project / "Dockerfile").read_text(encoding="utf-8")
    assert "https://example.com/demo.git" not in dockerfile
    assert f"COPY {LOCAL_SOURCE_CONTEXT_DIR}/demo/ $SRC/demo/" in dockerfile


def test_materialize_minimal_checkout_injects_local_source(tmp_path: Path) -> None:
    oss_fuzz = tmp_path / "oss-fuzz"
    candidate_project = tmp_path / "workspace" / "oss-fuzz-project"
    source_workspace = tmp_path / "workspace"
    eval_root = tmp_path / "eval" / "oss-fuzz"
    (oss_fuzz / "infra").mkdir(parents=True)
    candidate_project.mkdir(parents=True)
    (source_workspace / "demo").mkdir()
    (source_workspace / "demo" / "README.md").write_text("local source\n")
    (candidate_project / "Dockerfile").write_text(
        "\n".join(
            [
                "FROM gcr.io/oss-fuzz-base/base-builder",
                "RUN git clone --depth 1 https://example.com/demo.git demo",
                "WORKDIR demo",
                "",
            ]
        ),
        encoding="utf-8",
    )

    _materialize_minimal_checkout(
        oss_fuzz,
        eval_root,
        "demo",
        candidate_project,
        source_workspace_dir=source_workspace,
    )

    eval_project = eval_root / "projects" / "demo"
    assert (eval_project / LOCAL_SOURCE_CONTEXT_DIR / "demo" / "README.md").is_file()
    dockerfile = (eval_project / "Dockerfile").read_text(encoding="utf-8")
    assert "https://example.com/demo.git" not in dockerfile
    assert f"COPY {LOCAL_SOURCE_CONTEXT_DIR}/demo/ $SRC/demo/" in dockerfile


def test_generated_prompt_explains_editable_integration_and_local_source(
) -> None:
    project = ProjectInfo(name="demo", language="c++", rel_path="projects/demo")

    prompt = _prompt_for_project(project)
    assert "`oss-fuzz-project/` is editable" in prompt
    assert "Do not rewrite Dockerfile source checkout plumbing" in prompt
    assert "Do not read, depend on, or modify hidden oracle files." in prompt
