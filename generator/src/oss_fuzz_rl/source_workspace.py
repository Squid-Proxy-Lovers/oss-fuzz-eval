"""Materialize upstream source workspaces from OSS-Fuzz Dockerfiles."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from oss_fuzz_rl.sanitizer import FUZZ_ARTIFACT_RE, scrub_fuzz_artifacts

WORKDIR_RE = re.compile(r"^\s*WORKDIR\s+(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class SourceCommand:
    """A source checkout command parsed from an OSS-Fuzz Dockerfile."""

    kind: str
    url: str
    dest: str
    args: tuple[str, ...] = ()

    @property
    def dest_name(self) -> str:
        dest = self.dest.rstrip("/")
        if "/" in dest:
            return dest.rsplit("/", 1)[-1]
        return dest

    @property
    def is_fuzzer_artifact(self) -> bool:
        haystack = f"{self.url} {self.dest}"
        return bool(FUZZ_ARTIFACT_RE.search(haystack))


def parse_source_commands(dockerfile: Path) -> list[SourceCommand]:
    """Parse git/svn source checkout commands from a Dockerfile."""

    if not dockerfile.is_file():
        return []
    content = dockerfile.read_text(encoding="utf-8", errors="ignore")
    commands: list[SourceCommand] = []
    for logical_line in _dockerfile_logical_lines(content):
        if not logical_line.lstrip().startswith("RUN "):
            continue
        run_body = logical_line.lstrip()[4:]
        commands.extend(_parse_git_clones(run_body))
        commands.extend(_parse_svn_checkouts(run_body))
    return commands


def parse_workdir(dockerfile: Path) -> str | None:
    if not dockerfile.is_file():
        return None
    content = dockerfile.read_text(encoding="utf-8", errors="ignore")
    matches = WORKDIR_RE.findall(content)
    if not matches:
        return None
    return _normalize_dest(matches[-1])


def select_primary_source_command(dockerfile: Path) -> SourceCommand | None:
    """Pick the project source checkout, ignoring known fuzzer-only repos."""

    commands = [
        command for command in parse_source_commands(dockerfile) if not command.is_fuzzer_artifact
    ]
    if not commands:
        return None
    workdir = parse_workdir(dockerfile)
    if workdir:
        workdir_name = _normalize_dest(workdir).rstrip("/").rsplit("/", 1)[-1]
        for command in commands:
            if command.dest_name == workdir_name:
                return command
    return commands[0]


def materialize_source(
    command: SourceCommand,
    workspace_dir: Path,
    removed_artifacts: list[str] | None = None,
) -> Path:
    """Clone/checkout source into the public task workspace."""

    workspace_dir.mkdir(parents=True, exist_ok=True)
    destination = workspace_dir / command.dest_name
    if destination.exists():
        shutil.rmtree(destination)

    if command.kind == "git":
        clone_command = ["git", "clone", *command.args, command.url, str(destination)]
    elif command.kind == "svn":
        clone_command = ["svn", "checkout", command.url, str(destination)]
    else:
        raise ValueError(f"unsupported source command kind: {command.kind}")

    subprocess.run(clone_command, check=True, text=True, capture_output=True)
    removed = scrub_fuzz_artifacts(destination)
    if removed_artifacts is not None:
        removed_artifacts.extend(removed)
    return destination


def _dockerfile_logical_lines(content: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not current:
            current = line
        else:
            current += " " + line.lstrip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        lines.append(current)
        current = ""
    if current:
        lines.append(current)
    return lines


def _parse_git_clones(run_body: str) -> list[SourceCommand]:
    commands: list[SourceCommand] = []
    for segment in _split_shell_segments(run_body):
        if "git clone" not in segment:
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError:
            continue
        for index, token in enumerate(tokens):
            if token == "git" and index + 1 < len(tokens) and tokens[index + 1] == "clone":
                parsed = _source_from_git_tokens(tokens[index + 2 :])
                if parsed:
                    commands.append(parsed)
    return commands


def _parse_svn_checkouts(run_body: str) -> list[SourceCommand]:
    commands: list[SourceCommand] = []
    for segment in _split_shell_segments(run_body):
        if "svn checkout" not in segment and "svn co" not in segment:
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError:
            continue
        for index, token in enumerate(tokens):
            if (
                token == "svn"
                and index + 1 < len(tokens)
                and tokens[index + 1]
                in {
                    "checkout",
                    "co",
                }
            ):
                parsed = _source_from_svn_tokens(tokens[index + 2 :])
                if parsed:
                    commands.append(parsed)
    return commands


def _split_shell_segments(run_body: str) -> list[str]:
    return [segment.strip() for segment in re.split(r"\s*(?:&&|;)\s*", run_body) if segment.strip()]


def _source_from_git_tokens(tokens: list[str]) -> SourceCommand | None:
    passthrough_args: list[str] = []
    index = 0
    url: str | None = None
    dest: str | None = None
    options_with_values = {"--branch", "-b", "--depth", "--reference", "--origin", "-o"}
    passthrough_flags = {"--recurse-submodules", "--shallow-submodules", "--single-branch"}

    while index < len(tokens):
        token = tokens[index]
        if token in options_with_values and index + 1 < len(tokens):
            if token in {"--branch", "-b", "--recurse-submodules", "--shallow-submodules"}:
                passthrough_args.extend([token, tokens[index + 1]])
            index += 2
            continue
        if token in passthrough_flags:
            passthrough_args.append(token)
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if url is None:
            url = token
        elif dest is None:
            dest = token
            break
        index += 1

    if url is None:
        return None
    return SourceCommand(
        kind="git",
        url=url,
        dest=_normalize_dest(dest or _repo_name_from_url(url)),
        args=tuple(passthrough_args or ["--depth", "1"]),
    )


def _source_from_svn_tokens(tokens: list[str]) -> SourceCommand | None:
    positional = [token for token in tokens if not token.startswith("-")]
    if not positional:
        return None
    url = positional[0]
    dest = positional[1] if len(positional) > 1 else _repo_name_from_url(url)
    return SourceCommand(kind="svn", url=url, dest=_normalize_dest(dest))


def _repo_name_from_url(url: str) -> str:
    cleaned = url.rstrip("/").removesuffix(".git")
    if ":" in cleaned and "/" not in cleaned.rsplit(":", 1)[-1]:
        return cleaned.rsplit(":", 1)[-1]
    return cleaned.rsplit("/", 1)[-1]


def _normalize_dest(dest: str) -> str:
    dest = dest.strip().strip('"').strip("'")
    dest = dest.replace("$SRC/", "").replace("${SRC}/", "")
    if dest in {"$SRC", "${SRC}", "."}:
        return "source"
    return dest.lstrip("./")
