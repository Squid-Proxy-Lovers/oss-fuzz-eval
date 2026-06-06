"""Sanitize upstream source trees before exposing them as RL task workspaces."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

FUZZ_ARTIFACT_RE = re.compile(
    r"(?:^|[-_.])(?:fuzz|fuzzer|fuzzers|fuzzing|oss-fuzz)(?:$|[-_.])|"
    r"(?:fuzz|fuzzer|fuzzers|fuzzing)(?:$|[-_.])|oss[-_]?fuzz",
    re.I,
)
VCS_ARTIFACT_NAMES = {".git", ".gitmodules"}
MAX_CONTENT_SCAN_BYTES = 2 * 1024 * 1024

SOURCE_SCAN_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".go",
    ".h",
    ".hh",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".lua",
    ".mjs",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".swift",
    ".ts",
    ".tsx",
}
TEXT_SCAN_EXTENSIONS = SOURCE_SCAN_EXTENSIONS | {
    ".bazel",
    ".bzl",
    ".cmake",
    ".conf",
    ".cfg",
    ".gradle",
    ".gni",
    ".gn",
    ".ini",
    ".in",
    ".m4",
    ".md",
    ".mk",
    ".properties",
    ".rst",
    ".sh",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
TEXT_SCAN_NAMES = {
    ".bazelrc",
    ".cirrus.yml",
    ".github",
    ".gitlab-ci.yml",
    ".travis.yml",
    "BUILD",
    "BUILD.bazel",
    "Cargo.toml",
    "CMakeLists.txt",
    "Dockerfile",
    "Gemfile",
    "Makefile",
    "Rakefile",
    "README",
    "WORKSPACE",
    "WORKSPACE.bazel",
    "meson.build",
    "package.json",
    "pyproject.toml",
}
DOC_REDACTION_EXTENSIONS = {".md", ".rst", ".txt"}
DOC_REDACTION_NAMES = {
    "CHANGELOG",
    "CONTRIBUTING",
    "NEWS",
    "README",
    "THANKS",
}
CMAKE_REDACTION_EXTENSIONS = {".cmake"}
CMAKE_REDACTION_NAMES = {"CMakeLists.txt"}
MESON_REDACTION_NAMES = {"meson.build", "meson_options.txt"}
CMAKE_COMMAND_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
GO_FUZZ_FUNCTION_RE = re.compile(r"(?m)^func\s+Fuzz[A-Za-z0-9_]*\s*\(")
GO_IMPORT_RE = re.compile(r'\s*(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*|[_.])\s+)?\"(?P<path>[^\"]+)\"')

FUZZ_HARNESS_CONTENT_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("LLVMFuzzerTestOneInput", re.compile(rb"\bLLVMFuzzerTestOneInput\s*\(")),
    ("rust-fuzz-target", re.compile(rb"\bfuzz_target!\s*(?:\(|\{)")),
    ("atheris-setup", re.compile(rb"\batheris\.Setup\s*\(")),
    ("atheris-fuzz", re.compile(rb"\batheris\.Fuzz\s*\(")),
    ("jazzer-entrypoint", re.compile(rb"\bfuzzerTestOneInput\s*\(")),
    ("junit-fuzztest", re.compile(rb"@FuzzTest\b")),
    ("javascript-fuzz-export", re.compile(rb"\bmodule\.exports\.fuzz\b")),
    ("javascript-fuzz-function", re.compile(rb"\bexport\s+function\s+fuzz\s*\(")),
    ("go-fuzz-test", re.compile(rb"\bfunc\s+Fuzz[A-Za-z0-9_]*\s*\([^)]*\*testing\.F")),
    ("ruzzy", re.compile(rb"\bRuzzy\.fuzz\b")),
    ("luzer", re.compile(rb"\bluzer\.Fuzz\s*\(")),
)

FUZZ_GUIDANCE_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("oss-fuzz", re.compile(r"\boss[-_ ]?fuzz\b", re.I)),
    ("clusterfuzz", re.compile(r"\bclusterfuzz\b", re.I)),
    ("libfuzzer", re.compile(r"\blib[-_ ]?fuzzer\b", re.I)),
    ("llvm-fuzzer-entrypoint", re.compile(r"\bLLVMFuzzer(?:TestOneInput|Initialize)\b")),
    ("lib-fuzzing-engine", re.compile(r"\bLIB_FUZZING_ENGINE\b")),
    ("fuzzed-data-provider", re.compile(r"\bFuzzedDataProvider\b")),
    ("unsafe-fuzzing-mode", re.compile(r"\bFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION\b")),
    ("atheris", re.compile(r"\batheris\b", re.I)),
    ("jazzer", re.compile(r"\b(?:jazzer|code_intelligence\.jazzer)\b", re.I)),
    ("cargo-fuzz", re.compile(r"\bcargo[-_ ]fuzz\b|\bcargo\s+fuzz\b", re.I)),
    ("go-test-fuzz", re.compile(r"\bgo\s+test\b[^\n]*\s-fuzz(?:=|\b)", re.I)),
    ("rust-fuzz-target", re.compile(r"\bfuzz_target!\b")),
    ("fuzz-path-token", re.compile(r"(?:^|[/\\])fuzz(?:[/\\)\"']|$)", re.I)),
    ("uppercase-fuzz-token", re.compile(r"\b[A-Z0-9_]*FUZZ[A-Z0-9_]*\b")),
    ("honggfuzz", re.compile(r"\bhonggfuzz\b", re.I)),
    ("afl", re.compile(r"\b(?:AFL\+\+|afl-fuzz)\b", re.I)),
    ("fuzzer-sanitizer", re.compile(r"(?:^|\s)-fsanitize=fuzzer(?:-no-link)?(?:\s|$)", re.I)),
    (
        "fuzzing-tooling",
        re.compile(
            r"\b(?:fuzzer|fuzzers|fuzzing)\s+"
            r"(?:guide|target|targets|harness|harnesses|corpus|corpora|"
            r"regression|reproducer|crash|crashes)\b",
            re.I,
        ),
    ),
    ("fuzz-target-name", re.compile(r"\b[A-Za-z0-9./_-]+(?:_fuzzer|_fuzz_target)\b", re.I)),
)

REDACTION_MARKER = "[removed benchmark-only content]"


@dataclass(frozen=True)
class SanitizerRecord:
    """A single deletion or redaction performed by the source sanitizer."""

    path: str
    action: str
    category: str
    reason: str
    pattern: str | None = None
    lines: tuple[int, ...] = ()

    def to_json(self) -> dict:
        data: dict[str, object] = {
            "path": self.path,
            "action": self.action,
            "category": self.category,
            "reason": self.reason,
        }
        if self.pattern:
            data["pattern"] = self.pattern
        if self.lines:
            data["lines"] = list(self.lines)
        return data


@dataclass(frozen=True)
class SanitizerReport:
    """Structured source sanitizer result."""

    records: tuple[SanitizerRecord, ...]

    @property
    def changed_paths(self) -> list[str]:
        return [record.path for record in self.records]

    def counts_by_action(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.records:
            counts[record.action] = counts.get(record.action, 0) + 1
        return counts

    def counts_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.records:
            counts[record.category] = counts.get(record.category, 0) + 1
        return counts

    def to_json(self) -> dict:
        return {
            "records": [record.to_json() for record in self.records],
            "counts_by_action": self.counts_by_action(),
            "counts_by_category": self.counts_by_category(),
        }


def scrub_fuzz_artifacts(root: Path) -> list[str]:
    """Backward-compatible wrapper returning changed relative paths."""

    return sanitize_source_tree(root).changed_paths


def sanitize_source_tree(root: Path) -> SanitizerReport:
    """Remove or redact fuzzer-specific prior work from an upstream checkout."""

    records: list[SanitizerRecord] = []
    deleted = _delete_artifacts(root, records)
    _redact_remaining_guidance(root, deleted, records)
    return SanitizerReport(tuple(records))


def _delete_artifacts(root: Path, records: list[SanitizerRecord]) -> set[Path]:
    deleted: set[Path] = set()
    for path in sorted(root.rglob("*"), key=lambda p: (len(p.parts), p.as_posix())):
        if _has_deleted_ancestor(path, deleted):
            continue
        match = _deletion_match(path)
        if match is None:
            continue
        category, reason, pattern = match
        records.append(
            SanitizerRecord(
                path=path.relative_to(root).as_posix(),
                action="delete",
                category=category,
                reason=reason,
                pattern=pattern,
            )
        )
        deleted.add(path)

    for path in sorted(deleted, key=lambda p: len(p.parts), reverse=True):
        if not path.exists():
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    return deleted


def _redact_remaining_guidance(
    root: Path,
    deleted: set[Path],
    records: list[SanitizerRecord],
) -> None:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _has_deleted_ancestor(path, deleted):
            continue
        if path.suffix.lower() == ".go":
            rewrite = _remove_go_fuzz_functions(path)
            if rewrite is not None:
                pattern, lines = rewrite
                records.append(
                    SanitizerRecord(
                        path=path.relative_to(root).as_posix(),
                        action="redact",
                        category="content",
                        reason="harness-entrypoint-content",
                        pattern=pattern,
                        lines=tuple(lines),
                    )
                )
            continue
        if not _is_line_redaction_candidate(path):
            continue
        match = _guidance_text_match(path)
        if match is None:
            continue
        content, matches = match
        if _is_cmake_file(path):
            redacted, lines = _remove_cmake_guidance(content, matches)
        elif _is_meson_file(path):
            redacted, lines = _remove_meson_guidance(content, matches)
        else:
            redacted = _redact_lines(content, matches, path)
            lines = set(matches)
        if redacted == content:
            continue
        path.write_text(redacted, encoding="utf-8")
        records.append(
            SanitizerRecord(
                path=path.relative_to(root).as_posix(),
                action="redact",
                category="content",
                reason="fuzz-guidance-content",
                pattern=",".join(sorted(set(matches.values()))),
                lines=tuple(sorted(lines)),
            )
        )


def _deletion_match(path: Path) -> tuple[str, str, str | None] | None:
    if _is_vcs_artifact_name(path.name):
        return ("vcs", "vcs-artifact-name", path.name)
    if _is_fuzz_artifact_name(path.name):
        return ("name", "fuzz-artifact-name", None)
    if path.is_file():
        harness_pattern = _harness_content_pattern(path)
        if harness_pattern:
            return ("content", "harness-entrypoint-content", harness_pattern)
        if _is_ci_workflow(path):
            guidance = _guidance_text_match(path)
            if guidance is not None:
                _, matches = guidance
                return ("content", "ci-fuzz-guidance-content", ",".join(set(matches.values())))
    return None


def _harness_content_pattern(path: Path) -> str | None:
    if path.suffix.lower() not in SOURCE_SCAN_EXTENSIONS:
        return None
    if path.suffix.lower() == ".go":
        return _go_fuzz_file_delete_pattern(path)
    content = _read_small_bytes(path)
    if content is None:
        return None
    for name, pattern in FUZZ_HARNESS_CONTENT_PATTERNS:
        if pattern.search(content):
            return name
    return None


def _go_fuzz_file_delete_pattern(path: Path) -> str | None:
    content = _read_small_text(path)
    if content is None:
        return None
    spans = _go_fuzz_function_spans(content)
    if not spans or not _go_file_is_fuzz_only(content, spans):
        return None
    return "go-fuzz-test"


def _guidance_text_match(path: Path) -> tuple[str, dict[int, str]] | None:
    if not _is_text_scan_candidate(path):
        return None
    content = _read_small_text(path)
    if content is None:
        return None
    matches: dict[int, str] = {}
    for line_no, line in enumerate(content.splitlines(), start=1):
        for name, pattern in FUZZ_GUIDANCE_TEXT_PATTERNS:
            if pattern.search(line):
                matches[line_no] = name
                break
    if not matches:
        return None
    return content, matches


def _remove_cmake_guidance(content: str, matches: dict[int, str]) -> tuple[str, set[int]]:
    lines = content.splitlines()
    delete_indexes: set[int] = set()
    fuzz_targets: set[str] = set()

    for line_no in sorted(matches):
        command = _cmake_command_at(lines, line_no - 1)
        if command is None:
            delete_indexes.add(line_no - 1)
            continue
        start, end, name, text = command
        if name == "if":
            if _cmake_condition_is_fuzz_only(text):
                delete_indexes.update(_cmake_fuzz_if_delete_indexes(lines, start))
            continue
        if name in {"elseif", "else", "endif"}:
            continue
        delete_indexes.update(range(start, end + 1))
        if name in {"add_executable", "add_library"}:
            target = _cmake_first_arg(text)
            if target:
                fuzz_targets.add(target)

    if fuzz_targets:
        for index, _line in enumerate(lines):
            command = _cmake_command_at(lines, index)
            if command is None:
                continue
            start, end, name, text = command
            if start != index:
                continue
            if _cmake_command_references_fuzz_target(name, text, fuzz_targets):
                delete_indexes.update(range(start, end + 1))

    return _remove_line_indexes(content, delete_indexes), {index + 1 for index in delete_indexes}


def _remove_meson_guidance(content: str, matches: dict[int, str]) -> tuple[str, set[int]]:
    lines = content.splitlines()
    delete_indexes: set[int] = set()
    for line_no in sorted(matches):
        start, end = _build_command_span(lines, line_no - 1)
        delete_indexes.update(range(start, end + 1))
    return _remove_line_indexes(content, delete_indexes), {index + 1 for index in delete_indexes}


def _remove_go_fuzz_functions(path: Path) -> tuple[str, list[int]] | None:
    content = _read_small_text(path)
    if content is None:
        return None
    spans = _go_fuzz_function_spans(content)
    if not spans:
        return None
    rewritten, lines = _remove_go_spans(content, spans)
    if rewritten == content:
        return None
    path.write_text(rewritten, encoding="utf-8")
    return "go-fuzz-test", lines


def _remove_go_spans(content: str, spans: list[tuple[int, int]]) -> tuple[str, list[int]]:
    removed = "\n".join(content[start:end] for start, end in spans)
    rewritten = content
    for start, end in sorted(spans, reverse=True):
        rewritten = rewritten[:start] + rewritten[end:]
    rewritten = _remove_unused_go_imports(rewritten, removed)
    return rewritten, _line_numbers_for_spans(content, spans)


def _go_fuzz_function_spans(content: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in GO_FUZZ_FUNCTION_RE.finditer(content):
        open_brace = content.find("{", match.end())
        if open_brace == -1:
            continue
        signature = content[match.start() : open_brace]
        if not re.search(r"\*\s*testing\.F\b", signature):
            continue
        close_brace = _find_matching_go_brace(content, open_brace)
        if close_brace is None:
            continue
        end = close_brace + 1
        if end < len(content) and content[end] == "\n":
            end += 1
        spans.append((match.start(), end))
    return spans


def _find_matching_go_brace(content: str, open_brace: int) -> int | None:
    depth = 0
    index = open_brace
    state = "normal"
    escaped = False
    while index < len(content):
        char = content[index]
        next_char = content[index + 1] if index + 1 < len(content) else ""
        if state == "line-comment":
            if char == "\n":
                state = "normal"
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                state = "normal"
                index += 1
        elif state == "string":
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                state = "normal"
        elif state == "raw-string":
            if char == "`":
                state = "normal"
        elif state == "rune":
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "'":
                state = "normal"
        elif char == "/" and next_char == "/":
            state = "line-comment"
            index += 1
        elif char == "/" and next_char == "*":
            state = "block-comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "`":
            state = "raw-string"
        elif char == "'":
            state = "rune"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _go_file_is_fuzz_only(content: str, spans: list[tuple[int, int]]) -> bool:
    remaining = content
    for start, end in sorted(spans, reverse=True):
        remaining = remaining[:start] + remaining[end:]
    remaining = _remove_go_import_declarations(remaining)
    for line in remaining.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped == "*/"
        ):
            continue
        if stripped.startswith("package "):
            continue
        return False
    return True


def _remove_unused_go_imports(content: str, removed: str) -> str:
    lines = content.splitlines()
    if not lines:
        return content
    code_without_imports = _remove_go_import_declarations(content)
    new_lines: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.strip() == "import (":
            end = _go_import_block_end(lines, index)
            if end is None:
                new_lines.append(line)
                index += 1
                continue
            specs = lines[index + 1 : end]
            kept = [
                spec
                for spec in specs
                if not _go_import_spec_removed(spec, code_without_imports, removed)
            ]
            if any(GO_IMPORT_RE.match(spec) for spec in kept):
                new_lines.append(line)
                new_lines.extend(kept)
                new_lines.append(lines[end])
            index = end + 1
            continue
        if line.lstrip().startswith("import "):
            spec = line.split("import ", 1)[1]
            if _go_import_spec_removed(spec, code_without_imports, removed):
                index += 1
                continue
        new_lines.append(line)
        index += 1
    result = "\n".join(new_lines)
    if content.endswith("\n"):
        result += "\n"
    return result


def _remove_go_import_declarations(content: str) -> str:
    lines = content.splitlines()
    kept: list[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped == "import (":
            end = _go_import_block_end(lines, index)
            if end is None:
                kept.append(lines[index])
                index += 1
            else:
                index = end + 1
            continue
        if stripped.startswith("import "):
            index += 1
            continue
        kept.append(lines[index])
        index += 1
    return "\n".join(kept)


def _go_import_block_end(lines: list[str], start: int) -> int | None:
    for index in range(start + 1, len(lines)):
        if lines[index].strip() == ")":
            return index
    return None


def _go_import_spec_removed(spec: str, remaining: str, removed: str) -> bool:
    match = GO_IMPORT_RE.match(spec)
    if match is None:
        return False
    name = match.group("alias") or _go_import_default_name(match.group("path"))
    if name in {"_", "."}:
        return False
    return _word_in(name, removed) and not _word_in(name, remaining)


def _go_import_default_name(import_path: str) -> str:
    name = import_path.rsplit("/", 1)[-1].split(".", 1)[0]
    return name.replace("-", "_")


def _line_numbers_for_spans(content: str, spans: list[tuple[int, int]]) -> list[int]:
    line_numbers: set[int] = set()
    for start, end in spans:
        first = content.count("\n", 0, start) + 1
        last = content.count("\n", 0, max(start, end - 1)) + 1
        line_numbers.update(range(first, last + 1))
    return sorted(line_numbers)


def _word_in(word: str, content: str) -> bool:
    return re.search(rf"\b{re.escape(word)}\b", content) is not None


def _cmake_command_at(
    lines: list[str],
    index: int,
) -> tuple[int, int, str, str] | None:
    start, end = _build_command_span(lines, index)
    match = CMAKE_COMMAND_RE.match(lines[start])
    if match is None:
        return None
    name = match.group(1).lower()
    return start, end, name, "\n".join(lines[start : end + 1])


def _build_command_span(lines: list[str], index: int) -> tuple[int, int]:
    start = index
    for candidate in range(index, -1, -1):
        if CMAKE_COMMAND_RE.match(lines[candidate]):
            possible_end = _paren_command_end(lines, candidate)
            if possible_end >= index:
                start = candidate
                break
    return start, _paren_command_end(lines, start)


def _paren_command_end(lines: list[str], start: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start, len(lines)):
        line = _strip_hash_comment(lines[index])
        if "(" in line:
            seen_open = True
        depth += _paren_delta(line)
        if seen_open and depth <= 0:
            return index
    return start


def _cmake_if_block_span(lines: list[str], start: int) -> tuple[int, int]:
    depth = 0
    for index in range(start, len(lines)):
        command = _cmake_command_at(lines, index)
        if command is None or command[0] != index:
            continue
        _start, end, name, _text = command
        if name == "if":
            depth += 1
        elif name == "endif":
            depth -= 1
            if depth <= 0:
                return start, end
    return start, _paren_command_end(lines, start)


def _cmake_fuzz_if_delete_indexes(lines: list[str], start: int) -> set[int]:
    depth = 0
    else_span: tuple[int, int] | None = None
    endif_span: tuple[int, int] | None = None
    for index in range(start, len(lines)):
        command = _cmake_command_at(lines, index)
        if command is None or command[0] != index:
            continue
        _start, end, name, _text = command
        if name == "if":
            depth += 1
        elif name == "else" and depth == 1 and else_span is None:
            else_span = (index, end)
        elif name == "endif":
            depth -= 1
            if depth <= 0:
                endif_span = (index, end)
                break
    if endif_span is None:
        block_start, block_end = _cmake_if_block_span(lines, start)
        return set(range(block_start, block_end + 1))
    if else_span is None:
        return set(range(start, endif_span[1] + 1))
    delete_indexes = set(range(start, else_span[1] + 1))
    delete_indexes.update(range(endif_span[0], endif_span[1] + 1))
    return delete_indexes


def _cmake_condition_is_fuzz_only(command_text: str) -> bool:
    identifiers = [
        token
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", command_text)
        if token.lower() not in {"if", "elseif", "and", "or", "not", "defined", "env", "on", "off"}
    ]
    return bool(identifiers) and all(_line_has_fuzz_guidance(token) for token in identifiers)


def _cmake_command_references_fuzz_target(
    name: str,
    command_text: str,
    fuzz_targets: set[str],
) -> bool:
    target_commands = {
        "add_dependencies",
        "set_target_properties",
        "target_compile_definitions",
        "target_compile_options",
        "target_include_directories",
        "target_link_libraries",
        "target_link_options",
        "target_sources",
    }
    if name in target_commands:
        first_arg = _cmake_first_arg(command_text)
        return first_arg in fuzz_targets
    if name in {"add_test", "set_tests_properties"}:
        return any(_word_in(target, command_text) for target in fuzz_targets)
    return False


def _cmake_first_arg(command_text: str) -> str | None:
    match = re.match(r"\s*[A-Za-z_][A-Za-z0-9_]*\s*\((.*)", command_text, re.S)
    if match is None:
        return None
    args = re.findall(r'"[^"]+"|\$\{[^}]+\}|[^\s()]+', match.group(1))
    if not args:
        return None
    return args[0].strip('"')


def _remove_line_indexes(content: str, indexes: set[int]) -> str:
    lines = content.splitlines()
    result = "\n".join(line for index, line in enumerate(lines) if index not in indexes)
    if content.endswith("\n"):
        result += "\n"
    return result


def _strip_hash_comment(line: str) -> str:
    in_quote = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
            continue
        if char == "#" and not in_quote:
            return line[:index]
    return line


def _redact_lines(content: str, line_numbers: set[int] | dict[int, str], path: Path) -> str:
    marker = _redaction_line(path)
    redacted: list[str] = []
    needs_trailing_newline = content.endswith("\n")
    for line_no, line in enumerate(content.splitlines(), start=1):
        if line_no in line_numbers:
            leading = line[: len(line) - len(line.lstrip())]
            redacted.append(f"{leading}{marker}")
        else:
            redacted.append(line)
    result = "\n".join(redacted)
    if needs_trailing_newline:
        result += "\n"
    return result


def _redaction_line(path: Path) -> str:
    suffix = path.suffix.lower()
    if _is_cmake_file(path) or _is_meson_file(path):
        return f"# {REDACTION_MARKER}"
    if suffix in {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hh",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".mjs",
        ".rs",
        ".scala",
        ".swift",
        ".ts",
        ".tsx",
    }:
        return f"// {REDACTION_MARKER}"
    if suffix in {".xml"}:
        return f"<!-- {REDACTION_MARKER} -->"
    if suffix in {".md", ".rst", ".txt"}:
        return REDACTION_MARKER
    return f"# {REDACTION_MARKER}"


def _is_text_scan_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SCAN_EXTENSIONS or path.name in TEXT_SCAN_NAMES


def _is_line_redaction_candidate(path: Path) -> bool:
    return _is_cmake_file(path) or _is_meson_file(path) or _is_doc_file(path)


def _is_doc_file(path: Path) -> bool:
    if _is_cmake_file(path) or _is_meson_file(path):
        return False
    return path.suffix.lower() in DOC_REDACTION_EXTENSIONS or path.name in DOC_REDACTION_NAMES


def _is_cmake_file(path: Path) -> bool:
    return path.suffix.lower() in CMAKE_REDACTION_EXTENSIONS or path.name in CMAKE_REDACTION_NAMES


def _is_meson_file(path: Path) -> bool:
    return path.name in MESON_REDACTION_NAMES


def _line_has_fuzz_guidance(line: str) -> bool:
    return any(pattern.search(line) for _name, pattern in FUZZ_GUIDANCE_TEXT_PATTERNS)


def _is_ci_workflow(path: Path) -> bool:
    parts = path.parts
    return ".github" in parts and "workflows" in parts and path.suffix.lower() in {
        ".yaml",
        ".yml",
    }


def _is_fuzz_artifact_name(name: str) -> bool:
    return bool(FUZZ_ARTIFACT_RE.search(name))


def _is_vcs_artifact_name(name: str) -> bool:
    return name in VCS_ARTIFACT_NAMES


def _has_deleted_ancestor(path: Path, deleted: set[Path]) -> bool:
    return any(parent in deleted for parent in path.parents)


def _read_small_bytes(path: Path) -> bytes | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    if stat.st_size > MAX_CONTENT_SCAN_BYTES:
        return None
    try:
        content = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in content[:4096]:
        return None
    return content


def _read_small_text(path: Path) -> str | None:
    content = _read_small_bytes(path)
    if content is None:
        return None
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return content.decode("utf-8", errors="ignore")


def _paren_delta(line: str) -> int:
    return line.count("(") - line.count(")")
