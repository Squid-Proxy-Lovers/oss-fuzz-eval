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
        if not _is_line_redaction_candidate(path):
            continue
        match = _guidance_text_match(path)
        if match is None:
            continue
        content, matches = match
        redacted = _redact_lines(content, matches, path)
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
                lines=tuple(sorted(matches.keys())),
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
    content = _read_small_bytes(path)
    if content is None:
        return None
    for name, pattern in FUZZ_HARNESS_CONTENT_PATTERNS:
        if pattern.search(content):
            return name
    return None


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
    return content, _expand_redaction_lines(content, matches, path)


def _expand_redaction_lines(
    content: str,
    matches: dict[int, str],
    path: Path,
) -> dict[int, str]:
    expanded = dict(matches)
    lines = content.splitlines()
    if _is_cmake_file(path):
        _expand_cmake_blocks(lines, expanded)
    for line_no, name in tuple(matches.items()):
        index = line_no - 1
        if _line_opens_block(lines[index]):
            depth = _paren_delta(lines[index])
            for next_index in range(index + 1, len(lines)):
                expanded.setdefault(next_index + 1, name)
                depth += _paren_delta(lines[next_index])
                if depth <= 0:
                    break
    return expanded


def _expand_cmake_blocks(lines: list[str], expanded: dict[int, str]) -> None:
    for line_no, name in tuple(expanded.items()):
        index = line_no - 1
        stripped = lines[index].strip().lower()
        if stripped.startswith("if("):
            depth = 0
            for next_index in range(index, len(lines)):
                next_stripped = lines[next_index].strip().lower()
                if next_stripped.startswith("if("):
                    depth += 1
                expanded.setdefault(next_index + 1, name)
                if next_stripped.startswith("endif"):
                    depth -= 1
                    if depth <= 0:
                        break


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
    return _is_doc_file(path) or _is_cmake_file(path)


def _is_doc_file(path: Path) -> bool:
    return path.suffix.lower() in DOC_REDACTION_EXTENSIONS or path.name in DOC_REDACTION_NAMES


def _is_cmake_file(path: Path) -> bool:
    return path.suffix.lower() in CMAKE_REDACTION_EXTENSIONS or path.name in CMAKE_REDACTION_NAMES


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


def _line_opens_block(line: str) -> bool:
    stripped = line.strip()
    return stripped.endswith("\\") or _paren_delta(line) > 0


def _paren_delta(line: str) -> int:
    return line.count("(") - line.count(")")
