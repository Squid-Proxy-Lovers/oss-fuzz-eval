"""Language-specific harness discovery and static profiling."""

from __future__ import annotations

import ast
import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from oss_fuzz_rl.models import AstProfile, HarnessInfo

FUZZY_HARNESS_NAME = re.compile(r"(fuzz|fuzzer)", re.IGNORECASE)
WORD_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:.\->]*)\s*\(")
IMPORT_RE = re.compile(r"^\s*(?:#\s*)?(?:include|import|from|use|require)\b[^\n]*", re.MULTILINE)

INPUT_API_HINTS = (
    "FuzzedDataProvider",
    "Consume",
    "data",
    "bytes",
    "Buffer",
    "atheris",
    "fuzz_target",
    "f.Fuzz",
    "fuzzerTestOneInput",
    "LLVMFuzzerTestOneInput",
)
SETUP_HINTS = (
    "Initialize",
    "init",
    "open",
    "create",
    "new",
    "setup",
    "parse",
    "load",
    "decode",
)
CLEANUP_HINTS = (
    "free",
    "delete",
    "destroy",
    "close",
    "cleanup",
    "reset",
    "dispose",
    "defer",
)


@dataclass(frozen=True)
class LanguageAdapter:
    """Heuristic adapter for one OSS-Fuzz language family."""

    language: str
    extensions: tuple[str, ...]
    entrypoint_patterns: tuple[re.Pattern[str], ...]

    def is_harness_path(self, path: Path) -> bool:
        if path.suffix.lower() not in self.extensions:
            return False
        return bool(FUZZY_HARNESS_NAME.search(path.name)) or "fuzz_targets" in path.parts

    def detect_entrypoint(self, source: str) -> str | None:
        for pattern in self.entrypoint_patterns:
            match = pattern.search(source)
            if match:
                if match.groups():
                    return match.group(1)
                return match.group(0)
        return None

    def discover_harnesses(self, project_dir: Path) -> list[HarnessInfo]:
        harnesses: list[HarnessInfo] = []
        for path in sorted(project_dir.rglob("*")):
            if not path.is_file() or not self.is_harness_path(path):
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            entrypoint = self.detect_entrypoint(source)
            if not entrypoint and not looks_like_harness(source, self.language):
                continue
            rel_path = path.relative_to(project_dir).as_posix()
            harnesses.append(
                HarnessInfo(
                    rel_path=rel_path,
                    language=self.language,
                    target_name=target_name_for_path(path),
                    entrypoint=entrypoint,
                    source_sha256=sha256_text(source),
                )
            )
        return harnesses

    def profile_sources(self, project_dir: Path, rel_paths: list[str]) -> AstProfile:
        sources: list[tuple[str, str]] = []
        for rel_path in rel_paths:
            path = project_dir / rel_path
            if path.is_file():
                sources.append((rel_path, path.read_text(encoding="utf-8", errors="ignore")))
        return profile_sources(self.language, sources)


def sha256_text(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8", errors="ignore")).hexdigest()


def target_name_for_path(path: Path) -> str:
    if path.suffix == ".java" and path.name.endswith("Fuzzer.java"):
        return path.stem
    return path.stem


def looks_like_harness(source: str, language: str) -> bool:
    needles_by_language = {
        "c": ("LLVMFuzzerTestOneInput",),
        "c++": ("LLVMFuzzerTestOneInput",),
        "go": ("func Fuzz",),
        "rust": ("fuzz_target!",),
        "jvm": ("fuzzerTestOneInput", "@FuzzTest", "FuzzedDataProvider"),
        "python": ("atheris.Setup", "atheris.Fuzz", "TestOneInput"),
        "javascript": ("module.exports.fuzz", "FuzzedDataProvider", "jazzer"),
        "swift": ("LLVMFuzzerTestOneInput", "Fuzzer"),
        "ruby": ("Ruzzy", "fuzz"),
    }
    return any(needle in source for needle in needles_by_language.get(language, ("fuzz",)))


def profile_sources(language: str, sources: list[tuple[str, str]]) -> AstProfile:
    files = tuple(rel for rel, _ in sources)
    joined = "\n".join(source for _, source in sources)
    if language == "python":
        return _profile_python(files, joined)
    return _profile_text(language, files, joined)


def _profile_python(files: tuple[str, ...], source: str) -> AstProfile:
    calls: Counter[str] = Counter()
    imports: Counter[str] = Counter()
    branch_count = 0
    loop_count = 0
    entrypoints: list[str] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return _profile_text("python", files, source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _python_call_name(node.func)
            if name:
                calls[name] += 1
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.name.split(".")[0]] += 1
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports[node.module.split(".")[0]] += 1
        elif isinstance(node, ast.FunctionDef):
            if node.name.startswith("Fuzz") or node.name == "TestOneInput":
                entrypoints.append(node.name)
        elif isinstance(node, ast.If | ast.Match | ast.Try):
            branch_count += 1
        elif isinstance(node, ast.For | ast.While):
            loop_count += 1

    return AstProfile(
        language="python",
        files=files,
        entrypoints=tuple(sorted(set(entrypoints))),
        imported_modules=tuple(sorted(imports)),
        call_names=tuple(_expanded_counter(calls)),
        input_apis=tuple(_filter_terms(calls, INPUT_API_HINTS)),
        setup_apis=tuple(_filter_terms(calls, SETUP_HINTS)),
        cleanup_apis=tuple(_filter_terms(calls, CLEANUP_HINTS)),
        branch_count=branch_count,
        loop_count=loop_count,
        source_bytes=len(source.encode("utf-8", errors="ignore")),
    )


def _python_call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _python_call_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


def _profile_text(language: str, files: tuple[str, ...], source: str) -> AstProfile:
    call_counter: Counter[str] = Counter()
    imports = []
    for match in WORD_CALL.finditer(source):
        call = normalize_call_name(match.group(1))
        if call and not _is_language_keyword(call):
            call_counter[call] += 1
    for match in IMPORT_RE.finditer(source):
        imports.append(match.group(0).strip())

    entrypoints = []
    for pattern in ADAPTERS.get(language, ADAPTERS["c++"]).entrypoint_patterns:
        for match in pattern.finditer(source):
            if match.groups():
                entrypoints.append(match.group(1))
            else:
                entrypoints.append(match.group(0))

    return AstProfile(
        language=language,
        files=files,
        entrypoints=tuple(sorted(set(entrypoints))),
        imported_modules=tuple(sorted(set(imports))),
        call_names=tuple(_expanded_counter(call_counter)),
        input_apis=tuple(_filter_terms(call_counter, INPUT_API_HINTS)),
        setup_apis=tuple(_filter_terms(call_counter, SETUP_HINTS)),
        cleanup_apis=tuple(_filter_terms(call_counter, CLEANUP_HINTS)),
        branch_count=len(re.findall(r"\b(if|switch|catch|case|match)\b", source)),
        loop_count=len(re.findall(r"\b(for|while|loop)\b", source)),
        source_bytes=len(source.encode("utf-8", errors="ignore")),
    )


def normalize_call_name(call: str) -> str:
    call = call.strip().strip("&*")
    call = call.replace("->", ".").replace("::", ".")
    return call.rsplit(".", 1)[-1] if "." in call else call


def _is_language_keyword(call: str) -> bool:
    return call in {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "catch",
        "new",
        "delete",
        "function",
    }


def _expanded_counter(counter: Counter[str]) -> list[str]:
    expanded: list[str] = []
    for key, count in sorted(counter.items()):
        expanded.extend([key] * min(count, 8))
    return expanded


def _filter_terms(counter: Counter[str], hints: tuple[str, ...]) -> list[str]:
    values = []
    lowered_hints = tuple(h.lower() for h in hints)
    for key in sorted(counter):
        lowered = key.lower()
        if any(hint in lowered for hint in lowered_hints):
            values.append(key)
    return values


ADAPTERS: dict[str, LanguageAdapter] = {
    "c": LanguageAdapter(
        "c",
        (".c", ".h"),
        (re.compile(r"\bLLVMFuzzerTestOneInput\s*\("), re.compile(r"\bLLVMFuzzerInitialize\s*\(")),
    ),
    "c++": LanguageAdapter(
        "c++",
        (".cc", ".cpp", ".cxx", ".c", ".hpp", ".hh", ".h"),
        (re.compile(r"\bLLVMFuzzerTestOneInput\s*\("), re.compile(r"\bLLVMFuzzerInitialize\s*\(")),
    ),
    "go": LanguageAdapter(
        "go",
        (".go",),
        (re.compile(r"\bfunc\s+(Fuzz[A-Za-z0-9_]*)\s*\("),),
    ),
    "rust": LanguageAdapter(
        "rust",
        (".rs",),
        (re.compile(r"\bfuzz_target!\s*!?\s*\("), re.compile(r"\bfuzz_target!\s*\{")),
    ),
    "jvm": LanguageAdapter(
        "jvm",
        (".java", ".kt", ".scala"),
        (
            re.compile(r"\b(?:static\s+)?(?:void|int)\s+(fuzzerTestOneInput)\s*\("),
            re.compile(r"@(FuzzTest)\b"),
        ),
    ),
    "python": LanguageAdapter(
        "python",
        (".py",),
        (re.compile(r"\bdef\s+(TestOneInput|Fuzz[A-Za-z0-9_]*)\s*\("),),
    ),
    "javascript": LanguageAdapter(
        "javascript",
        (".js", ".mjs", ".cjs", ".ts"),
        (
            re.compile(r"\bmodule\.exports\.fuzz\b"),
            re.compile(r"\bexport\s+function\s+(fuzz)\s*\("),
        ),
    ),
    "swift": LanguageAdapter(
        "swift",
        (".swift",),
        (
            re.compile(r"\bLLVMFuzzerTestOneInput\s*\("),
            re.compile(r"\bfunc\s+(Fuzz[A-Za-z0-9_]*)\s*\("),
        ),
    ),
    "ruby": LanguageAdapter(
        "ruby",
        (".rb",),
        (re.compile(r"\bRuzzy\.fuzz\b"), re.compile(r"\bdef\s+(fuzz|test_one_input)\b")),
    ),
}


def adapter_for_language(language: str) -> LanguageAdapter:
    normalized = normalize_language(language)
    return ADAPTERS.get(normalized, ADAPTERS["c++"])


def normalize_language(language: str) -> str:
    language = language.strip().strip('"').strip("'").lower()
    if language in {"python3", "python"}:
        return "python"
    if language in {"java", "kotlin", "scala"}:
        return "jvm"
    if language in {"cpp", "cxx"}:
        return "c++"
    return language
