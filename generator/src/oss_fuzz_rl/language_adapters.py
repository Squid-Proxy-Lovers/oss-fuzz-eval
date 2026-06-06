"""Language-specific harness discovery and static profiling."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from tree_sitter import Parser
from tree_sitter_language_pack import get_language

from oss_fuzz_rl.models import AstProfile, HarnessInfo

FUZZY_HARNESS_NAME = re.compile(r"(fuzz|fuzzer)", re.IGNORECASE)

TREE_SITTER_GRAMMAR_BY_LANGUAGE = {
    "c": "c",
    "c++": "cpp",
    "go": "go",
    "javascript": "javascript",
    "jvm": "java",
    "python": "python",
    "ruby": "ruby",
    "rust": "rust",
    "swift": "swift",
}
TREE_SITTER_GRAMMAR_BY_SUFFIX = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".go": "go",
    ".h": "c",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".java": "java",
    ".js": "javascript",
    ".kt": "kotlin",
    ".mjs": "javascript",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".swift": "swift",
    ".ts": "typescript",
}
CALL_NODE_TYPES = {
    "call",
    "call_expression",
    "macro_invocation",
    "method_invocation",
}
DECLARATION_NODE_TYPES = {
    "function_declaration",
    "function_definition",
    "function_item",
    "method",
    "method_declaration",
}
IMPORT_NODE_TYPES = {
    "extern_crate_declaration",
    "import_declaration",
    "import_from_statement",
    "import_header",
    "import_statement",
    "preproc_include",
    "use_declaration",
}
BRANCH_NODE_TYPES = {
    "case_label",
    "case_statement",
    "catch_clause",
    "catch_formal_parameter",
    "if",
    "if_expression",
    "if_statement",
    "match_expression",
    "switch_expression",
    "switch_statement",
    "try_statement",
}
LOOP_NODE_TYPES = {
    "do_statement",
    "enhanced_for_statement",
    "for_expression",
    "for_in_statement",
    "for_statement",
    "loop_expression",
    "repeat_while_statement",
    "while_expression",
    "while_statement",
}
IDENTIFIER_NODE_TYPES = {
    "field_identifier",
    "identifier",
    "package_identifier",
    "property_identifier",
    "simple_identifier",
    "type_identifier",
}
ARGUMENT_NODE_TYPES = {
    "argument_list",
    "arguments",
    "call_suffix",
    "value_arguments",
}

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
    return _profile_tree_sitter(language, sources, files, joined)


def _profile_tree_sitter(
    language: str,
    sources: list[tuple[str, str]],
    files: tuple[str, ...],
    joined: str,
) -> AstProfile:
    calls: Counter[str] = Counter()
    imports: set[str] = set()
    entrypoints: list[str] = []
    branch_count = 0
    loop_count = 0

    for rel_path, source in sources:
        grammar = _tree_sitter_grammar(language, rel_path)
        source_bytes = source.encode("utf-8", errors="ignore")
        tree = _tree_sitter_parser(grammar).parse(source_bytes)
        source_branch_count, source_loop_count = _collect_tree_sitter_profile(
            grammar, tree.root_node, calls, imports, entrypoints
        )
        branch_count += source_branch_count
        loop_count += source_loop_count

    return AstProfile(
        language=language,
        files=files,
        entrypoints=tuple(sorted(set(entrypoints))),
        imported_modules=tuple(sorted(imports)),
        call_names=tuple(_expanded_counter(calls)),
        input_apis=tuple(_filter_terms(calls, INPUT_API_HINTS)),
        setup_apis=tuple(_filter_terms(calls, SETUP_HINTS)),
        cleanup_apis=tuple(_filter_terms(calls, CLEANUP_HINTS)),
        branch_count=branch_count,
        loop_count=loop_count,
        source_bytes=len(joined.encode("utf-8", errors="ignore")),
    )


def _tree_sitter_grammar(language: str, rel_path: str) -> str:
    suffix = Path(rel_path).suffix.lower()
    if suffix == ".h" and language == "c++":
        return "cpp"
    grammar = TREE_SITTER_GRAMMAR_BY_SUFFIX.get(
        suffix, TREE_SITTER_GRAMMAR_BY_LANGUAGE.get(language)
    )
    if grammar is None:
        raise ValueError(
            f"tree-sitter grammar is not configured for language={language!r}, "
            f"path={rel_path!r}"
        )
    return grammar


@cache
def _tree_sitter_parser(grammar: str) -> Any:
    parser = Parser()
    parser.language = get_language(grammar)
    return parser


def _walk_tree(root: Any):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _collect_tree_sitter_profile(
    grammar: str,
    root: Any,
    calls: Counter[str],
    imports: set[str],
    entrypoints: list[str],
) -> tuple[int, int]:
    branch_count = 0
    loop_count = 0
    for node in _walk_tree(root):
        node_type = node.type
        if node_type in CALL_NODE_TYPES:
            call_name = _tree_sitter_call_name(node)
            if call_name and not _is_language_keyword(call_name):
                calls[call_name] += 1
                if call_name == "require":
                    imports.add(_node_text(node).strip())
            entrypoint = _entrypoint_from_call(node, call_name, grammar)
            if entrypoint:
                entrypoints.append(entrypoint)
            if grammar == "rust" and call_name == "fuzz_target":
                nested = _rust_fuzz_target_body(_node_text(node))
                if nested:
                    nested_branch_count, nested_loop_count = _collect_rust_macro_body_profile(
                        nested, calls, imports, entrypoints
                    )
                    branch_count += nested_branch_count
                    loop_count += nested_loop_count
        elif node_type in DECLARATION_NODE_TYPES:
            entrypoint = _entrypoint_from_declaration(node, grammar)
            if entrypoint:
                entrypoints.append(entrypoint)
        elif node_type in IMPORT_NODE_TYPES:
            imports.add(_node_text(node).strip())
        elif node_type == "assignment_expression":
            entrypoint = _entrypoint_from_assignment(node, grammar)
            if entrypoint:
                entrypoints.append(entrypoint)
        elif node.is_named and node_type in BRANCH_NODE_TYPES:
            branch_count += 1
        elif node.is_named and node_type in LOOP_NODE_TYPES:
            loop_count += 1
        elif node_type in {"annotation", "marker_annotation"} and "FuzzTest" in _node_text(node):
            entrypoints.append("FuzzTest")
    return branch_count, loop_count


def _collect_rust_macro_body_profile(
    body: str,
    calls: Counter[str],
    imports: set[str],
    entrypoints: list[str],
) -> tuple[int, int]:
    tree = _tree_sitter_parser("rust").parse(f"fn __fuzz() {{ {body} }}".encode())
    return _collect_tree_sitter_profile("rust", tree.root_node, calls, imports, entrypoints)


def _node_text(node: Any) -> str:
    return node.text.decode("utf-8", errors="ignore")


def _tree_sitter_call_name(node: Any) -> str | None:
    for field in ("function", "name", "method"):
        child = node.child_by_field_name(field)
        if child is not None:
            return _last_identifier(child)

    for child in node.named_children:
        if child.type not in ARGUMENT_NODE_TYPES:
            name = _last_identifier(child)
            if name:
                return name
    return None


def _entrypoint_from_call(node: Any, call_name: str | None, grammar: str) -> str | None:
    text = _node_text(node)
    if grammar == "rust" and call_name == "fuzz_target":
        return "fuzz_target!("
    if grammar == "ruby" and call_name == "fuzz" and text.startswith("Ruzzy.fuzz"):
        return "Ruzzy.fuzz"
    if grammar in {"javascript", "typescript"} and call_name == "fuzz":
        return "fuzz"
    return None


def _entrypoint_from_assignment(node: Any, grammar: str) -> str | None:
    if grammar not in {"javascript", "typescript"}:
        return None
    left = node.child_by_field_name("left")
    if left is None:
        return None
    left_text = _node_text(left).strip()
    if left_text in {"module.exports.fuzz", "exports.fuzz"}:
        return left_text
    return None


def _rust_fuzz_target_body(text: str) -> str | None:
    first_pipe = text.find("|")
    if first_pipe < 0:
        return None
    second_pipe = text.find("|", first_pipe + 1)
    if second_pipe < 0:
        return None
    open_brace = text.find("{", second_pipe + 1)
    if open_brace < 0:
        return None

    depth = 0
    for index, char in enumerate(text[open_brace:], start=open_brace):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : index]
    return None


def _entrypoint_from_declaration(node: Any, grammar: str) -> str | None:
    name = _declaration_name(node)
    if not name:
        return None
    if name in {"LLVMFuzzerInitialize", "LLVMFuzzerTestOneInput"}:
        return f"{name}("
    if _is_named_entrypoint(name, grammar):
        return name
    return None


def _is_named_entrypoint(name: str, grammar: str) -> bool:
    return (
        (grammar == "go" and name.startswith("Fuzz"))
        or (grammar == "python" and (name.startswith("Fuzz") or name == "TestOneInput"))
        or (grammar in {"java", "kotlin", "scala"} and name == "fuzzerTestOneInput")
        or (grammar in {"javascript", "typescript"} and name == "fuzz")
        or (grammar == "ruby" and name in {"fuzz", "test_one_input"})
    )


def _declaration_name(node: Any) -> str | None:
    for field in ("name", "declarator"):
        child = node.child_by_field_name(field)
        if child is not None:
            name = _declarator_name(child)
            if name:
                return name
    return _declarator_name(node)


def _declarator_name(node: Any) -> str | None:
    if node.type in IDENTIFIER_NODE_TYPES:
        return _node_text(node)
    nested = node.child_by_field_name("declarator")
    if nested is not None:
        name = _declarator_name(nested)
        if name:
            return name
    for child in node.named_children:
        if child.type in {
            "formal_parameters",
            "function_body",
            "function_value_parameters",
            "parameter",
            "parameter_list",
            "parameters",
        }:
            continue
        name = _declarator_name(child)
        if name:
            return name
    return None


def _last_identifier(node: Any) -> str | None:
    identifiers: list[str] = []
    for child in _walk_tree(node):
        if child.type in IDENTIFIER_NODE_TYPES:
            identifiers.append(_node_text(child))
    if identifiers:
        return normalize_call_name(identifiers[-1])
    return normalize_call_name(_node_text(node))


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
    try:
        return ADAPTERS[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported OSS-Fuzz project language: {language!r}") from exc


def normalize_language(language: str) -> str:
    language = language.strip().strip('"').strip("'").lower()
    if language in {"python3", "python"}:
        return "python"
    if language in {"java", "kotlin", "scala"}:
        return "jvm"
    if language in {"cpp", "cxx"}:
        return "c++"
    return language
