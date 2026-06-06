from __future__ import annotations

import pytest

from oss_fuzz_rl.language_adapters import profile_sources


def test_tree_sitter_cpp_profile_counts_real_calls_not_declarations() -> None:
    source = """
#include "demo.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 1) {
    parse_demo(data, size);
  }
  if (size == 0) {
    cleanup_demo();
  }
  return 0;
}
"""

    profile = profile_sources("c++", [("demo_fuzzer.cc", source)])

    assert profile.entrypoints == ("LLVMFuzzerTestOneInput(",)
    assert profile.imported_modules == ('#include "demo.h"',)
    assert profile.call_names == ("cleanup_demo", "parse_demo")
    assert "LLVMFuzzerTestOneInput" not in profile.call_names
    assert profile.branch_count == 2
    assert profile.loop_count == 0


def test_tree_sitter_ruby_profile_detects_ruzzy_fuzz_entrypoint() -> None:
    source = """
require "ruzzy"
require "ox"

test_one_input = lambda do |data|
  Ox.parse(data)
end

Ruzzy.fuzz(test_one_input)
"""

    profile = profile_sources("ruby", [("fuzz_parse.rb", source)])

    assert "Ruzzy.fuzz" in profile.entrypoints
    assert {"fuzz", "lambda", "parse", "require"} <= set(profile.call_names)


@pytest.mark.parametrize(
    ("language", "rel_path", "source", "entrypoint", "calls", "branches"),
    [
        (
            "c",
            "fuzz_c.c",
            """
#include "demo.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size) parse_c(data);
  return 0;
}
""",
            "LLVMFuzzerTestOneInput(",
            {"parse_c"},
            1,
        ),
        (
            "go",
            "fuzz_go.go",
            """
package demo
import "testing"
func FuzzParser(f *testing.F) {
  f.Fuzz(func(t *testing.T, data []byte) { Parse(data) })
}
""",
            "FuzzParser",
            {"Fuzz", "Parse"},
            0,
        ),
        (
            "jvm",
            "ParserFuzzer.java",
            """
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
class ParserFuzzer {
  public static void fuzzerTestOneInput(byte[] data) {
    if (data.length > 0) parse(data);
  }
}
""",
            "fuzzerTestOneInput",
            {"parse"},
            1,
        ),
        (
            "jvm",
            "ParserFuzzer.kt",
            """
import com.code_intelligence.jazzer.api.FuzzedDataProvider
class ParserFuzzer {
  fun fuzzerTestOneInput(data: ByteArray) {
    if (data.isNotEmpty()) parse(data)
  }
}
""",
            "fuzzerTestOneInput",
            {"isNotEmpty", "parse"},
            1,
        ),
        (
            "javascript",
            "fuzz.js",
            """
const codec = require("codec");
module.exports.fuzz = function(data) {
  if (data.length) parse(data);
}
""",
            "module.exports.fuzz",
            {"parse", "require"},
            1,
        ),
        (
            "python",
            "fuzz_parser.py",
            """
import parser
def TestOneInput(data):
    if data:
        parser.parse(data)
""",
            "TestOneInput",
            {"parse"},
            1,
        ),
        (
            "ruby",
            "parser_fuzzer.rb",
            """
require "json"
def fuzz(data)
  if data
    JSON.parse(data)
  end
end
""",
            "fuzz",
            {"parse", "require"},
            1,
        ),
        (
            "rust",
            "fuzz_targets/parser.rs",
            """
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
  if data.len() > 0 {
    parse(data);
  }
});
""",
            "fuzz_target!(",
            {"fuzz_target", "len", "parse"},
            1,
        ),
        (
            "swift",
            "Fuzzer.swift",
            """
import Foundation
public func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int32 {
  if size > 0 {
    parse(data)
  }
  return 0
}
""",
            "LLVMFuzzerTestOneInput(",
            {"parse"},
            1,
        ),
    ],
)
def test_tree_sitter_profiles_supported_languages(
    language: str,
    rel_path: str,
    source: str,
    entrypoint: str,
    calls: set[str],
    branches: int,
) -> None:
    profile = profile_sources(language, [(rel_path, source)])

    assert entrypoint in profile.entrypoints
    assert calls <= set(profile.call_names)
    assert profile.branch_count == branches
