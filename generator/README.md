# OSS-Fuzz RL Eval

This package creates and scores RL episodes where an agent writes OSS-Fuzz
conformant fuzzing harnesses for real OSS-Fuzz project integrations.

The generator parses each OSS-Fuzz project's `Dockerfile`, finds the upstream
source checkout command, clones that upstream source into the task workspace,
and removes files/directories whose names identify fuzzing artifacts. Existing
OSS-Fuzz harnesses are not placed in the source workspace. Agents receive the
scrubbed upstream source tree, a redacted OSS-Fuzz integration context, harness
requirements, and an OpenCode-style edit environment. They finish an episode
with a single `task-end` tool call.

## Quick Start

```bash
cd generator
python -m pip install -r requirements.txt
uv run oss-fuzz-rl index --oss-fuzz-dir ../oss-fuzz
uv run oss-fuzz-rl generate --oss-fuzz-dir ../oss-fuzz --out /tmp/ofuzz-tasks --limit 5
uv run oss-fuzz-rl score --task /tmp/ofuzz-tasks/<task-id>
```

Static scoring works without Docker. Full scoring can run OSS-Fuzz build,
`check_build`, and coverage/Fuzz Introspector hooks:

```bash
uv run oss-fuzz-rl score --task /tmp/ofuzz-tasks/<task-id> --oss-fuzz-dir ../oss-fuzz --run-oss-fuzz
```

Tree-sitter dependencies are mandatory for task generation and scoring. The
profiler does not provide a regex fallback; missing parser dependencies or
unsupported grammars fail the run.

Reward weights can be changed with a schema-versioned config:

```bash
uv run oss-fuzz-rl score --task /tmp/ofuzz-tasks/<task-id> --reward-config reward-config.json
```

## Task Layout

Each generated task contains:

- `prompt.md`: public task prompt for the agent.
- `task.json`: public task metadata.
- `workspace/<source-dir>/`: upstream source cloned from the Dockerfile.
- `workspace/oss-fuzz-project/`: redacted OSS-Fuzz integration context.
- `oracle/`: hidden oracle metadata and original harness files.

Do not expose `oracle/` to the policy during training.

## Reward Shape

The scorer returns a `reward.v3` report with a normalized scalar in `[0, 1]`.
The report includes `groups`, `microcomponents`, `raw_metrics`, `caps`,
`artifacts`, and the `reward_config` used to compute the scalar.

- Hard-zero gates still apply for missing required `task-end` calls and hidden
  oracle access.
- Failed builds cap reward at `0.05`; failed runtime/checks cap reward at
  `0.25`; candidate-induced coverage failures after build/check cap reward at
  `0.35`.
- Scalar scoring requires dynamic OSS-Fuzz build/check/coverage data and hidden
  oracle coverage. Static tree-sitter profiling feeds diagnostics,
  microcomponents, gates, and caps, but there is no static scalar fallback.
- Creating more than one fuzz harness is allowed. Additional harnesses are
  judged through normal build, runtime, focus, and coverage signals; there is
  no separate harness-count quality reward.
- Built-in dynamic coverage scoring is relative to hidden oracle coverage
  breadth: for lines, functions, and regions, matching the oracle's covered
  count scores `0.8`; above-oracle coverage approaches `1.0` as the candidate
  approaches the oracle coverage denominator.
- `reward_config.v3` uses one dynamic scheme with a continuous smoothstep
  schedule from initial to mature weights. The old static and discrete
  early/middle/late configurations are not supported.
