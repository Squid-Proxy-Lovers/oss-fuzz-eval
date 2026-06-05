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
uv run oss-fuzz-rl index --oss-fuzz-dir ../oss-fuzz
uv run oss-fuzz-rl generate --oss-fuzz-dir ../oss-fuzz --out /tmp/ofuzz-tasks --limit 5
uv run oss-fuzz-rl score --task /tmp/ofuzz-tasks/<task-id>
```

Static scoring works without Docker. Full scoring can run OSS-Fuzz build,
`check_build`, and coverage/Fuzz Introspector hooks:

```bash
uv run oss-fuzz-rl score --task /tmp/ofuzz-tasks/<task-id> --oss-fuzz-dir ../oss-fuzz --run-oss-fuzz
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

The scorer returns a scalar in `[0, 2]` plus detailed components:

- Build/conformance, runtime, AST/reference structure, and subsystem focus
  contribute up to `1.0`.
- Fuzz Introspector/coverage performance contributes up to `1.0`.
- Build and runtime failures cap the scalar to avoid rewarding non-working
  harnesses.
