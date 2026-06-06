"""Command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from oss_fuzz_rl.episode import EpisodeTrace
from oss_fuzz_rl.jsonio import write_json
from oss_fuzz_rl.project_index import index_projects
from oss_fuzz_rl.replay import restore_oracle_workspace
from oss_fuzz_rl.reward import baseline_oracle_coverage, score_task
from oss_fuzz_rl.task_generator import generate_tasks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oss-fuzz-rl")
    sub = parser.add_subparsers(dest="command", required=True)

    index_parser = sub.add_parser("index", help="Index OSS-Fuzz projects and harnesses")
    index_parser.add_argument("--oss-fuzz-dir", type=Path, required=True)
    index_parser.add_argument("--json-out", type=Path)

    gen_parser = sub.add_parser("generate", help="Generate masked RL task bundles")
    gen_parser.add_argument("--oss-fuzz-dir", type=Path, required=True)
    gen_parser.add_argument("--out", type=Path, required=True)
    gen_parser.add_argument("--project")
    gen_parser.add_argument("--limit", type=int)
    gen_parser.add_argument("--seed", type=int, default=0)
    gen_parser.add_argument("--harnesses-per-task", type=int, default=1)

    score_parser = sub.add_parser("score", help="Score a completed task workspace")
    score_parser.add_argument("--task", type=Path, required=True)
    score_parser.add_argument("--workspace", type=Path)
    score_parser.add_argument("--trace", type=Path)
    score_parser.add_argument("--oss-fuzz-dir", type=Path)
    score_parser.add_argument("--run-oss-fuzz", action="store_true")
    score_parser.add_argument("--require-task-end", action="store_true")
    score_parser.add_argument("--reward-config", type=Path)
    score_parser.add_argument("--json-out", type=Path)

    baseline_parser = sub.add_parser("baseline-oracle", help="Generate hidden oracle coverage")
    baseline_parser.add_argument("--task", type=Path, required=True)
    baseline_parser.add_argument("--oss-fuzz-dir", type=Path, required=True)
    baseline_parser.add_argument("--coverage-seconds", type=int, default=30)
    baseline_parser.add_argument("--json-out", type=Path)

    replay_parser = sub.add_parser("replay-oracle", help="Restore hidden oracle and score it")
    replay_parser.add_argument("--task", type=Path, required=True)
    replay_parser.add_argument("--oss-fuzz-dir", type=Path)
    replay_parser.add_argument("--run-oss-fuzz", action="store_true")
    replay_parser.add_argument("--reward-config", type=Path)
    replay_parser.add_argument("--json-out", type=Path)

    args = parser.parse_args(argv)
    if args.command == "index":
        projects = index_projects(args.oss_fuzz_dir.resolve())
        data = {"projects": [project.to_json() for project in projects]}
        _emit(data, args.json_out)
        return 0
    if args.command == "generate":
        generated = generate_tasks(
            args.oss_fuzz_dir.resolve(),
            args.out.resolve(),
            project_name=args.project,
            limit=args.limit,
            seed=args.seed,
            harnesses_per_task=args.harnesses_per_task,
        )
        data = {"tasks": [str(path) for path in generated], "count": len(generated)}
        _emit(data, None)
        return 0
    if args.command == "score":
        trace = EpisodeTrace.from_jsonl(args.trace.resolve()) if args.trace else None
        report = score_task(
            args.task.resolve(),
            candidate_project_dir=args.workspace.resolve() if args.workspace else None,
            trace=trace,
            oss_fuzz_dir=args.oss_fuzz_dir.resolve() if args.oss_fuzz_dir else None,
            run_oss_fuzz=args.run_oss_fuzz,
            require_task_end=args.require_task_end,
            reward_config_path=args.reward_config.resolve() if args.reward_config else None,
        )
        _emit(report.to_json(), args.json_out)
        return 0
    if args.command == "baseline-oracle":
        coverage = baseline_oracle_coverage(
            args.task.resolve(),
            oss_fuzz_dir=args.oss_fuzz_dir.resolve(),
            coverage_seconds=args.coverage_seconds,
        )
        _emit({"coverage": coverage.to_json()}, args.json_out)
        return 0
    if args.command == "replay-oracle":
        workspace = restore_oracle_workspace(args.task.resolve())
        report = score_task(
            args.task.resolve(),
            candidate_project_dir=workspace,
            oss_fuzz_dir=args.oss_fuzz_dir.resolve() if args.oss_fuzz_dir else None,
            run_oss_fuzz=args.run_oss_fuzz,
            require_task_end=False,
            reward_config_path=args.reward_config.resolve() if args.reward_config else None,
        )
        _emit(report.to_json(), args.json_out)
        return 0
    return 2


def _emit(data: dict, path: Path | None) -> None:
    if path:
        write_json(path, data)
    else:
        print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
