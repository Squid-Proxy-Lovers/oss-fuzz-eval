"""Oracle replay helpers for validating task bundles."""

from __future__ import annotations

import shutil
from pathlib import Path

from oss_fuzz_rl.jsonio import read_json
from oss_fuzz_rl.models import OracleMetadata


def restore_oracle_workspace(task_dir: Path) -> Path:
    """Create a workspace with hidden oracle harness files restored."""

    oracle = OracleMetadata.from_json(read_json(task_dir / "oracle" / "oracle.json"))
    source = task_dir / "workspace"
    destination = task_dir / "oracle-replay-workspace"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    hidden_integration = task_dir / "oracle" / "oss-fuzz-project"
    if hidden_integration.is_dir():
        public_integration = destination / "oss-fuzz-project"
        shutil.rmtree(public_integration, ignore_errors=True)
        shutil.copytree(hidden_integration, public_integration)
    for harness in oracle.harnesses:
        src = task_dir / "oracle" / "files" / harness.rel_path
        dst = destination / "oss-fuzz-project" / harness.rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return destination
