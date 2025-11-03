"""Computation dispatcher - manages computation lifecycle via filesystem"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from bee_hive_core.types import Computation, ComputationResult


class ComputationDispatcher:
    """Manages computation lifecycle via filesystem"""

    def __init__(self, data_dir: Path):
        self.comp_dir = data_dir / "computation"
        self.comp_dir.mkdir(parents=True, exist_ok=True)

    def dispatch(self, computation: Computation) -> None:
        """Write .pending file for nectar to process"""
        pending_file = self.comp_dir / f"{computation.comp_id}.pending"
        pending_file.write_text(computation.model_dump_json(indent=2))

    async def wait_for_result(self, comp_id: str, timeout: int) -> ComputationResult:
        """Poll for .complete file"""
        complete_file = self.comp_dir / f"{comp_id}.complete"
        deadline = datetime.utcnow().timestamp() + timeout

        while datetime.utcnow().timestamp() < deadline:
            if complete_file.exists():
                result_data = json.loads(complete_file.read_text())
                result = ComputationResult(**result_data)
                complete_file.unlink()  # Cleanup
                return result
            await asyncio.sleep(0.1)

        # Timeout
        return ComputationResult(
            comp_id=comp_id,
            result=None,
            status="timeout",
            error=f"Computation timed out after {timeout}s"
        )
