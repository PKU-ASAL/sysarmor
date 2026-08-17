#!/usr/bin/env python3
"""Read phase-specific performance metrics from an endpoint matrix."""

from __future__ import annotations

import csv
import math
from pathlib import Path
from typing import Any


def load_matrix_phase(path: Path, phase: str) -> dict[str, Any]:
    matrix = path.parent / "matrix.csv"
    if not matrix.exists():
        return {}
    with matrix.open(newline="") as stream:
        for row in csv.DictReader(stream):
            if row.get("policy_dir") == path.name:
                return {
                    "agent_cpu_avg_pct": numeric(row.get(f"{phase}_agent_cpu_avg_pct")),
                    "agent_rss_max_mb": numeric(row.get(f"{phase}_agent_rss_max_mb")),
                    "eps": numeric(row.get(f"{phase}_eps")),
                }
    return {}


def numeric(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None
