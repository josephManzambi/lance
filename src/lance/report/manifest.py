"""JSON manifest writer for Findings. Implementation pending v0.1."""

from __future__ import annotations

from pathlib import Path

from lance.models.finding import Finding


def write_manifest(finding: Finding, output_dir: Path) -> Path:
    """Write a Finding to a reproducibility JSON manifest. Returns the path written."""
    raise NotImplementedError("write_manifest — pending v0.1.")
