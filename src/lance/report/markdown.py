"""Markdown report writer for Findings. Implementation pending v0.1."""

from __future__ import annotations

from pathlib import Path

from lance.models.finding import Finding


def write_markdown(finding: Finding, output_dir: Path) -> Path:
    """Write a human-readable Markdown report for a Finding."""
    raise NotImplementedError("write_markdown — pending v0.1.")
