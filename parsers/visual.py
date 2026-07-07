from __future__ import annotations

import re
from pathlib import Path

from core.models import Target, VisualEvidence, clean_text


def build_evidence(
    *,
    target: Target,
    url: str,
    screenshot_path: Path,
    raw_output_path: Path,
    port: str,
    service: str = "web",
    output: str = "",
) -> VisualEvidence:
    title = _extract_title(output)
    status_code = _extract_status(output)
    return VisualEvidence(
        target=target.display,
        url=url,
        screenshot_path=str(screenshot_path),
        ip=target.scan_host,
        port=port,
        service=service,
        raw_output_path=str(raw_output_path),
        title=title,
        status_code=status_code,
    )


def _extract_title(output: str) -> str:
    match = re.search(r'title="?([^"\n]+)"?', output, flags=re.IGNORECASE)
    return clean_text(match.group(1), 160) if match else ""


def _extract_status(output: str) -> str:
    match = re.search(r"status(?:-code)?=([0-9]{3})", output, flags=re.IGNORECASE)
    return match.group(1) if match else ""
