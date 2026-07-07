from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    repo_root: Path
    targets_file: Path
    target_override: str | None = None
    profile: str = "balanced"
    interactive: bool = True
    pause_severities: set[str] = field(default_factory=lambda: {"Critical", "High", "Medium"})
    command_timeout: int = 1800
    nmap_discovery_args: list[str] = field(
        default_factory=lambda: ["-sS", "-p-", "--min-rate", "2000", "-Pn"]
    )
    nmap_service_args: list[str] = field(default_factory=lambda: ["-sV", "-sC", "-Pn"])
    nuclei_templates: str = "cves/,vulnerabilities/,misconfiguration/"
    nuclei_severity: str = "critical,high,medium"
    skip_tools: set[str] = field(default_factory=set)
    include_nikto: bool = True
    include_auxiliary_nmap: bool = True

    def tool_enabled(self, name: str) -> bool:
        return name.lower() not in {item.lower() for item in self.skip_tools}
