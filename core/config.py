from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    repo_root: Path
    targets_file: Path
    target_override: str | None = None
    profile: str = "balanced"
    interactive: bool = False
    pause_severities: set[str] = field(default_factory=lambda: {"Critical", "High", "Medium"})
    command_timeout: int = 1800
    nmap_discovery_args: list[str] = field(
        default_factory=lambda: ["-sT", "-p-", "--min-rate", "2000", "-Pn"]
    )
    nmap_service_args: list[str] = field(default_factory=lambda: ["-sV", "-sC", "-Pn"])
    fallback_service_ports: str = "21,22,25,53,80,110,135,139,143,389,443,445,587,993,995,1433,1521,3306,3389,5432,5900,5985,5986,8000,8080,8443,8888"
    nuclei_templates: str = "cves/,vulnerabilities/,misconfiguration/"
    nuclei_severity: str = "critical,high,medium"
    skip_tools: set[str] = field(default_factory=set)
    include_nikto: bool = True
    include_auxiliary_nmap: bool = True
    fallback_common_checks: bool = True

    def tool_enabled(self, name: str) -> bool:
        return name.lower() not in {item.lower() for item in self.skip_tools}
