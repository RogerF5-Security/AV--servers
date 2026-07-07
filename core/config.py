from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    repo_root: Path
    targets_file: Path
    target_override: str | None = None
    profile: str = "deep"
    interactive: bool = False
    pause_severities: set[str] = field(default_factory=lambda: {"Critical", "High", "Medium"})
    command_timeout: int = 3600
    nmap_discovery_args: list[str] = field(
        default_factory=lambda: ["-sT", "-p-", "--min-rate", "2000", "-Pn"]
    )
    nmap_service_args: list[str] = field(default_factory=lambda: ["-sV", "-sC", "-Pn"])
    fallback_service_ports: str = "21,22,25,53,80,110,135,139,143,389,443,445,587,993,995,1433,1521,2375,3306,3389,5000,5001,5432,5900,5985,5986,6379,8000,8080,8443,8888,9000,9090,9200,9300,10250,11211,15672,27017,27018"
    nuclei_templates: str = "cves/,vulnerabilities/,misconfiguration/"
    nuclei_severity: str = "critical,high,medium,low"
    skip_tools: set[str] = field(default_factory=set)
    include_nikto: bool = True
    include_auxiliary_nmap: bool = True
    include_searchsploit: bool = True
    include_nmap_vuln: bool = True
    include_sslscan: bool = True
    include_visual: bool = True
    visual_timeout: int = 20
    compare_previous: Path | None = None
    fallback_common_checks: bool = True

    def tool_enabled(self, name: str) -> bool:
        return name.lower() not in {item.lower() for item in self.skip_tools}
