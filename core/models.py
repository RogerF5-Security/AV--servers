from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}


def normalize_severity(value: str | None) -> str:
    mapping = {
        "critical": "Critical",
        "crit": "Critical",
        "high": "High",
        "medium": "Medium",
        "med": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
        "unknown": "Info",
    }
    return mapping.get(str(value or "Info").strip().lower(), "Info")


def clean_text(value: Any, limit: int = 1200) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def slugify(value: str, fallback: str = "target") -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    return slug[:90] or fallback


@dataclass
class AuditIdentity:
    started_at: str
    hostname: str = ""
    username: str = ""
    interface: str = ""
    source_ip: str = ""
    source_mac: str = ""
    route_probe: str = ""
    all_interfaces: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Target:
    raw: str
    host: str
    display: str
    kind: str
    scheme: str = ""
    port: int | None = None
    url: str = ""
    ip: str = ""

    @property
    def scan_host(self) -> str:
        return self.ip or self.host or self.display

    @property
    def is_url(self) -> bool:
        return self.kind == "url"

    @property
    def slug(self) -> str:
        return slugify(self.display)


@dataclass
class Service:
    host: str
    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""

    @property
    def label(self) -> str:
        parts = [self.name, self.product, self.version]
        return " ".join(part for part in parts if part).strip() or "unknown"

    @property
    def endpoint(self) -> str:
        return f"{self.port}/{self.protocol}"


@dataclass
class Finding:
    tool: str
    target: str
    title: str
    severity: str = "Info"
    ip: str = ""
    url: str = ""
    port: str = ""
    service: str = ""
    cve: str = ""
    cwe: str = ""
    cvss: str = ""
    description: str = ""
    evidence: str = ""
    raw_output_path: str = ""
    recommendation: str = ""
    auditor_note: str = ""
    status: str = "potential"
    confidence: str = "medium"
    source_id: str = ""
    fingerprint: str = ""

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if not self.fingerprint:
            self.fingerprint = self.build_fingerprint()

    def build_fingerprint(self) -> str:
        raw = "|".join(
            [
                self.tool.lower(),
                self.target.lower(),
                self.title.lower(),
                self.ip,
                self.url.lower(),
                self.port,
                self.service.lower(),
                self.cve.upper(),
                clean_text(self.evidence, 300).lower(),
            ]
        )
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CommandResult:
    tool: str
    profile: str
    command: list[str]
    raw_output_path: Path
    returncode: int | None
    timed_out: bool
    duration_seconds: float
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "profile": self.profile,
            "command": self.command,
            "raw_output_path": str(self.raw_output_path),
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "duration_seconds": round(self.duration_seconds, 3),
            "stdout_bytes": len(self.stdout.encode("utf-8", errors="ignore")),
            "stderr_bytes": len(self.stderr.encode("utf-8", errors="ignore")),
        }


@dataclass
class ScanRecord:
    target: Target
    workspace: str
    services: list[Service] = field(default_factory=list)
    confirmed_findings: list[Finding] = field(default_factory=list)
    discarded_findings: list[Finding] = field(default_factory=list)
    observed_findings: list[Finding] = field(default_factory=list)
    commands: list[CommandResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.__dict__,
            "workspace": self.workspace,
            "services": [service.__dict__ for service in self.services],
            "confirmed_findings": [finding.to_dict() for finding in self.confirmed_findings],
            "discarded_findings": [finding.to_dict() for finding in self.discarded_findings],
            "observed_findings": [finding.to_dict() for finding in self.observed_findings],
            "commands": [command.to_dict() for command in self.commands],
        }
