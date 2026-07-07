from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .models import Finding, ScanRecord, Target, slugify


class ScanWorkspace:
    def __init__(self, repo_root: Path, target: Target, timestamp: str | None = None) -> None:
        self.repo_root = repo_root
        self.target = target
        self.timestamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.root = repo_root / "scans" / f"{self.timestamp}_{slugify(target.display)}"
        self.raw_outputs = self.root / "raw_outputs"
        self.reports = self.root / "reports"
        self.evidence_notes = self.root / "evidence_notes"
        self.state_path = self.root / "state.json"
        self.exclusions_path = self.root / "exclusions.jsonl"
        self.commands_path = self.root / "commands.jsonl"

    def prepare(self) -> None:
        for path in (self.raw_outputs, self.reports, self.evidence_notes):
            path.mkdir(parents=True, exist_ok=True)

    def raw_path(self, tool: str, profile: str, suffix: str = "log") -> Path:
        safe = slugify(f"{tool}_{profile}")
        return self.raw_outputs / f"{safe}.{suffix}"

    def evidence_path(self, finding: Finding) -> Path:
        safe = slugify(f"{finding.severity}_{finding.tool}_{finding.title}_{finding.fingerprint[:10]}")
        return self.evidence_notes / f"{safe}.md"

    def append_exclusion(self, finding: Finding) -> None:
        self.exclusions_path.parent.mkdir(parents=True, exist_ok=True)
        with self.exclusions_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")

    def write_evidence_note(self, finding: Finding) -> Path:
        path = self.evidence_path(finding)
        lines = [
            f"# Evidence Note - {finding.title}",
            "",
            f"- Tool: {finding.tool}",
            f"- Severity: {finding.severity}",
            f"- Target: {finding.target}",
            f"- IP: {finding.ip or '-'}",
            f"- URL: {finding.url or '-'}",
            f"- Port/Service: {finding.port or '-'} {finding.service or ''}".strip(),
            f"- CVE/CWE: {finding.cve or '-'} / {finding.cwe or '-'}",
            f"- Status: {finding.status}",
            "",
            "## Auditor Note",
            "",
            finding.auditor_note or "-",
            "",
            "## Evidence",
            "",
            "```text",
            finding.evidence or "-",
            "```",
            "",
            f"Raw output: `{finding.raw_output_path or '-'}`",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def append_command(self, payload: dict) -> None:
        with self.commands_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def save_state(self, record: ScanRecord) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(record.to_dict(), handle, indent=2, ensure_ascii=False)
        tmp.replace(self.state_path)
