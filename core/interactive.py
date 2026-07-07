from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .models import Finding
from .workspace import ScanWorkspace


@dataclass
class InteractionState:
    non_interactive_targets: set[str] = field(default_factory=set)

    def skip_for(self, target: str) -> bool:
        return target in self.non_interactive_targets

    def set_skip(self, target: str) -> None:
        self.non_interactive_targets.add(target)


class InteractiveReview:
    def __init__(self, enabled: bool, pause_severities: set[str]) -> None:
        self.enabled = enabled
        self.pause_severities = pause_severities
        self.console = Console()
        self.state = InteractionState()

    def should_pause(self, finding: Finding) -> bool:
        if not self.enabled:
            return False
        if self.state.skip_for(finding.target):
            return False
        return finding.severity in self.pause_severities

    def review(self, finding: Finding, workspace: ScanWorkspace) -> Finding:
        if self.state.skip_for(finding.target):
            finding.status = "confirmed"
            finding.auditor_note = finding.auditor_note or "Auto-added after auditor selected continue without pauses for this target."
            workspace.write_evidence_note(finding)
            return finding

        if not self.should_pause(finding):
            finding.status = "observed"
            return finding

        while True:
            self._render(finding)
            choice = Prompt.ask(
                "[bold cyan][A][/bold cyan]gregar / [bold cyan][D][/bold cyan]escartar / "
                "[bold cyan][P][/bold cyan]ausar shell / [bold cyan][C][/bold cyan]ontinuar sin pausas",
                choices=["A", "D", "P", "C", "a", "d", "p", "c"],
                default="A",
            ).upper()
            if choice == "A":
                finding.status = "confirmed"
                finding.auditor_note = Prompt.ask("Nota breve de validacion", default="")
                workspace.write_evidence_note(finding)
                return finding
            if choice == "D":
                finding.status = "discarded"
                finding.auditor_note = Prompt.ask("Motivo del descarte", default="False positive / not reproducible")
                workspace.append_exclusion(finding)
                return finding
            if choice == "P":
                self._open_shell()
                continue
            if choice == "C":
                self.state.set_skip(finding.target)
                finding.status = "confirmed"
                finding.auditor_note = "Auto-added after auditor selected continue without pauses for this target."
                workspace.write_evidence_note(finding)
                return finding

    def _render(self, finding: Finding) -> None:
        self.console.rule("[bold red]Potential Vulnerability Detected[/bold red]")
        table = Table(show_header=False, box=None)
        for key, value in [
            ("Tool", finding.tool),
            ("Target", finding.target),
            ("IP/URL", finding.ip or finding.url or "-"),
            ("Port/Service", f"{finding.port or '-'} {finding.service or ''}".strip()),
            ("Severity", finding.severity),
            ("CVE/CWE", f"{finding.cve or '-'} / {finding.cwe or '-'}"),
            ("Raw Output", finding.raw_output_path or "-"),
        ]:
            table.add_row(f"[bold]{key}[/bold]", str(value))
        self.console.print(table)
        self.console.print(
            Panel.fit(
                finding.evidence or finding.description or finding.title,
                title=finding.title,
                border_style="red" if finding.severity in {"Critical", "High"} else "yellow",
            )
        )

    def _open_shell(self) -> None:
        shell = os.environ.get("SHELL") or "/bin/bash"
        self.console.print(f"[yellow]Opening temporary shell: {shell}. Type 'exit' to return.[/yellow]")
        try:
            subprocess.run([shell], check=False)
        except OSError as exc:
            self.console.print(f"[red]Could not open shell: {exc}[/red]")
