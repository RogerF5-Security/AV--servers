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
        if not self.enabled:
            finding.status = "confirmed"
            finding.auditor_note = finding.auditor_note or "Confirmado automaticamente por modo zero-touch."
            workspace.write_evidence_note(finding)
            return finding

        if self.state.skip_for(finding.target):
            finding.status = "confirmed"
            finding.auditor_note = finding.auditor_note or "Agregado automaticamente despues de seleccionar continuar sin pausas para este objetivo."
            workspace.write_evidence_note(finding)
            return finding

        if not self.should_pause(finding):
            finding.status = "confirmed"
            finding.auditor_note = finding.auditor_note or "Confirmado automaticamente porque la severidad no requiere pausa interactiva."
            workspace.write_evidence_note(finding)
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
                finding.auditor_note = Prompt.ask("Motivo del descarte", default="Falso positivo / no reproducible")
                workspace.append_exclusion(finding)
                return finding
            if choice == "P":
                self._open_shell()
                continue
            if choice == "C":
                self.state.set_skip(finding.target)
                finding.status = "confirmed"
                finding.auditor_note = "Agregado automaticamente despues de seleccionar continuar sin pausas para este objetivo."
                workspace.write_evidence_note(finding)
                return finding

    def _render(self, finding: Finding) -> None:
        self.console.rule("[bold red]Vulnerabilidad potencial detectada[/bold red]")
        table = Table(show_header=False, box=None)
        for key, value in [
            ("Herramienta", finding.tool),
            ("Objetivo", finding.target),
            ("IP/URL", finding.ip or finding.url or "-"),
            ("Puerto/Servicio", f"{finding.port or '-'} {finding.service or ''}".strip()),
            ("Severidad", self._sev(finding.severity)),
            ("CVE/CWE", f"{finding.cve or '-'} / {finding.cwe or '-'}"),
            ("Salida cruda", finding.raw_output_path or "-"),
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
        self.console.print(f"[yellow]Abriendo shell temporal: {shell}. Escribe 'exit' para volver.[/yellow]")
        try:
            subprocess.run([shell], check=False)
        except OSError as exc:
            self.console.print(f"[red]No se pudo abrir la shell: {exc}[/red]")

    def _sev(self, severity: str) -> str:
        return {
            "Critical": "Critica",
            "High": "Alta",
            "Medium": "Media",
            "Low": "Baja",
            "Info": "Informativa",
        }.get(severity, severity)
