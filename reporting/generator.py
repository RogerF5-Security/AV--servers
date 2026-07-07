from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path

from core.models import AuditIdentity, Finding, ScanRecord, SEVERITY_ORDER, clean_text
from .templates import HTML_STYLE


SEVERITY_ES = {
    "Critical": "Critica",
    "High": "Alta",
    "Medium": "Media",
    "Low": "Baja",
    "Info": "Informativa",
}


class ReportGenerator:
    def write(self, record: ScanRecord, reports_dir: Path) -> tuple[Path, Path]:
        reports_dir.mkdir(parents=True, exist_ok=True)
        base = f"{record.target.slug}_reporte"
        md_path = reports_dir / f"{base}.md"
        html_path = reports_dir / f"{base}.html"
        md_path.write_text(self.markdown(record), encoding="utf-8")
        html_path.write_text(self.html(record), encoding="utf-8")
        return md_path, html_path

    def write_campaign(
        self,
        *,
        records: list[ScanRecord],
        scans_dir: Path,
        identity: AuditIdentity,
        campaign_id: str,
        finished_at: str,
    ) -> tuple[Path, Path]:
        scans_dir.mkdir(parents=True, exist_ok=True)
        md_path = scans_dir / f"{campaign_id}_reporte_final_todos_los_objetivos.md"
        html_path = scans_dir / f"{campaign_id}_reporte_final_todos_los_objetivos.html"
        md_path.write_text(self.campaign_markdown(records, identity, finished_at), encoding="utf-8")
        html_path.write_text(self.campaign_html(records, identity, finished_at), encoding="utf-8")
        return md_path, html_path

    def campaign_markdown(self, records: list[ScanRecord], identity: AuditIdentity, finished_at: str) -> str:
        confirmed = self._sort([finding for record in records for finding in record.confirmed_findings])
        discarded = self._sort([finding for record in records for finding in record.discarded_findings])
        observed = self._sort([finding for record in records for finding in record.observed_findings])
        lines: list[str] = [
            "# Reporte Final Consolidado - Todos los Objetivos",
            "",
            "## Identidad de Ejecucion para SOC",
            "",
            f"- Inicio: `{identity.started_at}`",
            f"- Fin: `{finished_at}`",
            f"- Hostname: `{identity.hostname or '-'}`",
            f"- Usuario local: `{identity.username or '-'}`",
            f"- Interfaz origen: `{identity.interface or '-'}`",
            f"- IP origen para whitelist: `{identity.source_ip or '-'}`",
            f"- MAC origen para whitelist: `{identity.source_mac or '-'}`",
            f"- Ruta usada para deteccion: `{identity.route_probe or '-'}`",
            "",
        ]
        if identity.all_interfaces:
            lines.extend(
                [
                    "### Interfaces Locales Detectadas",
                    "",
                    "| Interfaz | IP | CIDR | MAC |",
                    "|---|---|---|---|",
                ]
            )
            for item in identity.all_interfaces:
                lines.append(
                    f"| {item.get('interface', '-')} | {item.get('ip', '-')} | {item.get('cidr', '-')} | {item.get('mac', '-')} |"
                )
            lines.append("")

        lines.extend(
            [
                "## Resumen Ejecutivo",
                "",
                self._executive_summary(confirmed, discarded, observed),
                "",
                "### Objetivos Analizados",
                "",
                "| Objetivo | IP resuelta | Servicios | Confirmados | Observados | Descartados | Reporte individual |",
                "|---|---|---:|---:|---:|---:|---|",
            ]
        )
        for record in records:
            report_path = f"{record.workspace}/reports/{record.target.slug}_reporte.html"
            lines.append(
                f"| {record.target.display} | {record.target.ip or '-'} | {len(record.services)} | {len(record.confirmed_findings)} | {len(record.observed_findings)} | {len(record.discarded_findings)} | `{report_path}` |"
            )

        lines.extend(
            [
                "",
                "### Resumen de Riesgo Global",
                "",
                "| Severidad | Confirmados | Observados | Descartados |",
                "|---|---:|---:|---:|",
            ]
        )
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            lines.append(
                f"| {self._sev(severity)} | {self._count(confirmed, severity)} | {self._count(observed, severity)} | {self._count(discarded, severity)} |"
            )

        lines.extend(["", "## Vulnerabilidades Confirmadas Consolidadas", ""])
        lines.extend(self._markdown_findings(confirmed, empty="No se confirmaron vulnerabilidades en la campana."))
        if observed:
            lines.extend(["", "## Observaciones Consolidadas", ""])
            lines.extend(self._markdown_findings(observed, empty=""))
        lines.extend(["", "## Falsos Positivos Descartados", ""])
        if discarded:
            lines.extend(["| Herramienta | Objetivo | Severidad | Titulo | Nota |", "|---|---|---|---|---|"])
            for finding in discarded:
                lines.append(
                    f"| {finding.tool} | {finding.target} | {self._sev(finding.severity)} | {clean_text(finding.title, 120)} | {clean_text(finding.auditor_note, 160)} |"
                )
        else:
            lines.append("No se descartaron hallazgos.")
        lines.append("")
        return "\n".join(lines)

    def campaign_html(self, records: list[ScanRecord], identity: AuditIdentity, finished_at: str) -> str:
        confirmed = self._sort([finding for record in records for finding in record.confirmed_findings])
        discarded = self._sort([finding for record in records for finding in record.discarded_findings])
        observed = self._sort([finding for record in records for finding in record.observed_findings])
        parts = [
            "<!doctype html><html><head><meta charset='utf-8'>",
            "<title>Reporte Final Consolidado - AV--servers</title>",
            f"<style>{HTML_STYLE}</style></head><body>",
            "<h1>Reporte Final Consolidado - Todos los Objetivos</h1>",
            "<h2>Identidad de Ejecucion para SOC</h2>",
            "<table>",
            f"<tr><th>Inicio</th><td>{html.escape(identity.started_at)}</td></tr>",
            f"<tr><th>Fin</th><td>{html.escape(finished_at)}</td></tr>",
            f"<tr><th>Hostname</th><td>{html.escape(identity.hostname or '-')}</td></tr>",
            f"<tr><th>Usuario local</th><td>{html.escape(identity.username or '-')}</td></tr>",
            f"<tr><th>Interfaz origen</th><td>{html.escape(identity.interface or '-')}</td></tr>",
            f"<tr><th>IP origen para whitelist</th><td>{html.escape(identity.source_ip or '-')}</td></tr>",
            f"<tr><th>MAC origen para whitelist</th><td>{html.escape(identity.source_mac or '-')}</td></tr>",
            "</table>",
        ]
        if identity.all_interfaces:
            parts.append("<h3>Interfaces Locales Detectadas</h3>")
            parts.append("<table><tr><th>Interfaz</th><th>IP</th><th>CIDR</th><th>MAC</th></tr>")
            for item in identity.all_interfaces:
                parts.append(
                    f"<tr><td>{html.escape(item.get('interface', '-'))}</td><td>{html.escape(item.get('ip', '-'))}</td><td>{html.escape(item.get('cidr', '-'))}</td><td>{html.escape(item.get('mac', '-'))}</td></tr>"
                )
            parts.append("</table>")

        parts.extend(
            [
                "<h2>Resumen Ejecutivo</h2>",
                f"<p>{html.escape(self._executive_summary(confirmed, discarded, observed))}</p>",
                "<h3>Objetivos Analizados</h3>",
                "<table><tr><th>Objetivo</th><th>IP resuelta</th><th>Servicios</th><th>Confirmados</th><th>Observados</th><th>Descartados</th><th>Workspace</th></tr>",
            ]
        )
        for record in records:
            parts.append(
                f"<tr><td>{html.escape(record.target.display)}</td><td>{html.escape(record.target.ip or '-')}</td><td>{len(record.services)}</td><td>{len(record.confirmed_findings)}</td><td>{len(record.observed_findings)}</td><td>{len(record.discarded_findings)}</td><td><code>{html.escape(record.workspace)}</code></td></tr>"
            )
        parts.append("</table>")
        parts.append("<h3>Resumen de Riesgo Global</h3>")
        parts.append("<table><tr><th>Severidad</th><th>Confirmados</th><th>Observados</th><th>Descartados</th></tr>")
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            parts.append(
                f"<tr><td class='sev-{severity}'>{html.escape(self._sev(severity))}</td><td>{self._count(confirmed, severity)}</td><td>{self._count(observed, severity)}</td><td>{self._count(discarded, severity)}</td></tr>"
            )
        parts.append("</table>")
        parts.append("<h2>Vulnerabilidades Confirmadas Consolidadas</h2>")
        parts.extend(self._html_findings(confirmed, "No se confirmaron vulnerabilidades en la campana."))
        if observed:
            parts.append("<h2>Observaciones Consolidadas</h2>")
            parts.extend(self._html_findings(observed, ""))
        parts.append("<h2>Falsos Positivos Descartados</h2>")
        if discarded:
            parts.append("<table><tr><th>Herramienta</th><th>Objetivo</th><th>Severidad</th><th>Titulo</th><th>Nota</th></tr>")
            for finding in discarded:
                parts.append(
                    f"<tr><td>{html.escape(finding.tool)}</td><td>{html.escape(finding.target)}</td><td>{html.escape(self._sev(finding.severity))}</td><td>{html.escape(finding.title)}</td><td>{html.escape(finding.auditor_note)}</td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p>No se descartaron hallazgos.</p>")
        parts.append("</body></html>")
        return "\n".join(parts)

    def markdown(self, record: ScanRecord) -> str:
        confirmed = self._sort(record.confirmed_findings)
        discarded = self._sort(record.discarded_findings)
        observed = self._sort(record.observed_findings)
        lines: list[str] = [
            f"# Informe de Evaluacion de Vulnerabilidades - {record.target.display}",
            "",
            f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "**Confidencialidad:** Confidencial",
            f"**Workspace:** `{record.workspace}`",
            "",
            "## Resumen Ejecutivo",
            "",
            self._executive_summary(confirmed, discarded, observed),
            "",
            "### Resumen de Riesgo",
            "",
            "| Severidad | Confirmados | Observados | Descartados |",
            "|---|---:|---:|---:|",
        ]
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            lines.append(
                f"| {self._sev(severity)} | {self._count(confirmed, severity)} | {self._count(observed, severity)} | {self._count(discarded, severity)} |"
            )
        lines.extend(
            [
                "",
                "## Alcance y Metodologia",
                "",
                f"- Objetivo: `{record.target.raw}`",
                f"- Host/IP resuelto: `{record.target.host}` / `{record.target.ip or 'no resuelto'}`",
                "- Metodologia: descubrimiento Nmap, deteccion de servicios y versiones, enumeracion por servicio, fingerprinting web, validacion con Nuclei, checks con Nikto y revision zero-touch.",
                "- Evidencia: toda la salida cruda de cada herramienta queda almacenada en `raw_outputs/` dentro del workspace del escaneo.",
                "",
                "### Servicios Identificados",
                "",
                "| Puerto | Protocolo | Servicio | Producto | Version |",
                "|---:|---|---|---|---|",
            ]
        )
        if record.services:
            for service in sorted(record.services, key=lambda item: (item.protocol, item.port)):
                lines.append(
                    f"| {service.port} | {service.protocol} | {service.name or '-'} | {service.product or '-'} | {service.version or '-'} |"
                )
        else:
            lines.append("| - | - | - | - | - |")

        lines.extend(["", "### Herramientas Ejecutadas", ""])
        lines.extend(self._markdown_commands(record))

        lines.extend(["", "## Vulnerabilidades Confirmadas", ""])
        lines.extend(self._markdown_findings(confirmed, empty="No se confirmaron vulnerabilidades durante esta ejecucion."))

        if observed:
            lines.extend(["", "## Observaciones Pendientes de Revision Manual", ""])
            lines.extend(self._markdown_findings(observed, empty=""))

        lines.extend(["", "## Anexo - Falsos Positivos Descartados", ""])
        if discarded:
            lines.extend(["| Herramienta | Severidad | Titulo | Nota del Auditor |", "|---|---|---|---|"])
            for finding in discarded:
                lines.append(
                    f"| {finding.tool} | {self._sev(finding.severity)} | {clean_text(finding.title, 120)} | {clean_text(finding.auditor_note, 160)} |"
                )
        else:
            lines.append("No se descartaron hallazgos.")
        lines.append("")
        return "\n".join(lines)

    def html(self, record: ScanRecord) -> str:
        confirmed = self._sort(record.confirmed_findings)
        observed = self._sort(record.observed_findings)
        discarded = self._sort(record.discarded_findings)
        summary = html.escape(self._executive_summary(confirmed, discarded, observed))
        parts = [
            "<!doctype html><html><head><meta charset='utf-8'>",
            f"<title>Informe de Vulnerabilidades - {html.escape(record.target.display)}</title>",
            f"<style>{HTML_STYLE}</style></head><body>",
            f"<h1>Informe de Evaluacion de Vulnerabilidades - {html.escape(record.target.display)}</h1>",
            f"<p class='meta'>Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>Workspace: {html.escape(record.workspace)}</p>",
            "<h2>Resumen Ejecutivo</h2>",
            f"<p>{summary}</p>",
            "<h3>Resumen de Riesgo</h3>",
            "<table><tr><th>Severidad</th><th>Confirmados</th><th>Observados</th><th>Descartados</th></tr>",
        ]
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            parts.append(
                f"<tr><td class='sev-{severity}'>{html.escape(self._sev(severity))}</td><td>{self._count(confirmed, severity)}</td><td>{self._count(observed, severity)}</td><td>{self._count(discarded, severity)}</td></tr>"
            )
        parts.extend(
            [
                "</table>",
                "<h2>Alcance y Metodologia</h2>",
                "<ul>",
                f"<li>Objetivo: <code>{html.escape(record.target.raw)}</code></li>",
                f"<li>Host/IP resuelto: <code>{html.escape(record.target.host)}</code> / <code>{html.escape(record.target.ip or 'no resuelto')}</code></li>",
                "<li>Metodologia: descubrimiento Nmap, deteccion de servicios y versiones, enumeracion por servicio, fingerprinting web, validacion con Nuclei, checks con Nikto y revision zero-touch.</li>",
                "<li>Evidencia: toda la salida cruda se almacena en <code>raw_outputs/</code>.</li>",
                "</ul>",
                "<h3>Servicios Identificados</h3>",
                "<table><tr><th>Puerto</th><th>Protocolo</th><th>Servicio</th><th>Producto</th><th>Version</th></tr>",
            ]
        )
        if record.services:
            for service in sorted(record.services, key=lambda item: (item.protocol, item.port)):
                parts.append(
                    f"<tr><td>{service.port}</td><td>{html.escape(service.protocol)}</td><td>{html.escape(service.name or '-')}</td><td>{html.escape(service.product or '-')}</td><td>{html.escape(service.version or '-')}</td></tr>"
                )
        else:
            parts.append("<tr><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>")
        parts.append("</table>")
        parts.append("<h3>Herramientas Ejecutadas</h3>")
        parts.extend(self._html_commands(record))
        parts.extend(["<h2>Vulnerabilidades Confirmadas</h2>"])
        parts.extend(self._html_findings(confirmed, "No se confirmaron vulnerabilidades durante esta ejecucion."))
        if observed:
            parts.append("<h2>Observaciones Pendientes de Revision Manual</h2>")
            parts.extend(self._html_findings(observed, ""))
        parts.append("<h2>Anexo - Falsos Positivos Descartados</h2>")
        if discarded:
            parts.append("<table><tr><th>Herramienta</th><th>Severidad</th><th>Titulo</th><th>Nota del Auditor</th></tr>")
            for finding in discarded:
                parts.append(
                    f"<tr><td>{html.escape(finding.tool)}</td><td>{html.escape(self._sev(finding.severity))}</td><td>{html.escape(finding.title)}</td><td>{html.escape(finding.auditor_note)}</td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p>No se descartaron hallazgos.</p>")
        parts.append("</body></html>")
        return "\n".join(parts)

    def _markdown_findings(self, findings: list[Finding], empty: str) -> list[str]:
        if not findings:
            return [empty] if empty else []
        lines: list[str] = []
        for index, finding in enumerate(findings, 1):
            lines.extend(
                [
                    f"### {index}. [{self._sev(finding.severity)}] {finding.title}",
                    "",
                    f"- Herramienta: `{finding.tool}`",
                    f"- IP / URL: `{finding.ip or '-'}` / `{finding.url or '-'}`",
                    f"- Puerto / Servicio: `{finding.port or '-'}` / `{finding.service or '-'}`",
                    f"- CVE / CWE: `{finding.cve or '-'}` / `{finding.cwe or '-'}`",
                    f"- CVSS: `{finding.cvss or '-'}`",
                    f"- Salida cruda: `{finding.raw_output_path or '-'}`",
                    "",
                    "**Descripcion Tecnica**",
                    "",
                    finding.description or finding.title,
                    "",
                    "**Evidencia**",
                    "",
                    "```text",
                    finding.evidence or "-",
                    "```",
                    "",
                    "**Notas del Auditor**",
                    "",
                    finding.auditor_note or "-",
                    "",
                    "**Remediacion**",
                    "",
                    finding.recommendation or "Validar el hallazgo, parchear el componente afectado y reducir la exposicion del servicio.",
                    "",
                ]
            )
        return lines

    def _html_findings(self, findings: list[Finding], empty: str) -> list[str]:
        if not findings:
            return [f"<p>{html.escape(empty)}</p>"] if empty else []
        parts: list[str] = []
        for index, finding in enumerate(findings, 1):
            severity = html.escape(self._sev(finding.severity))
            parts.extend(
                [
                    f"<h3>{index}. <span class='sev-{finding.severity}'>[{severity}]</span> {html.escape(finding.title)}</h3>",
                    "<table>",
                    f"<tr><th>Herramienta</th><td>{html.escape(finding.tool)}</td></tr>",
                    f"<tr><th>IP / URL</th><td><code>{html.escape(finding.ip or '-')}</code> / <code>{html.escape(finding.url or '-')}</code></td></tr>",
                    f"<tr><th>Puerto / Servicio</th><td>{html.escape(finding.port or '-')} / {html.escape(finding.service or '-')}</td></tr>",
                    f"<tr><th>CVE / CWE</th><td>{html.escape(finding.cve or '-')} / {html.escape(finding.cwe or '-')}</td></tr>",
                    f"<tr><th>Salida cruda</th><td><code>{html.escape(finding.raw_output_path or '-')}</code></td></tr>",
                    "</table>",
                    f"<p><strong>Descripcion Tecnica:</strong> {html.escape(finding.description or finding.title)}</p>",
                    f"<pre>{html.escape(finding.evidence or '-')}</pre>",
                    f"<p><strong>Notas del Auditor:</strong> {html.escape(finding.auditor_note or '-')}</p>",
                    f"<p><strong>Remediacion:</strong> {html.escape(finding.recommendation or 'Validar el hallazgo, parchear el componente afectado y reducir la exposicion del servicio.')}</p>",
                ]
            )
        return parts

    def _markdown_commands(self, record: ScanRecord) -> list[str]:
        if not record.commands:
            return ["No se registraron comandos ejecutados."]
        lines = ["| Herramienta | Perfil | Codigo | Timeout | Duracion | Salida cruda |", "|---|---|---:|---|---:|---|"]
        for command in record.commands:
            timeout = "si" if command.timed_out else "no"
            lines.append(
                f"| {command.tool} | {command.profile} | {command.returncode if command.returncode is not None else '-'} | {timeout} | {command.duration_seconds:.1f}s | `{command.raw_output_path}` |"
            )
        return lines

    def _html_commands(self, record: ScanRecord) -> list[str]:
        if not record.commands:
            return ["<p>No se registraron comandos ejecutados.</p>"]
        parts = ["<table><tr><th>Herramienta</th><th>Perfil</th><th>Codigo</th><th>Timeout</th><th>Duracion</th><th>Salida cruda</th></tr>"]
        for command in record.commands:
            timeout = "si" if command.timed_out else "no"
            code = command.returncode if command.returncode is not None else "-"
            parts.append(
                f"<tr><td>{html.escape(command.tool)}</td><td>{html.escape(command.profile)}</td><td>{code}</td><td>{timeout}</td><td>{command.duration_seconds:.1f}s</td><td><code>{html.escape(str(command.raw_output_path))}</code></td></tr>"
            )
        parts.append("</table>")
        return parts

    def _executive_summary(self, confirmed: list[Finding], discarded: list[Finding], observed: list[Finding]) -> str:
        counts = Counter(f.severity for f in confirmed)
        total = len(confirmed)
        if total:
            sev_text = ", ".join(f"{counts[s]} {self._sev(s)}" for s in ["Critical", "High", "Medium", "Low", "Info"] if counts[s])
            return (
                f"La evaluacion identifico {total} hallazgo(s) confirmado(s): {sev_text}. "
                f"{len(discarded)} hallazgo(s) potencial(es) fueron descartados como falsos positivos. "
                f"{len(observed)} hallazgo(s) quedaron como observaciones."
            )
        return (
            "No se agregaron vulnerabilidades confirmadas durante esta ejecucion. "
            f"{len(discarded)} hallazgo(s) fueron descartados y {len(observed)} hallazgo(s) quedaron como observaciones."
        )

    def _sort(self, findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.tool, item.title))

    def _count(self, findings: list[Finding], severity: str) -> int:
        return sum(1 for finding in findings if finding.severity == severity)

    def _sev(self, severity: str) -> str:
        return SEVERITY_ES.get(severity, severity)
