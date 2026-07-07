from __future__ import annotations

import csv
import html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from core.models import AuditIdentity, Finding, ScanRecord, SEVERITY_ORDER, VisualEvidence, clean_text, tail_text
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
        self.write_enterprise_exports([record], reports_dir, Path(record.workspace).name)
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
        self.write_enterprise_exports(records, scans_dir, campaign_id)
        return md_path, html_path

    def write_enterprise_exports(self, records: list[ScanRecord], output_dir: Path, prefix: str) -> tuple[Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        csv_path = output_dir / f"{prefix}_reporte_consolidado.csv"
        dojo_path = output_dir / f"{prefix}_defectdojo_generic.json"
        findings = self._sort([finding for record in records for finding in [*record.confirmed_findings, *record.observed_findings]])
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["Target", "Port", "Protocol", "Service", "Severity", "Tool", "Title", "CVE/CWE", "Remediation_Summary"],
            )
            writer.writeheader()
            for finding in findings:
                port, protocol = self._port_protocol(finding)
                writer.writerow(
                    {
                        "Target": finding.target,
                        "Port": port,
                        "Protocol": protocol,
                        "Service": finding.service,
                        "Severity": finding.severity,
                        "Tool": finding.tool,
                        "Title": finding.title,
                        "CVE/CWE": " / ".join(item for item in (finding.cve, finding.cwe) if item),
                        "Remediation_Summary": finding.recommendation or "Validar, corregir y reducir exposicion del servicio afectado.",
                    }
                )
        dojo_path.write_text(json.dumps({"findings": [self._defectdojo_finding(item) for item in findings]}, indent=2, ensure_ascii=False), encoding="utf-8")
        return csv_path, dojo_path

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
        if any(record.delta_summary for record in records):
            lines.extend(["", "## Analisis Diferencial Consolidado", ""])
            for record in records:
                if record.delta_summary:
                    lines.extend([f"### {record.target.display}", ""])
                    lines.extend(self._markdown_delta(record.delta_summary))
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
        if any(record.delta_summary for record in records):
            parts.append("<h2>Analisis Diferencial Consolidado</h2>")
            for record in records:
                if record.delta_summary:
                    parts.append(f"<h3>{html.escape(record.target.display)}</h3>")
                    parts.extend(self._html_delta(record.delta_summary))
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
        if record.delta_summary:
            lines.extend(["", "## Analisis Diferencial (Delta de Seguridad)", ""])
            lines.extend(self._markdown_delta(record.delta_summary))
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

        lines.extend(["", "### Resumen de Superficie Web", ""])
        lines.extend(self._markdown_visual_evidence(record.visual_evidence))

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
        parts.append("</table>")
        if record.delta_summary:
            parts.append("<h2>Analisis Diferencial (Delta de Seguridad)</h2>")
            parts.extend(self._html_delta(record.delta_summary))
        parts.extend(
            [
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
        parts.append("<h3>Resumen de Superficie Web</h3>")
        parts.extend(self._html_visual_evidence(record.visual_evidence))
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

    def _markdown_visual_evidence(self, items: list[VisualEvidence]) -> list[str]:
        if not items:
            return ["No se registraron capturas visuales web."]
        lines = ["| URL | Puerto | Estado | Titulo | Captura |", "|---|---|---|---|---|"]
        for item in items:
            shot = item.screenshot_path.replace("\\", "/")
            lines.append(
                f"| {item.url} | {item.port or '-'} | {item.status_code or '-'} | {clean_text(item.title, 120) or '-'} | ![captura]({shot}) |"
            )
        return lines

    def _html_visual_evidence(self, items: list[VisualEvidence]) -> list[str]:
        if not items:
            return ["<p>No se registraron capturas visuales web.</p>"]
        parts = ["<table><tr><th>URL</th><th>Puerto</th><th>Estado</th><th>Titulo</th><th>Captura</th></tr>"]
        for item in items:
            shot = item.screenshot_path.replace("\\", "/")
            parts.append(
                f"<tr><td><code>{html.escape(item.url)}</code></td><td>{html.escape(item.port or '-')}</td><td>{html.escape(item.status_code or '-')}</td><td>{html.escape(item.title or '-')}</td><td><img class='screenshot-thumb' src='{html.escape(shot)}' alt='Captura de {html.escape(item.url)}'></td></tr>"
            )
        parts.append("</table>")
        return parts

    def _markdown_delta(self, delta: dict[str, list[str]]) -> list[str]:
        if delta.get("error"):
            return [f"- Error de comparacion: {clean_text('; '.join(delta['error']), 220)}", ""]
        lines: list[str] = []
        sections = [
            ("Nuevos Puertos / Servicios Expuestos", delta.get("new_services", []), "No se detectaron nuevos servicios."),
            ("Nuevas Vulnerabilidades Detectadas", delta.get("new_findings", []), "No se detectaron vulnerabilidades nuevas."),
            ("Vulnerabilidades Remediadas", delta.get("remediated_findings", []), "No se detectaron vulnerabilidades remediadas."),
        ]
        for title, values, empty in sections:
            lines.extend([f"### {title}", ""])
            if values:
                lines.extend(f"- {clean_text(item, 220)}" for item in values)
            else:
                lines.append(empty)
            lines.append("")
        return lines

    def _html_delta(self, delta: dict[str, list[str]]) -> list[str]:
        if delta.get("error"):
            return [f"<p><strong>Error de comparacion:</strong> {html.escape(clean_text('; '.join(delta['error']), 220))}</p>"]
        parts: list[str] = []
        sections = [
            ("Nuevos Puertos / Servicios Expuestos", delta.get("new_services", []), "No se detectaron nuevos servicios."),
            ("Nuevas Vulnerabilidades Detectadas", delta.get("new_findings", []), "No se detectaron vulnerabilidades nuevas."),
            ("Vulnerabilidades Remediadas", delta.get("remediated_findings", []), "No se detectaron vulnerabilidades remediadas."),
        ]
        for title, values, empty in sections:
            parts.append(f"<h3>{html.escape(title)}</h3>")
            if values:
                parts.append("<ul>")
                for item in values:
                    parts.append(f"<li>{html.escape(clean_text(item, 220))}</li>")
                parts.append("</ul>")
            else:
                parts.append(f"<p>{html.escape(empty)}</p>")
        return parts

    def _markdown_commands(self, record: ScanRecord) -> list[str]:
        if not record.commands:
            return ["No se registraron comandos ejecutados."]
        lines = ["| Herramienta | Perfil | Codigo | Timeout | Duracion | Resumen salida | Salida cruda |", "|---|---|---:|---|---:|---|---|"]
        for command in record.commands:
            timeout = "si" if command.timed_out else "no"
            output = clean_text(tail_text(command.stdout or command.stderr, 220), 220) or "-"
            lines.append(
                f"| {command.tool} | {command.profile} | {command.returncode if command.returncode is not None else '-'} | {timeout} | {command.duration_seconds:.1f}s | {output} | `{command.raw_output_path}` |"
            )
        return lines

    def _html_commands(self, record: ScanRecord) -> list[str]:
        if not record.commands:
            return ["<p>No se registraron comandos ejecutados.</p>"]
        parts = ["<table><tr><th>Herramienta</th><th>Perfil</th><th>Codigo</th><th>Timeout</th><th>Duracion</th><th>Resumen salida</th><th>Salida cruda</th></tr>"]
        for command in record.commands:
            timeout = "si" if command.timed_out else "no"
            code = command.returncode if command.returncode is not None else "-"
            output = tail_text(command.stdout or command.stderr, 260) or "-"
            parts.append(
                f"<tr><td>{html.escape(command.tool)}</td><td>{html.escape(command.profile)}</td><td>{code}</td><td>{timeout}</td><td>{command.duration_seconds:.1f}s</td><td>{html.escape(output)}</td><td><code>{html.escape(str(command.raw_output_path))}</code></td></tr>"
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

    def _port_protocol(self, finding: Finding) -> tuple[str, str]:
        if finding.port:
            parts = finding.port.split("/", 1)
            if len(parts) == 2:
                return parts[0], parts[1]
            return finding.port, ""
        if finding.url:
            parsed = urlparse(finding.url)
            if parsed.port:
                return str(parsed.port), "tcp"
            if parsed.scheme == "https":
                return "443", "tcp"
            if parsed.scheme == "http":
                return "80", "tcp"
        return "", ""

    def _defectdojo_finding(self, finding: Finding) -> dict:
        port, protocol = self._port_protocol(finding)
        description = finding.description or finding.evidence or finding.title
        return {
            "title": finding.title,
            "severity": finding.severity,
            "description": clean_text(description, 3000),
            "mitigation": finding.recommendation or "Validar, corregir y reducir exposicion del servicio afectado.",
            "impact": f"Afecta al objetivo {finding.target} en {finding.port or finding.url or 'superficie detectada'}.",
            "references": finding.raw_output_path,
            "cve": finding.cve,
            "cwe": finding.cwe,
            "active": True,
            "verified": finding.status == "confirmed",
            "false_p": False,
            "unique_id_from_tool": finding.fingerprint,
            "scanner_confidence": finding.confidence,
            "endpoints": [
                {
                    "host": finding.ip or finding.target,
                    "port": port,
                    "protocol": protocol,
                    "path": finding.url,
                }
            ],
            "static_finding": False,
            "dynamic_finding": True,
        }
