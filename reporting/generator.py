from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path

from core.models import Finding, ScanRecord, SEVERITY_ORDER, clean_text
from .templates import HTML_STYLE


class ReportGenerator:
    def write(self, record: ScanRecord, reports_dir: Path) -> tuple[Path, Path]:
        reports_dir.mkdir(parents=True, exist_ok=True)
        base = f"{record.target.slug}_report"
        md_path = reports_dir / f"{base}.md"
        html_path = reports_dir / f"{base}.html"
        md_path.write_text(self.markdown(record), encoding="utf-8")
        html_path.write_text(self.html(record), encoding="utf-8")
        return md_path, html_path

    def markdown(self, record: ScanRecord) -> str:
        confirmed = self._sort(record.confirmed_findings)
        discarded = self._sort(record.discarded_findings)
        observed = self._sort(record.observed_findings)
        lines: list[str] = [
            f"# Vulnerability Assessment Report - {record.target.display}",
            "",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "**Confidentiality:** Confidential",
            f"**Workspace:** `{record.workspace}`",
            "",
            "## Executive Summary",
            "",
            self._executive_summary(confirmed, discarded, observed),
            "",
            "### Risk Overview",
            "",
            "| Severity | Confirmed | Observed | Discarded |",
            "|---|---:|---:|---:|",
        ]
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            lines.append(
                f"| {severity} | {self._count(confirmed, severity)} | {self._count(observed, severity)} | {self._count(discarded, severity)} |"
            )
        lines.extend(
            [
                "",
                "## Scope and Methodology",
                "",
                f"- Target: `{record.target.raw}`",
                f"- Resolved host/IP: `{record.target.host}` / `{record.target.ip or 'unresolved'}`",
                "- Methodology: Nmap discovery, service/version detection, service-specific enumeration, web fingerprinting, Nuclei template validation, Nikto web checks, and auditor-controlled review.",
                "- Raw outputs: every command output is stored under `raw_outputs/` inside the scan workspace.",
                "",
                "### Services Identified",
                "",
                "| Port | Protocol | Service | Product | Version |",
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

        lines.extend(["", "## Confirmed Vulnerabilities", ""])
        lines.extend(self._markdown_findings(confirmed, empty="No confirmed vulnerabilities were added by the auditor."))

        if observed:
            lines.extend(["", "## Observed Findings Pending Manual Review", ""])
            lines.extend(self._markdown_findings(observed, empty=""))

        lines.extend(["", "## Appendix - Discarded False Positives", ""])
        if discarded:
            lines.extend(["| Tool | Severity | Title | Auditor Note |", "|---|---|---|---|"])
            for finding in discarded:
                lines.append(
                    f"| {finding.tool} | {finding.severity} | {clean_text(finding.title, 120)} | {clean_text(finding.auditor_note, 160)} |"
                )
        else:
            lines.append("No findings were discarded.")
        lines.append("")
        return "\n".join(lines)

    def html(self, record: ScanRecord) -> str:
        md_summary = html.escape(self._executive_summary(record.confirmed_findings, record.discarded_findings, record.observed_findings))
        confirmed = self._sort(record.confirmed_findings)
        observed = self._sort(record.observed_findings)
        discarded = self._sort(record.discarded_findings)
        parts = [
            "<!doctype html><html><head><meta charset='utf-8'>",
            f"<title>Vulnerability Assessment - {html.escape(record.target.display)}</title>",
            f"<style>{HTML_STYLE}</style></head><body>",
            f"<h1>Vulnerability Assessment Report - {html.escape(record.target.display)}</h1>",
            f"<p class='meta'>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>Workspace: {html.escape(record.workspace)}</p>",
            "<h2>Executive Summary</h2>",
            f"<p>{md_summary}</p>",
            "<h3>Risk Overview</h3>",
            "<table><tr><th>Severity</th><th>Confirmed</th><th>Observed</th><th>Discarded</th></tr>",
        ]
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            parts.append(
                f"<tr><td class='sev-{severity}'>{severity}</td><td>{self._count(confirmed, severity)}</td><td>{self._count(observed, severity)}</td><td>{self._count(discarded, severity)}</td></tr>"
            )
        parts.extend(
            [
                "</table>",
                "<h2>Scope and Methodology</h2>",
                "<ul>",
                f"<li>Target: <code>{html.escape(record.target.raw)}</code></li>",
                f"<li>Resolved host/IP: <code>{html.escape(record.target.host)}</code> / <code>{html.escape(record.target.ip or 'unresolved')}</code></li>",
                "<li>Methodology: Nmap discovery, service/version detection, service-specific enumeration, web fingerprinting, Nuclei template validation, Nikto web checks, and auditor-controlled review.</li>",
                "</ul>",
                "<h3>Services Identified</h3>",
                "<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>",
            ]
        )
        if record.services:
            for service in sorted(record.services, key=lambda item: (item.protocol, item.port)):
                parts.append(
                    f"<tr><td>{service.port}</td><td>{html.escape(service.protocol)}</td><td>{html.escape(service.name or '-')}</td><td>{html.escape(service.product or '-')}</td><td>{html.escape(service.version or '-')}</td></tr>"
                )
        else:
            parts.append("<tr><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>")
        parts.extend(["</table>", "<h2>Confirmed Vulnerabilities</h2>"])
        parts.extend(self._html_findings(confirmed, "No confirmed vulnerabilities were added by the auditor."))
        if observed:
            parts.append("<h2>Observed Findings Pending Manual Review</h2>")
            parts.extend(self._html_findings(observed, ""))
        parts.append("<h2>Appendix - Discarded False Positives</h2>")
        if discarded:
            parts.append("<table><tr><th>Tool</th><th>Severity</th><th>Title</th><th>Auditor Note</th></tr>")
            for finding in discarded:
                parts.append(
                    f"<tr><td>{html.escape(finding.tool)}</td><td>{html.escape(finding.severity)}</td><td>{html.escape(finding.title)}</td><td>{html.escape(finding.auditor_note)}</td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p>No findings were discarded.</p>")
        parts.append("</body></html>")
        return "\n".join(parts)

    def _markdown_findings(self, findings: list[Finding], empty: str) -> list[str]:
        if not findings:
            return [empty] if empty else []
        lines: list[str] = []
        for index, finding in enumerate(findings, 1):
            lines.extend(
                [
                    f"### {index}. [{finding.severity}] {finding.title}",
                    "",
                    f"- Tool: `{finding.tool}`",
                    f"- IP / URL: `{finding.ip or '-'}` / `{finding.url or '-'}`",
                    f"- Port / Service: `{finding.port or '-'}` / `{finding.service or '-'}`",
                    f"- CVE / CWE: `{finding.cve or '-'}` / `{finding.cwe or '-'}`",
                    f"- CVSS: `{finding.cvss or '-'}`",
                    f"- Raw Output: `{finding.raw_output_path or '-'}`",
                    "",
                    "**Technical Description**",
                    "",
                    finding.description or finding.title,
                    "",
                    "**Evidence**",
                    "",
                    "```text",
                    finding.evidence or "-",
                    "```",
                    "",
                    "**Auditor Notes**",
                    "",
                    finding.auditor_note or "-",
                    "",
                    "**Remediation**",
                    "",
                    finding.recommendation or "Validate the finding, patch the affected component, and reduce service exposure.",
                    "",
                ]
            )
        return lines

    def _html_findings(self, findings: list[Finding], empty: str) -> list[str]:
        if not findings:
            return [f"<p>{html.escape(empty)}</p>"] if empty else []
        parts: list[str] = []
        for index, finding in enumerate(findings, 1):
            parts.extend(
                [
                    f"<h3>{index}. <span class='sev-{finding.severity}'>[{html.escape(finding.severity)}]</span> {html.escape(finding.title)}</h3>",
                    "<table>",
                    f"<tr><th>Tool</th><td>{html.escape(finding.tool)}</td></tr>",
                    f"<tr><th>IP / URL</th><td><code>{html.escape(finding.ip or '-')}</code> / <code>{html.escape(finding.url or '-')}</code></td></tr>",
                    f"<tr><th>Port / Service</th><td>{html.escape(finding.port or '-')} / {html.escape(finding.service or '-')}</td></tr>",
                    f"<tr><th>CVE / CWE</th><td>{html.escape(finding.cve or '-')} / {html.escape(finding.cwe or '-')}</td></tr>",
                    f"<tr><th>Raw Output</th><td><code>{html.escape(finding.raw_output_path or '-')}</code></td></tr>",
                    "</table>",
                    f"<p><strong>Technical Description:</strong> {html.escape(finding.description or finding.title)}</p>",
                    f"<pre>{html.escape(finding.evidence or '-')}</pre>",
                    f"<p><strong>Auditor Notes:</strong> {html.escape(finding.auditor_note or '-')}</p>",
                    f"<p><strong>Remediation:</strong> {html.escape(finding.recommendation or 'Validate the finding, patch the affected component, and reduce service exposure.')}</p>",
                ]
            )
        return parts

    def _executive_summary(self, confirmed: list[Finding], discarded: list[Finding], observed: list[Finding]) -> str:
        counts = Counter(f.severity for f in confirmed)
        total = len(confirmed)
        if total:
            sev_text = ", ".join(f"{counts[s]} {s}" for s in ["Critical", "High", "Medium", "Low", "Info"] if counts[s])
            return (
                f"The assessment identified {total} auditor-confirmed finding(s): {sev_text}. "
                f"{len(discarded)} potential finding(s) were discarded as false positives. "
                f"{len(observed)} lower-priority finding(s) were observed without interrupting execution."
            )
        return (
            "No auditor-confirmed vulnerabilities were added during this run. "
            f"{len(discarded)} finding(s) were discarded and {len(observed)} finding(s) remain as observations."
        )

    def _sort(self, findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.tool, item.title))

    def _count(self, findings: list[Finding], severity: str) -> int:
        return sum(1 for finding in findings if finding.severity == severity)
