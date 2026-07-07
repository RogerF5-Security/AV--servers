from __future__ import annotations

from collections import OrderedDict
from datetime import datetime
from pathlib import Path
import shutil
import subprocess
from typing import Callable
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from parsers import enum4linux, nikto, nmap, nuclei, searchsploit, smbmap, sslscan, visual, whatweb
from reporting.generator import ReportGenerator

from .config import ScanConfig
from .delta import compare_record_with_previous
from .fuser import VulnerabilityFuser
from .identity import IdentityDetector
from .interactive import InteractiveReview
from .models import AuditIdentity, CommandResult, Finding, ScanRecord, Service, Target
from .runner import CommandRunner, ToolUnavailable
from .workspace import ScanWorkspace


class ScanOrchestrator:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.console = Console()
        self.runner = CommandRunner(timeout=config.command_timeout)
        self.review = InteractiveReview(config.interactive, config.pause_severities)
        self.reporter = ReportGenerator()
        self.fuser = VulnerabilityFuser()

    def scan_targets(self, targets: list[Target]) -> list[ScanRecord]:
        campaign_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        identity = IdentityDetector.detect()
        self._print_audit_identity(identity, targets)
        records: list[ScanRecord] = []
        for target in targets:
            records.append(self.scan_target(target, campaign_id))
        finished_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z%z")
        self._write_campaign_summary(records, identity, finished_at)
        final_md, final_html = self.reporter.write_campaign(
            records=records,
            scans_dir=self.config.repo_root / "scans",
            identity=identity,
            campaign_id=campaign_id,
            finished_at=finished_at,
        )
        self.console.print(f"[bold green]Reporte final consolidado:[/bold green] {final_md} | {final_html}")
        return records

    def scan_target(self, target: Target, campaign_id: str | None = None) -> ScanRecord:
        workspace = ScanWorkspace(self.config.repo_root, target, timestamp=campaign_id)
        workspace.prepare()
        record = ScanRecord(target=target, workspace=str(workspace.root))
        seen_findings: set[str] = set()

        self.console.rule(f"[bold cyan]Objetivo: {target.display}[/bold cyan]")

        def handle_finding(finding: Finding) -> None:
            if finding.fingerprint in seen_findings:
                return
            seen_findings.add(finding.fingerprint)
            reviewed = self.review.review(finding, workspace)
            if reviewed.status == "confirmed":
                record.confirmed_findings.append(reviewed)
            elif reviewed.status == "discarded":
                record.discarded_findings.append(reviewed)
            else:
                record.observed_findings.append(reviewed)
            workspace.save_state(record)

        self._run_nmap_discovery(target, workspace, record, handle_finding)
        service_xml = self._run_nmap_services(target, workspace, record, handle_finding)
        if service_xml:
            self._run_searchsploit(target, workspace, record, service_xml, handle_finding)
        self._run_nmap_vuln_scripts(target, workspace, record, handle_finding)
        self._run_nmap_deep_service_scripts(target, workspace, record, handle_finding)
        if self.config.profile == "deep":
            self._run_nmap_udp_deep_scripts(target, workspace, record, handle_finding)
        self._run_sslscan_modules(target, workspace, record, handle_finding)
        self._run_smb_modules(target, workspace, record, handle_finding)
        self._run_web_modules(target, workspace, record, handle_finding)
        self._run_visual_modules(target, workspace, record)
        self._run_auxiliary_modules(target, workspace, record, handle_finding)

        self._fuse_record_findings(record)
        self._apply_delta(record)
        md_path, html_path = self.reporter.write(record, workspace.reports)
        workspace.save_state(record)
        self.console.print(f"[green]Reportes generados:[/green] {md_path} | {html_path}")
        return record

    def _run_nmap_discovery(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> Path | None:
        if not self.config.tool_enabled("nmap"):
            return None
        xml_path = workspace.raw_path("nmap", "discovery", "xml")
        log_path = workspace.raw_path("nmap", "discovery", "log")
        try:
            nmap_bin = self.runner.require("nmap")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}. Se omite Nmap para este objetivo.[/yellow]")
            return
        command = [nmap_bin, *self.config.nmap_discovery_args, "-oX", str(xml_path), target.scan_host]
        result = self._run_command(
            target=target,
            workspace=workspace,
            record=record,
            tool="nmap",
            profile="discovery",
            command=command,
            raw_output_path=log_path,
            line_parser=lambda line, raw: self._with_raw(nmap.parse_line(line, target), raw),
            handle_finding=handle_finding,
        )
        if self._needs_nmap_tcp_fallback(result):
            self._log_result(result, workspace)
            self.console.print("[yellow]Nmap SYN scan requiere privilegios. Reintentando discovery con -sT.[/yellow]")
            fallback_xml = workspace.raw_path("nmap", "discovery_fallback_sT", "xml")
            fallback_log = workspace.raw_path("nmap", "discovery_fallback_sT", "log")
            fallback_args = ["-sT" if arg == "-sS" else arg for arg in self.config.nmap_discovery_args]
            command = [nmap_bin, *fallback_args, "-oX", str(fallback_xml), target.scan_host]
            result = self._run_command(
                target=target,
                workspace=workspace,
                record=record,
                tool="nmap",
                profile="discovery_fallback_sT",
                command=command,
                raw_output_path=fallback_log,
                line_parser=lambda line, raw: self._with_raw(nmap.parse_line(line, target), raw),
                handle_finding=handle_finding,
            )
            xml_path = fallback_xml
        if xml_path.exists():
            services, findings = nmap.parse_services(xml_path.read_text(encoding="utf-8", errors="ignore"), target)
            self._merge_services(record, services)
            for finding in findings:
                finding.raw_output_path = str(xml_path)
                handle_finding(finding)
        self._log_result(result, workspace)

    def _run_nmap_services(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        if not self.config.tool_enabled("nmap"):
            return
        ports = ",".join(str(service.port) for service in sorted(record.services, key=lambda item: item.port))
        profile = "servicios_detectados"
        if not ports and self.config.fallback_common_checks:
            ports = self.config.fallback_service_ports
            profile = "servicios_comunes"
        if not ports:
            return None
        xml_path = workspace.raw_path("nmap", profile, "xml")
        log_path = workspace.raw_path("nmap", profile, "log")
        try:
            nmap_bin = self.runner.require("nmap")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}. Se omite deteccion de servicios.[/yellow]")
            return None
        command = [nmap_bin, *self.config.nmap_service_args, "-p", ports, "-oX", str(xml_path), target.scan_host]
        result = self._run_command(
            target=target,
            workspace=workspace,
            record=record,
            tool="nmap",
            profile=profile,
            command=command,
            raw_output_path=log_path,
            line_parser=lambda line, raw: self._with_raw(nmap.parse_line(line, target), raw),
            handle_finding=handle_finding,
        )
        if xml_path.exists():
            services, findings = nmap.parse_services(xml_path.read_text(encoding="utf-8", errors="ignore"), target)
            self._merge_services(record, services)
            for finding in findings:
                finding.raw_output_path = str(xml_path)
                handle_finding(finding)
        self._log_result(result, workspace)
        return xml_path if xml_path.exists() else None

    def _run_nmap_vuln_scripts(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        if not self.config.include_nmap_vuln or not self.config.tool_enabled("nmap"):
            return
        ports = ",".join(str(service.port) for service in sorted(record.services, key=lambda item: item.port))
        if not ports and self.config.fallback_common_checks:
            ports = self.config.fallback_service_ports
        if not ports:
            return
        xml_path = workspace.raw_path("nmap", "vuln_scripts", "xml")
        log_path = workspace.raw_path("nmap", "vuln_scripts", "log")
        try:
            nmap_bin = self.runner.require("nmap")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}. Se omite Nmap vuln.[/yellow]")
            return
        command = [
            nmap_bin,
            "-sV",
            "--version-all",
            "-Pn",
            "--script",
            "vuln",
            "--script-timeout",
            "60s",
            "-p",
            ports,
            "-oX",
            str(xml_path),
            target.scan_host,
        ]
        result = self._run_command(
            target=target,
            workspace=workspace,
            record=record,
            tool="nmap",
            profile="vuln_scripts",
            command=command,
            raw_output_path=log_path,
            line_parser=lambda line, raw: self._with_raw(nmap.parse_line(line, target), raw),
            handle_finding=handle_finding,
        )
        if xml_path.exists():
            services, findings = nmap.parse_services(xml_path.read_text(encoding="utf-8", errors="ignore"), target)
            self._merge_services(record, services)
            for finding in findings:
                finding.raw_output_path = str(xml_path)
                handle_finding(finding)
        self._log_result(result, workspace)

    def _run_searchsploit(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        nmap_xml: Path,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        if not self.config.include_searchsploit or not self.config.tool_enabled("searchsploit"):
            return
        try:
            binary = self.runner.require("searchsploit")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}. Se omite correlacion Exploit-DB.[/yellow]")
            return
        raw_path = workspace.raw_path("searchsploit", "nmap_xml", "log")
        command = [binary, "--nmap", str(nmap_xml)]
        result = self._run_command(
            target=target,
            workspace=workspace,
            record=record,
            tool="searchsploit",
            profile="nmap_xml",
            command=command,
            raw_output_path=raw_path,
            line_parser=lambda line, raw: self._with_raw(searchsploit.parse_line(line, target), raw),
            handle_finding=handle_finding,
        )
        self._log_result(result, workspace)

    def _run_nmap_deep_service_scripts(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        if not self.config.tool_enabled("nmap"):
            return
        port_set = {service.port for service in record.services}
        if not port_set and self.config.fallback_common_checks:
            port_set = {int(port) for port in self.config.fallback_service_ports.split(",") if port.strip().isdigit()}
        profiles: list[tuple[str, set[int], str]] = [
            (
                "smb_deep",
                {139, 445},
                "smb-security-mode,smb2-security-mode,smb2-capabilities,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve2009-3103,smb-vuln-ms10-054,smb-vuln-ms10-061",
            ),
            (
                "web_deep",
                {80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443},
                "http-security-headers,http-methods,http-server-header,http-title,http-robots.txt,http-git,http-config-backup",
            ),
            (
                "tls_deep",
                {443, 465, 587, 636, 993, 995, 8443, 9443},
                "ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params,tls-alpn",
            ),
            ("ftp_deep", {21}, "ftp-anon,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor"),
            ("ssh_deep", {22}, "ssh2-enum-algos,ssh-hostkey"),
            ("rdp_deep", {3389}, "rdp-enum-encryption,rdp-ntlm-info"),
            ("smtp_deep", {25, 465, 587}, "smtp-open-relay,smtp-commands,smtp-vuln-cve2010-4344"),
            ("mysql_deep", {3306}, "mysql-info,mysql-empty-password,mysql-vuln-cve2012-2122"),
            ("mssql_deep", {1433}, "ms-sql-info,ms-sql-empty-password"),
            ("postgres_deep", {5432}, "pgsql-empty-password"),
            ("redis_deep", {6379}, "redis-info"),
            ("docker_deep", {2375}, "docker-version"),
            ("vnc_deep", {5900}, "vnc-info,realvnc-auth-bypass"),
        ]
        try:
            nmap_bin = self.runner.require("nmap")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}. Se omiten scripts profundos Nmap.[/yellow]")
            return
        for profile, candidate_ports, scripts in profiles:
            selected = sorted(port_set.intersection(candidate_ports))
            if not selected:
                continue
            ports = ",".join(str(port) for port in selected)
            xml_path = workspace.raw_path("nmap", profile, "xml")
            log_path = workspace.raw_path("nmap", profile, "log")
            command = [
                nmap_bin,
                "-sV",
                "--version-all",
                "-Pn",
                "--script",
                scripts,
                "--script-timeout",
                "90s",
                "-p",
                ports,
                "-oX",
                str(xml_path),
                target.scan_host,
            ]
            result = self._run_command(
                target=target,
                workspace=workspace,
                record=record,
                tool="nmap",
                profile=profile,
                command=command,
                raw_output_path=log_path,
                line_parser=lambda line, raw: self._with_raw(nmap.parse_line(line, target), raw),
                handle_finding=handle_finding,
            )
            if xml_path.exists():
                services, findings = nmap.parse_services(xml_path.read_text(encoding="utf-8", errors="ignore"), target)
                self._merge_services(record, services)
                for finding in findings:
                    finding.raw_output_path = str(xml_path)
                    handle_finding(finding)
            self._log_result(result, workspace)

    def _run_nmap_udp_deep_scripts(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        if not self.config.tool_enabled("nmap"):
            return
        try:
            nmap_bin = self.runner.require("nmap")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}. Se omite perfil UDP profundo.[/yellow]")
            return
        xml_path = workspace.raw_path("nmap", "udp_deep", "xml")
        log_path = workspace.raw_path("nmap", "udp_deep", "log")
        command = [
            nmap_bin,
            "-sU",
            "-Pn",
            "--max-retries",
            "2",
            "--script",
            "dns-recursion,ntp-info,snmp-info,snmp-sysdescr",
            "--script-timeout",
            "60s",
            "-p",
            "53,123,161",
            "-oX",
            str(xml_path),
            target.scan_host,
        ]
        result = self._run_command(
            target=target,
            workspace=workspace,
            record=record,
            tool="nmap",
            profile="udp_deep",
            command=command,
            raw_output_path=log_path,
            line_parser=lambda line, raw: self._with_raw(nmap.parse_line(line, target), raw),
            handle_finding=handle_finding,
        )
        if xml_path.exists():
            services, findings = nmap.parse_services(xml_path.read_text(encoding="utf-8", errors="ignore"), target)
            self._merge_services(record, services)
            for finding in findings:
                finding.raw_output_path = str(xml_path)
                handle_finding(finding)
        self._log_result(result, workspace)

    def _run_smb_modules(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        should_probe_smb = any(service.port in {139, 445} for service in record.services)
        if not should_probe_smb and not (self.config.fallback_common_checks and not record.services):
            return
        if self.config.tool_enabled("smbmap"):
            self._run_simple_parser(
                target=target,
                workspace=workspace,
                record=record,
                tool="smbmap",
                profile="smb_shares",
                command_builder=lambda binary: [binary, "-H", target.scan_host],
                parser=lambda line, raw: self._with_raw(smbmap.parse_line(line, target), raw),
                handle_finding=handle_finding,
            )
        if self.config.tool_enabled("enum4linux-ng"):
            self._run_simple_parser(
                target=target,
                workspace=workspace,
                record=record,
                tool="enum4linux-ng",
                profile="smb_enum",
                command_builder=lambda binary: [binary, target.scan_host],
                parser=lambda line, raw: self._with_raw(enum4linux.parse_line(line, target), raw),
                handle_finding=handle_finding,
            )

    def _run_sslscan_modules(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        if not self.config.include_sslscan or not self.config.tool_enabled("sslscan"):
            return
        try:
            binary = self.runner.require("sslscan")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}. Se omite auditoria TLS/SSL.[/yellow]")
            return
        supports_json = self._sslscan_supports_json(binary)
        for service in self._tls_services(record.services):
            endpoint = service.endpoint
            structured_path = workspace.raw_path("sslscan", f"{service.port}", "json" if supports_json else "xml")
            log_path = workspace.raw_path("sslscan", f"{service.port}", "log")
            command = [binary, "--no-failed", "--show-certificate"]
            if supports_json:
                command.append("--json")
            else:
                command.append(f"--xml={structured_path}")
            starttls = self._sslscan_starttls_flag(service)
            if starttls:
                command.append(starttls)
            if service.port == 3389:
                command.append("--rdp")
            if target.host and target.host != target.scan_host:
                command.extend(["--sni-name", target.host])
            command.append(f"{target.scan_host}:{service.port}")
            result = self._run_command(
                target=target,
                workspace=workspace,
                record=record,
                tool="sslscan",
                profile=f"{service.port}",
                command=command,
                raw_output_path=log_path,
                line_parser=None,
                handle_finding=handle_finding,
            )
            findings: list[Finding] = []
            if supports_json:
                structured_path.write_text(result.stdout, encoding="utf-8", errors="ignore")
                findings.extend(sslscan.parse_json_text(result.stdout, target, endpoint, str(structured_path)))
            elif structured_path.exists():
                findings.extend(sslscan.parse_xml(structured_path.read_text(encoding="utf-8", errors="ignore"), target, endpoint, str(structured_path)))
            if not findings:
                findings.extend(sslscan.parse_text(result.stdout, target, endpoint, str(log_path)))
            for finding in findings:
                handle_finding(finding)
            self._log_result(result, workspace)

    def _run_web_modules(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        for url in self._web_urls(target, record.services):
            safe_profile = url.replace("://", "_").replace("/", "_").replace(":", "_")
            if self.config.tool_enabled("whatweb"):
                self._run_simple_parser(
                    target=target,
                    workspace=workspace,
                    record=record,
                    tool="whatweb",
                    profile=safe_profile,
                    command_builder=lambda binary, url=url: [binary, "--color=never", url],
                    parser=lambda line, raw, url=url: self._with_raw(whatweb.parse_line(line, target, url), raw),
                    handle_finding=handle_finding,
                )
            if self.config.tool_enabled("nuclei"):
                self._run_simple_parser(
                    target=target,
                    workspace=workspace,
                    record=record,
                    tool="nuclei",
                    profile=f"{safe_profile}_auto",
                    command_builder=lambda binary, url=url: [
                        binary,
                        "-u",
                        url,
                        "-as",
                        "-severity",
                        self.config.nuclei_severity,
                        "-jsonl",
                        "-silent",
                        "-no-color",
                    ],
                    parser=lambda line, raw: self._with_raw(nuclei.parse_json_line(line, target), raw),
                    handle_finding=handle_finding,
                )
                self._run_simple_parser(
                    target=target,
                    workspace=workspace,
                    record=record,
                    tool="nuclei",
                    profile=f"{safe_profile}_templates",
                    command_builder=lambda binary, url=url: [
                        binary,
                        "-u",
                        url,
                        *self._nuclei_template_args(),
                        "-severity",
                        self.config.nuclei_severity,
                        "-jsonl",
                        "-silent",
                        "-no-color",
                    ],
                    parser=lambda line, raw: self._with_raw(nuclei.parse_json_line(line, target), raw),
                    handle_finding=handle_finding,
                )
            if self.config.include_nikto and self.config.tool_enabled("nikto"):
                self._run_simple_parser(
                    target=target,
                    workspace=workspace,
                    record=record,
                    tool="nikto",
                    profile=safe_profile,
                    command_builder=lambda binary, url=url: [binary, "-h", url, "-nointeractive"],
                    parser=lambda line, raw, url=url: self._with_raw(nikto.parse_line(line, target, url), raw),
                    handle_finding=handle_finding,
                )

    def _run_visual_modules(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
    ) -> None:
        if not self.config.include_visual or not self.config.tool_enabled("gowitness"):
            return
        urls = self._web_urls(target, record.services)
        if not urls:
            return
        try:
            binary = self.runner.require("gowitness")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}. Se omiten capturas web.[/yellow]")
            return
        for url in urls:
            parsed = urlparse(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            expected = workspace.screenshot_path(url, port)
            before = {path.resolve() for path in workspace.screenshots.glob("*.png")}
            profile = f"screenshot_{port}_{parsed.scheme or 'http'}"
            log_path = workspace.raw_path("gowitness", profile, "log")
            command = [
                binary,
                "scan",
                "single",
                "-u",
                url,
                "--screenshot-path",
                str(workspace.screenshots),
                "--timeout",
                str(self.config.visual_timeout),
            ]
            result = self._run_command(
                target=target,
                workspace=workspace,
                record=record,
                tool="gowitness",
                profile=profile,
                command=command,
                raw_output_path=log_path,
                line_parser=None,
                handle_finding=lambda finding: None,
            )
            screenshot = self._latest_new_screenshot(workspace.screenshots, before)
            if screenshot and screenshot.exists():
                if screenshot.resolve() != expected.resolve():
                    expected.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(screenshot, expected)
                record.visual_evidence.append(
                    visual.build_evidence(
                        target=target,
                        url=url,
                        screenshot_path=expected,
                        raw_output_path=log_path,
                        port=f"{port}/tcp",
                        output=result.stdout,
                    )
                )
            self._log_result(result, workspace)

    def _run_auxiliary_modules(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        if not self.config.include_auxiliary_nmap or not self.config.tool_enabled("nmap"):
            return
        scripts_by_port = {
            21: "ftp-anon,ftp-syst",
            3389: "rdp-enum-encryption",
            5985: "http-title,http-server-header",
            5986: "ssl-cert,http-title,http-server-header",
        }
        for service in record.services:
            scripts = scripts_by_port.get(service.port)
            if not scripts:
                continue
            xml_path = workspace.raw_path("nmap", f"aux_{service.port}", "xml")
            log_path = workspace.raw_path("nmap", f"aux_{service.port}", "log")
            try:
                nmap_bin = self.runner.require("nmap")
            except ToolUnavailable:
                return
            command = [nmap_bin, "-Pn", "-sV", "-p", str(service.port), "--script", scripts, "-oX", str(xml_path), target.scan_host]
            result = self._run_command(
                target=target,
                workspace=workspace,
                record=record,
                tool="nmap",
                profile=f"aux_{service.port}",
                command=command,
                raw_output_path=log_path,
                line_parser=lambda line, raw: self._with_raw(nmap.parse_line(line, target), raw),
                handle_finding=handle_finding,
            )
            if xml_path.exists():
                _, findings = nmap.parse_services(xml_path.read_text(encoding="utf-8", errors="ignore"), target)
                for finding in findings:
                    finding.raw_output_path = str(xml_path)
                    handle_finding(finding)
            self._log_result(result, workspace)

    def _run_simple_parser(
        self,
        *,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        tool: str,
        profile: str,
        command_builder: Callable[[str], list[str]],
        parser: Callable[[str, str], list[Finding]],
        handle_finding: Callable[[Finding], None],
    ) -> None:
        try:
            binary = self.runner.require(tool)
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}. Se omite {tool}.[/yellow]")
            return
        raw_path = workspace.raw_path(tool, profile, "log")
        command = command_builder(binary)
        result = self._run_command(
            target=target,
            workspace=workspace,
            record=record,
            tool=tool,
            profile=profile,
            command=command,
            raw_output_path=raw_path,
            line_parser=parser,
            handle_finding=handle_finding,
        )
        self._log_result(result, workspace)

    def _run_command(
        self,
        *,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        tool: str,
        profile: str,
        command: list[str],
        raw_output_path: Path,
        line_parser: Callable[[str, str], list[Finding]] | None,
        handle_finding: Callable[[Finding], None],
    ) -> CommandResult:
        self.console.print(f"[cyan]Ejecutando[/cyan] {tool}:{profile} -> {target.display}")
        result = self.runner.run(
            tool=tool,
            profile=profile,
            command=command,
            raw_output_path=raw_output_path,
            timeout=self.config.command_timeout,
            line_parser=line_parser,
            finding_handler=handle_finding,
        )
        record.commands.append(result)
        workspace.save_state(record)
        if result.timed_out:
            self.console.print(f"[yellow]Timeout[/yellow] {tool}:{profile}")
        elif result.returncode not in {0, None}:
            self.console.print(f"[yellow]Salida {result.returncode}[/yellow] {tool}:{profile}")
        return result

    def _with_raw(self, findings: list[Finding], raw_path: str) -> list[Finding]:
        for finding in findings:
            finding.raw_output_path = raw_path
        return findings

    def _merge_services(self, record: ScanRecord, services: list[Service]) -> None:
        merged: "OrderedDict[tuple[str, int, str], Service]" = OrderedDict()
        for service in [*record.services, *services]:
            key = (service.protocol, service.port, service.host)
            current = merged.get(key)
            if current is None or len(service.label) > len(current.label):
                merged[key] = service
        record.services = list(merged.values())

    def _web_urls(self, target: Target, services: list[Service]) -> list[str]:
        urls: OrderedDict[str, None] = OrderedDict()
        if target.url:
            urls[target.url] = None
        web_ports = {80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443}
        for service in services:
            label = service.label.lower()
            if service.port not in web_ports and "http" not in label and "www" not in label:
                continue
            scheme = "https" if service.port in {443, 8443, 9443} or service.tunnel == "ssl" or "https" in label else "http"
            default = (scheme == "http" and service.port == 80) or (scheme == "https" and service.port == 443)
            port_part = "" if default else f":{service.port}"
            urls[f"{scheme}://{target.host or target.scan_host}{port_part}"] = None
        if not urls and self.config.fallback_common_checks:
            host = target.host or target.scan_host
            urls[f"http://{host}"] = None
            urls[f"https://{host}"] = None
        return list(urls.keys())

    def _tls_services(self, services: list[Service]) -> list[Service]:
        tls_ports = {443, 465, 587, 636, 993, 995, 8443, 9443, 5986, 3389}
        starttls_ports = {21, 25, 110, 143, 389, 587}
        selected: "OrderedDict[tuple[str, int, str], Service]" = OrderedDict()
        for service in services:
            label = service.label.lower()
            if service.port in tls_ports or service.port in starttls_ports or service.tunnel == "ssl" or "ssl" in label or "tls" in label or "https" in label:
                selected[(service.protocol, service.port, service.host)] = service
        return list(selected.values())

    def _sslscan_starttls_flag(self, service: Service) -> str:
        label = service.label.lower()
        if service.port in {25, 587} or "smtp" in label:
            return "--starttls-smtp"
        if service.port == 110 or "pop3" in label:
            return "--starttls-pop3"
        if service.port == 143 or "imap" in label:
            return "--starttls-imap"
        if service.port == 21 or "ftp" in label:
            return "--starttls-ftp"
        if service.port == 389 or "ldap" in label:
            return "--starttls-ldap"
        return ""

    def _sslscan_supports_json(self, binary: str) -> bool:
        try:
            result = subprocess.run([binary, "--help"], capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=5)
        except Exception:
            return False
        return "--json" in f"{result.stdout}\n{result.stderr}"

    def _latest_new_screenshot(self, screenshot_dir: Path, before: set[Path]) -> Path | None:
        candidates = [path for path in screenshot_dir.glob("*.png") if path.resolve() not in before]
        if not candidates:
            return None
        return max(candidates, key=lambda item: item.stat().st_mtime)

    def _fuse_record_findings(self, record: ScanRecord) -> None:
        record.confirmed_findings = self.fuser.fuse(record.confirmed_findings)
        record.observed_findings = self.fuser.fuse(record.observed_findings)
        record.discarded_findings = self.fuser.fuse(record.discarded_findings)

    def _apply_delta(self, record: ScanRecord) -> None:
        if not self.config.compare_previous:
            return
        record.delta_summary = compare_record_with_previous(record, self.config.compare_previous)

    def _nuclei_template_args(self) -> list[str]:
        templates = [item.strip() for item in self.config.nuclei_templates.split(",") if item.strip()]
        args: list[str] = []
        for template in templates:
            args.extend(["-t", self._resolve_nuclei_template(template)])
        return args

    def _resolve_nuclei_template(self, template: str) -> str:
        candidate = Path(template).expanduser()
        if candidate.is_absolute() and candidate.exists():
            return str(candidate)
        bases = [
            Path.home() / ".local" / "nuclei-templates",
            Path.home() / "nuclei-templates",
            self.config.repo_root / "nuclei-templates",
        ]
        for base in bases:
            resolved = base / template
            if resolved.exists():
                return str(resolved)
        return template

    def _needs_nmap_tcp_fallback(self, result: CommandResult) -> bool:
        if result.returncode in {0, None}:
            return False
        text = f"{result.stdout}\n{result.stderr}".lower()
        return "-ss" in " ".join(result.command).lower() and (
            "requires root privileges" in text
            or "you requested a scan type which requires root privileges" in text
            or "root privileges" in text
        )

    def _log_result(self, result: CommandResult, workspace: ScanWorkspace) -> None:
        workspace.append_command(result.to_dict())

    def _print_audit_identity(self, identity: AuditIdentity, targets: list[Target]) -> None:
        table = Table(show_header=False, box=None)
        table.add_row("[bold]Fecha/hora de inicio[/bold]", identity.started_at)
        table.add_row("[bold]Hostname[/bold]", identity.hostname or "-")
        table.add_row("[bold]Usuario local[/bold]", identity.username or "-")
        table.add_row("[bold]Interfaz origen[/bold]", identity.interface or "-")
        table.add_row("[bold]IP origen para whitelist SOC[/bold]", identity.source_ip or "-")
        table.add_row("[bold]MAC origen para whitelist SOC[/bold]", identity.source_mac or "-")
        table.add_row("[bold]Objetivos cargados[/bold]", str(len(targets)))
        self.console.print(Panel(table, title="Identidad de ejecucion para SOC", border_style="cyan"))

    def _write_campaign_summary(self, records: list[ScanRecord], identity: AuditIdentity, finished_at: str) -> None:
        if not records:
            return
        summary_dir = self.config.repo_root / "scans"
        summary_dir.mkdir(parents=True, exist_ok=True)
        path = summary_dir / "latest_campaign_summary.md"
        lines = [
            "# Resumen de la Ultima Campana",
            "",
            f"- Inicio: `{identity.started_at}`",
            f"- Fin: `{finished_at}`",
            f"- IP origen SOC: `{identity.source_ip}`",
            f"- MAC origen SOC: `{identity.source_mac}`",
            f"- Interfaz origen: `{identity.interface}`",
            "",
            "| Objetivo | Confirmados | Observados | Descartados | Workspace |",
            "|---|---:|---:|---:|---|",
        ]
        for record in records:
            lines.append(
                f"| {record.target.display} | {len(record.confirmed_findings)} | {len(record.observed_findings)} | {len(record.discarded_findings)} | `{record.workspace}` |"
            )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
