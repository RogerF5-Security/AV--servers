from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Callable

from rich.console import Console

from parsers import enum4linux, nikto, nmap, nuclei, smbmap, whatweb
from reporting.generator import ReportGenerator

from .config import ScanConfig
from .interactive import InteractiveReview
from .models import CommandResult, Finding, ScanRecord, Service, Target
from .runner import CommandRunner, ToolUnavailable
from .workspace import ScanWorkspace


class ScanOrchestrator:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.console = Console()
        self.runner = CommandRunner(timeout=config.command_timeout)
        self.review = InteractiveReview(config.interactive, config.pause_severities)
        self.reporter = ReportGenerator()

    def scan_targets(self, targets: list[Target]) -> list[ScanRecord]:
        records: list[ScanRecord] = []
        for target in targets:
            records.append(self.scan_target(target))
        self._write_campaign_summary(records)
        return records

    def scan_target(self, target: Target) -> ScanRecord:
        workspace = ScanWorkspace(self.config.repo_root, target)
        workspace.prepare()
        record = ScanRecord(target=target, workspace=str(workspace.root))
        seen_findings: set[str] = set()

        self.console.rule(f"[bold cyan]Target: {target.display}[/bold cyan]")

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
        self._run_nmap_services(target, workspace, record, handle_finding)
        self._run_smb_modules(target, workspace, record, handle_finding)
        self._run_web_modules(target, workspace, record, handle_finding)
        self._run_auxiliary_modules(target, workspace, record, handle_finding)

        md_path, html_path = self.reporter.write(record, workspace.reports)
        workspace.save_state(record)
        self.console.print(f"[green]Reports written:[/green] {md_path} | {html_path}")
        return record

    def _run_nmap_discovery(
        self,
        target: Target,
        workspace: ScanWorkspace,
        record: ScanRecord,
        handle_finding: Callable[[Finding], None],
    ) -> None:
        if not self.config.tool_enabled("nmap"):
            return
        xml_path = workspace.raw_path("nmap", "discovery", "xml")
        log_path = workspace.raw_path("nmap", "discovery", "log")
        try:
            nmap_bin = self.runner.require("nmap")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}[/yellow]")
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
        if not self.config.tool_enabled("nmap") or not record.services:
            return
        ports = ",".join(str(service.port) for service in sorted(record.services, key=lambda item: item.port))
        if not ports:
            return
        xml_path = workspace.raw_path("nmap", "services", "xml")
        log_path = workspace.raw_path("nmap", "services", "log")
        try:
            nmap_bin = self.runner.require("nmap")
        except ToolUnavailable as exc:
            self.console.print(f"[yellow]{exc}[/yellow]")
            return
        command = [nmap_bin, *self.config.nmap_service_args, "-p", ports, "-oX", str(xml_path), target.scan_host]
        result = self._run_command(
            target=target,
            workspace=workspace,
            record=record,
            tool="nmap",
            profile="services",
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
        if not any(service.port in {139, 445} for service in record.services):
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
                    profile=safe_profile,
                    command_builder=lambda binary, url=url: [
                        binary,
                        "-u",
                        url,
                        "-t",
                        self.config.nuclei_templates,
                        "-severity",
                        self.config.nuclei_severity,
                        "-jsonl",
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
            self.console.print(f"[yellow]{exc}[/yellow]")
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
        self.console.print(f"[cyan]Running[/cyan] {tool}:{profile} -> {target.display}")
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
            self.console.print(f"[yellow]Exit {result.returncode}[/yellow] {tool}:{profile}")
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
        return list(urls.keys())

    def _log_result(self, result: CommandResult, workspace: ScanWorkspace) -> None:
        workspace.append_command(result.to_dict())

    def _write_campaign_summary(self, records: list[ScanRecord]) -> None:
        if not records:
            return
        summary_dir = self.config.repo_root / "scans"
        summary_dir.mkdir(parents=True, exist_ok=True)
        path = summary_dir / "latest_campaign_summary.md"
        lines = [
            "# Latest Campaign Summary",
            "",
            "| Target | Confirmed | Observed | Discarded | Workspace |",
            "|---|---:|---:|---:|---|",
        ]
        for record in records:
            lines.append(
                f"| {record.target.display} | {len(record.confirmed_findings)} | {len(record.observed_findings)} | {len(record.discarded_findings)} | `{record.workspace}` |"
            )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
