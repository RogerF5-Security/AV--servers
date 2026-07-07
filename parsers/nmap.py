from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from core.models import Finding, Service, Target, clean_text


VULN_POSITIVE = ("cve-", "vulnerable", "state: vulnerable", "exploit", "vulners.com", "cvss")
VULN_NEGATIVE = ("not vulnerable", "no vulnerabilities found", "state: not_vulnerable", "no cpe")


def parse_services(xml_text: str, target: Target) -> tuple[list[Service], list[Finding]]:
    if not xml_text.strip():
        return [], []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return [], []

    services: list[Service] = []
    findings: list[Finding] = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service_node = port.find("service")
        service = Service(
            host=target.scan_host,
            port=int(port.get("portid", "0")),
            protocol=port.get("protocol", "tcp"),
            name=service_node.get("name", "") if service_node is not None else "",
            product=service_node.get("product", "") if service_node is not None else "",
            version=service_node.get("version", "") if service_node is not None else "",
            tunnel=service_node.get("tunnel", "") if service_node is not None else "",
        )
        services.append(service)
        for script in port.findall("script"):
            finding = _script_finding(target, service, script.get("id", "script"), script.get("output", ""))
            if finding:
                findings.append(finding)
    return services, findings


def parse_line(line: str, target: Target) -> list[Finding]:
    lower = line.lower()
    if not any(marker in lower for marker in VULN_POSITIVE):
        return []
    if any(marker in lower for marker in VULN_NEGATIVE):
        return []
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", line, flags=re.IGNORECASE)))
    return [
        Finding(
            tool="nmap",
            target=target.display,
            title=f"Nmap vulnerability signal: {', '.join(cves[:3]) if cves else clean_text(line, 80)}",
            severity=_severity_from_text(line),
            ip=target.scan_host,
            cve=", ".join(cves[:8]),
            evidence=clean_text(line, 1400),
            confidence="low" if not cves else "medium",
            source_id="nmap-live",
        )
    ]


def _script_finding(target: Target, service: Service, script_id: str, output: str) -> Finding | None:
    text = f"{script_id} {output}"
    lower = text.lower()
    if any(marker in lower for marker in VULN_NEGATIVE):
        return None
    if not any(marker in lower for marker in VULN_POSITIVE):
        return None
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", output, flags=re.IGNORECASE)))
    return Finding(
        tool="nmap",
        target=target.display,
        title=f"Nmap NSE finding on {service.endpoint}: {', '.join(cves[:5]) if cves else script_id}",
        severity=_severity_from_text(output),
        ip=target.scan_host,
        port=service.endpoint,
        service=service.label,
        cve=", ".join(cves[:8]),
        evidence=clean_text(output, 1800),
        recommendation="Validate affected software versions, patch vulnerable services, and restrict exposure where possible.",
        confidence="medium" if cves else "low",
        source_id=f"nmap:{script_id}",
    )


def _severity_from_text(text: str) -> str:
    upper = text.upper()
    scores = [float(match) for match in re.findall(r"\b(?:CVSS[:\s]*)?(10\.0|[0-9]\.[0-9])\b", text, flags=re.IGNORECASE)]
    score = max(scores) if scores else 0.0
    if score >= 9.0 or "CRITICAL" in upper:
        return "Critical"
    if score >= 7.0 or "HIGH" in upper or "EXPLOIT" in upper:
        return "High"
    if score >= 4.0 or "MEDIUM" in upper or "VULNERABLE" in upper:
        return "Medium"
    return "Low"
