from __future__ import annotations

import re

from core.models import Finding, Target, clean_text


def parse_line(line: str, target: Target, url: str) -> list[Finding]:
    text = line.strip()
    if not text.startswith("+"):
        return []
    lower = text.lower()
    positive = ["cve-", "osvdb", "vulnerab", "outdated", "allowed http methods", "x-frame-options", "x-content-type-options"]
    if not any(marker in lower for marker in positive):
        return []
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))
    severity = "High" if cves or "vulnerab" in lower else "Medium"
    if "x-frame-options" in lower or "x-content-type-options" in lower:
        severity = "Low"
    return [
        Finding(
            tool="nikto",
            target=target.display,
            title=f"Hallazgo web de Nikto: {', '.join(cves[:3]) if cves else clean_text(text.lstrip('+').strip(), 90)}",
            severity=severity,
            ip=target.scan_host,
            url=url,
            service="web",
            cve=", ".join(cves[:8]),
            evidence=clean_text(text, 1400),
            recommendation="Validar el hallazgo de Nikto y corregir el control afectado en el servidor web o la aplicacion.",
            confidence="medium" if cves else "low",
            source_id="nikto-line",
        )
    ]


def parse_text(text: str, target: Target, url: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        findings.extend(parse_line(line, target, url))
    return findings
