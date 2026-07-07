from __future__ import annotations

import re

from core.models import Finding, Target, clean_text


def parse_line(line: str, target: Target) -> list[Finding]:
    text = line.strip()
    if not text or "|" not in text:
        return []
    lower = text.lower()
    if any(skip in lower for skip in ["exploit title", "shellcodes", "papers", "-----"]):
        return []
    title, _, path = text.partition("|")
    title = title.strip()
    path = path.strip()
    if not title or not path:
        return []
    if not re.search(r"\b(exploit|rce|remote|injection|bypass|overflow|traversal|disclosure|dos|privilege|xss|sqli|cve-\d{4})\b", lower):
        return []
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))
    severity = "High" if any(word in lower for word in ["rce", "remote code", "unauth", "privilege", "overflow"]) else "Medium"
    return [
        Finding(
            tool="searchsploit",
            target=target.display,
            title=f"Exploit publico asociado a tecnologia detectada: {clean_text(title, 140)}",
            severity=severity,
            ip=target.scan_host,
            cve=", ".join(cves[:8]),
            evidence=clean_text(text, 1400),
            recommendation="Validar version exacta afectada, aplicar parches del fabricante y retirar componentes vulnerables o expuestos innecesariamente.",
            confidence="medium",
            source_id=f"searchsploit:{path}",
        )
    ]


def parse_text(text: str, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        findings.extend(parse_line(line, target))
    return findings
