from __future__ import annotations

import json
import re
from typing import Any

from core.models import Finding, Target, clean_text, normalize_severity


def parse_json_line(line: str, target: Target) -> list[Finding]:
    line = line.strip()
    if not line:
        return []
    if not line.startswith("{"):
        return parse_text_line(line, target)
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        return parse_text_line(line, target)
    if not isinstance(item, dict):
        return []
    return [finding_from_item(item, target)]


def parse_json_lines(text: str, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        findings.extend(parse_json_line(line, target))
    return findings


def finding_from_item(item: dict[str, Any], target: Target) -> Finding:
    info = item.get("info") or {}
    classification = info.get("classification") or item.get("classification") or {}
    template_id = item.get("template-id") or item.get("templateID") or item.get("template") or "nuclei"
    name = info.get("name") or template_id
    severity = normalize_severity(info.get("severity") or item.get("severity"))
    cve = _join(classification.get("cve-id") or classification.get("cve") or _extract_cves(json.dumps(item)))
    cwe = _join(classification.get("cwe-id") or classification.get("cwe"))
    extracted = item.get("extracted-results") or item.get("extracted_results") or []
    evidence_parts = [
        f"Plantilla={template_id}",
        f"Matcher={item.get('matcher-name', '-')}",
        f"Tipo={item.get('type', '-')}",
        f"Host={item.get('host', '-')}",
        f"Coincidencia={item.get('matched-at') or item.get('url') or '-'}",
    ]
    if extracted:
        evidence_parts.append(f"Extraido={clean_text(extracted, 500)}")
    if item.get("curl-command"):
        evidence_parts.append(f"Curl={clean_text(item.get('curl-command'), 500)}")
    return Finding(
        tool="nuclei",
        target=target.display,
        title=f"Nuclei: {name}",
        severity=severity,
        ip=target.scan_host,
        url=item.get("matched-at") or item.get("url") or item.get("host") or target.url,
        cve=cve,
        cwe=cwe,
        cvss=str(classification.get("cvss-score") or classification.get("cvss") or ""),
        description=clean_text(info.get("description") or "", 1000),
        evidence=" | ".join(evidence_parts),
        recommendation=info.get("remediation") or info.get("reference") or "Validar el resultado del template y aplicar la remediacion indicada por el fabricante o framework afectado.",
        confidence="medium",
        source_id=str(template_id),
    )


def parse_text_line(line: str, target: Target) -> list[Finding]:
    text = line.strip()
    if not text.startswith("["):
        return []
    bracket_parts = re.findall(r"\[([^\]]+)\]", text)
    severities = {"critical", "high", "medium", "low", "info", "informational", "unknown"}
    severity_value = next((part for part in bracket_parts if part.lower() in severities), "")
    if not severity_value or not bracket_parts:
        return []
    template_id = bracket_parts[0]
    tail = re.sub(r"^(?:\[[^\]]+\]\s*)+", "", text).strip()
    matched_at = tail.split()[0] if tail else target.url or target.display
    cves = _extract_cves(text)
    protocol = next((part for part in bracket_parts[1:] if part.lower() not in severities), "")
    return [
        Finding(
            tool="nuclei",
            target=target.display,
            title=f"Nuclei: {template_id}",
            severity=normalize_severity(severity_value),
            ip=target.scan_host,
            url=matched_at,
            cve=", ".join(cves[:8]),
            evidence=clean_text(text, 1400),
            recommendation="Validar el resultado del template y aplicar la remediacion indicada por el fabricante o framework afectado.",
            confidence="medium" if severity_value.lower() in {"critical", "high", "medium"} else "low",
            source_id=str(template_id),
            service=protocol,
        )
    ]


def _extract_cves(text: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))


def _join(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item)
    return str(value)
