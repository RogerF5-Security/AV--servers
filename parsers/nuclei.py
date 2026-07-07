from __future__ import annotations

import json
import re
from typing import Any

from core.models import Finding, Target, clean_text, normalize_severity


def parse_json_line(line: str, target: Target) -> list[Finding]:
    line = line.strip()
    if not line or not line.startswith("{"):
        return []
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        return []
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
        f"Template={template_id}",
        f"Matcher={item.get('matcher-name', '-')}",
        f"Type={item.get('type', '-')}",
        f"Host={item.get('host', '-')}",
        f"Matched={item.get('matched-at') or item.get('url') or '-'}",
    ]
    if extracted:
        evidence_parts.append(f"Extracted={clean_text(extracted, 500)}")
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
        recommendation=info.get("remediation") or info.get("reference") or "Validate the template result and apply the vendor or framework remediation.",
        confidence="medium",
        source_id=str(template_id),
    )


def _extract_cves(text: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))


def _join(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item)
    return str(value)
