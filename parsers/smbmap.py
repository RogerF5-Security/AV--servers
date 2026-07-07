from __future__ import annotations

import re

from core.models import Finding, Target, clean_text


def parse_line(line: str, target: Target) -> list[Finding]:
    text = line.strip()
    if not text:
        return []
    lower = text.lower()
    findings: list[Finding] = []
    if re.search(r"\b(read,\s*write|write|read/write)\b", lower) and "no access" not in lower:
        findings.append(
            Finding(
                tool="smbmap",
                target=target.display,
                title="SMB share with write-capable or read/write permissions",
                severity="High" if "write" in lower else "Medium",
                ip=target.scan_host,
                port="445/tcp",
                service="smb",
                evidence=clean_text(text, 1200),
                recommendation="Remove anonymous or broad share permissions and enforce least-privilege ACLs.",
                confidence="medium",
                source_id="smbmap-share-permission",
            )
        )
    elif "anonymous login successful" in lower or "null session" in lower:
        findings.append(
            Finding(
                tool="smbmap",
                target=target.display,
                title="SMB anonymous or null session access detected",
                severity="Medium",
                ip=target.scan_host,
                port="445/tcp",
                service="smb",
                evidence=clean_text(text, 1000),
                recommendation="Disable null sessions and require authenticated SMB access.",
                confidence="medium",
                source_id="smbmap-null-session",
            )
        )
    return findings


def parse_text(text: str, target: Target) -> list[Finding]:
    out: list[Finding] = []
    for line in text.splitlines():
        out.extend(parse_line(line, target))
    return out
