from __future__ import annotations

import re

from core.models import Finding, Target, clean_text


def parse_line(line: str, target: Target) -> list[Finding]:
    text = line.strip()
    lower = text.lower()
    if not text:
        return []
    if any(marker in lower for marker in ["null session", "anonymous login", "session check on"]):
        if any(ok in lower for ok in ["successful", "allowed", "succeeded"]):
            return [
                Finding(
                    tool="enum4linux-ng",
                    target=target.display,
                    title="SMB null session appears to be allowed",
                    severity="Medium",
                    ip=target.scan_host,
                    port="445/tcp",
                    service="smb",
                    evidence=clean_text(text, 1000),
                    recommendation="Disable anonymous SMB enumeration and validate RestrictAnonymous settings.",
                    confidence="medium",
                    source_id="enum4linux-null-session",
                )
            ]
    if re.search(r"\b(user|group|share)s?\s+enumerat", lower) and any(ok in lower for ok in ["found", "success", "result"]):
        return [
            Finding(
                tool="enum4linux-ng",
                target=target.display,
                title="SMB enumeration returned directory or share data",
                severity="Low",
                ip=target.scan_host,
                port="445/tcp",
                service="smb",
                evidence=clean_text(text, 1000),
                recommendation="Restrict SMB enumeration to authenticated administrative contexts.",
                confidence="low",
                source_id="enum4linux-enumeration",
            )
        ]
    return []


def parse_text(text: str, target: Target) -> list[Finding]:
    out: list[Finding] = []
    for line in text.splitlines():
        out.extend(parse_line(line, target))
    return out
