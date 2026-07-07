from __future__ import annotations

import re

from core.models import Finding, Target, clean_text


RISKY_TECH = (
    "phpmyadmin",
    "jenkins",
    "tomcat",
    "jboss",
    "weblogic",
    "struts",
    "wordpress",
    "joomla",
    "drupal",
)


def parse_line(line: str, target: Target, url: str) -> list[Finding]:
    text = line.strip()
    if not text:
        return []
    lower = text.lower()
    if not any(tech in lower for tech in RISKY_TECH):
        return []
    versions = re.findall(r"\[([0-9][A-Za-z0-9._-]{1,30})\]", text)
    return [
        Finding(
            tool="whatweb",
            target=target.display,
            title="Web technology fingerprint requires version validation",
            severity="Low",
            ip=target.scan_host,
            url=url,
            service="web",
            evidence=clean_text(text, 1400),
            description=f"Detected exposed technology fingerprint{': ' + ', '.join(versions[:5]) if versions else ''}.",
            recommendation="Verify exposed versions, hide unnecessary banners, and patch affected components.",
            confidence="low",
            source_id="whatweb-tech-fingerprint",
        )
    ]


def parse_text(text: str, target: Target, url: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        findings.extend(parse_line(line, target, url))
    return findings
