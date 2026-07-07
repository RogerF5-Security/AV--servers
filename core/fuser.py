from __future__ import annotations

import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from .models import Finding, SEVERITY_ORDER, clean_text


class VulnerabilityFuser:
    def fuse(self, findings: list[Finding]) -> list[Finding]:
        groups: list[list[Finding]] = []
        for finding in findings:
            for group in groups:
                if self._same_issue(finding, group[0]):
                    group.append(finding)
                    break
            else:
                groups.append([finding])
        return [self._merge(group) for group in groups]

    def _same_issue(self, left: Finding, right: Finding) -> bool:
        if (left.ip or left.target) != (right.ip or right.target):
            return False
        if self._port_number(left) != self._port_number(right):
            return False
        left_cves = self._finding_ids(left, "CVE")
        right_cves = self._finding_ids(right, "CVE")
        if left_cves and right_cves:
            return bool(left_cves.intersection(right_cves))
        left_cwes = self._finding_ids(left, "CWE")
        right_cwes = self._finding_ids(right, "CWE")
        if left_cwes and right_cwes:
            return bool(left_cwes.intersection(right_cwes))
        return self._title_similarity(left.title, right.title) >= 0.82

    def _merge(self, group: list[Finding]) -> Finding:
        if len(group) == 1:
            return group[0]
        group = sorted(group, key=lambda item: SEVERITY_ORDER.get(item.severity, 99))
        base = group[0]
        tools = self._unique(item.tool for item in group)
        source_ids = self._unique(item.source_id for item in group if item.source_id)
        cves = self._unique_id_values(item.cve for item in group)
        cwes = self._unique_id_values(item.cwe for item in group)
        raw_paths = self._unique(item.raw_output_path for item in group if item.raw_output_path)
        evidence_blocks = []
        for item in group:
            header = f"[{item.tool}] {item.source_id or item.title}"
            evidence_blocks.append(f"{header}\n{item.evidence or '-'}")
        base.tool = ", ".join(tools)
        base.cve = ", ".join(cves)
        base.cwe = ", ".join(cwes)
        base.raw_output_path = " | ".join(raw_paths)
        base.evidence = clean_text("\n\n--- Evidencia fusionada ---\n\n".join(evidence_blocks), 6000)
        base.confidence = "Alta Confianza - Validado por Multiples Fuentes" if len(tools) > 1 else "Alta Confianza - Evidencia Correlacionada"
        if source_ids:
            base.source_id = ", ".join(source_ids)
        if not base.auditor_note:
            base.auditor_note = "Hallazgo consolidado automaticamente por el motor de fusion."
        base.fingerprint = base.build_fingerprint()
        return base

    def _port_number(self, finding: Finding) -> str:
        if finding.port:
            match = re.search(r"\d+", finding.port)
            if match:
                return match.group(0)
        if finding.url:
            parsed = urlparse(finding.url)
            if parsed.port:
                return str(parsed.port)
            if parsed.scheme == "https":
                return "443"
            if parsed.scheme == "http":
                return "80"
        return ""

    def _ids(self, value: str) -> set[str]:
        return {item.upper() for item in re.findall(r"(?:CVE-\d{4}-\d{4,7}|CWE-\d+)", value or "", flags=re.IGNORECASE)}

    def _finding_ids(self, finding: Finding, prefix: str) -> set[str]:
        text = " ".join([finding.cve, finding.cwe, finding.title, finding.evidence])
        if prefix == "CVE":
            return {item.upper() for item in re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)}
        return {item.upper() for item in re.findall(r"CWE-\d+", text, flags=re.IGNORECASE)}

    def _title_similarity(self, left: str, right: str) -> float:
        return SequenceMatcher(None, self._normalize_title(left), self._normalize_title(right)).ratio()

    def _normalize_title(self, value: str) -> str:
        text = value.lower()
        text = re.sub(r"\b(nuclei|nmap|nse|searchsploit|nikto|sslscan|hallazgo|detectado|detectada|vulnerabilidad)\b", " ", text)
        text = re.sub(r"[^a-z0-9]+", " ", text)
        return re.sub(r"\s+", " ", text).strip()

    def _unique(self, values) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for value in values:
            text = str(value or "").strip()
            key = text.lower()
            if text and key not in seen:
                seen.add(key)
                out.append(text)
        return out

    def _unique_id_values(self, values) -> list[str]:
        ids: list[str] = []
        seen: set[str] = set()
        for value in values:
            for item in re.findall(r"(?:CVE-\d{4}-\d{4,7}|CWE-\d+)", str(value or ""), flags=re.IGNORECASE):
                key = item.upper()
                if key not in seen:
                    seen.add(key)
                    ids.append(key)
        return ids
