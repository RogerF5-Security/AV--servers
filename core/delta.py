from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Finding, ScanRecord, clean_text


def compare_record_with_previous(record: ScanRecord, previous_state: Path) -> dict[str, list[str]]:
    if not previous_state.exists():
        return {
            "error": [f"No se encontro el archivo previo: {previous_state}"],
            "new_services": [],
            "new_findings": [],
            "remediated_findings": [],
        }
    try:
        payload = json.loads(previous_state.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "error": [f"No se pudo leer el estado previo: {exc}"],
            "new_services": [],
            "new_findings": [],
            "remediated_findings": [],
        }

    previous_services = {_service_key(item) for item in payload.get("services", []) if isinstance(item, dict)}
    current_services = {_service_key(item.__dict__) for item in record.services}
    previous_findings = {_finding_key(item) for item in _state_findings(payload)}
    current_findings = {_finding_key(item.to_dict()) for item in record.confirmed_findings}

    return {
        "new_services": sorted(current_services - previous_services),
        "new_findings": sorted(current_findings - previous_findings),
        "remediated_findings": sorted(previous_findings - current_findings),
    }


def _state_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for key in ("confirmed_findings", "observed_findings"):
        for item in payload.get(key, []):
            if isinstance(item, dict):
                findings.append(item)
    return findings


def _service_key(item: dict[str, Any]) -> str:
    port = str(item.get("port") or "-")
    proto = str(item.get("protocol") or "tcp")
    label = clean_text(" ".join(str(item.get(key) or "") for key in ("name", "product", "version")), 160) or "unknown"
    return f"{port}/{proto} {label}"


def _finding_key(item: dict[str, Any]) -> str:
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(item.get("cve") or ""), flags=re.IGNORECASE)))
    cwes = sorted(set(re.findall(r"CWE-\d+", str(item.get("cwe") or ""), flags=re.IGNORECASE)))
    port = str(item.get("port") or "")
    identity = ", ".join([*cves, *cwes])
    if not identity:
        identity = _normalize_title(str(item.get("title") or ""))
    return clean_text(f"{port} {identity}", 220)


def _normalize_title(title: str) -> str:
    text = title.lower()
    text = re.sub(r"\b(nuclei|nmap|nse|searchsploit|nikto|sslscan|hallazgo|detectado|detectada)\b", " ", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()
