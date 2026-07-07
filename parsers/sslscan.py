from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from core.models import Finding, Target, clean_text


LEGACY_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLS1.0", "TLS1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC3", "NULL", "ADH", "AECDH", "EXPORT", "MD5")


def parse_xml(text: str, target: Target, endpoint: str, raw_output_path: str = "") -> list[Finding]:
    if not text.strip():
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return parse_text(text, target, endpoint, raw_output_path)

    findings: list[Finding] = []
    protocols = _enabled_legacy_protocols(root)
    if protocols:
        findings.append(
            _finding(
                target,
                endpoint,
                "Protocolos TLS/SSL obsoletos habilitados",
                "High" if any(item in {"SSLv2", "SSLv3", "TLSv1.0", "TLS1.0"} for item in protocols) else "Medium",
                f"Protocolos habilitados: {', '.join(protocols)}",
                "Deshabilitar SSLv2, SSLv3, TLS 1.0 y TLS 1.1. Permitir solo TLS 1.2/1.3 con configuracion moderna.",
                raw_output_path,
                "sslscan:legacy-protocol",
            )
        )

    weak_ciphers = _weak_ciphers(root)
    if weak_ciphers:
        severity = "High" if any(any(marker in item.upper() for marker in ("NULL", "ADH", "AECDH", "EXPORT")) for item in weak_ciphers) else "Medium"
        findings.append(
            _finding(
                target,
                endpoint,
                "Cifrados TLS inseguros aceptados",
                severity,
                "Cifrados debiles: " + ", ".join(weak_ciphers[:20]),
                "Eliminar suites NULL/anonimas/EXPORT/RC4/3DES/MD5 y priorizar suites AEAD con PFS.",
                raw_output_path,
                "sslscan:weak-cipher",
            )
        )

    certificate_issues = _certificate_issues(root)
    if certificate_issues:
        findings.append(
            _finding(
                target,
                endpoint,
                "Problemas criptograficos en certificado TLS",
                "Medium",
                "; ".join(certificate_issues),
                "Reemitir el certificado con una CA confiable, algoritmo moderno y llave RSA >= 2048 bits o ECDSA equivalente.",
                raw_output_path,
                "sslscan:certificate",
            )
        )
    return findings


def parse_json_text(text: str, target: Target, endpoint: str, raw_output_path: str = "") -> list[Finding]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    flattened = "\n".join(_flatten(payload))
    return parse_text(flattened, target, endpoint, raw_output_path)


def parse_text(text: str, target: Target, endpoint: str, raw_output_path: str = "") -> list[Finding]:
    upper = text.upper()
    findings: list[Finding] = []
    protocols = [protocol for protocol in LEGACY_PROTOCOLS if protocol.upper() in upper and _enabled_near(text, protocol)]
    if protocols:
        findings.append(
            _finding(
                target,
                endpoint,
                "Protocolos TLS/SSL obsoletos habilitados",
                "High",
                clean_text(text, 1800),
                "Deshabilitar protocolos SSL/TLS heredados y permitir solo TLS 1.2/1.3.",
                raw_output_path,
                "sslscan:text-legacy-protocol",
            )
        )
    weak = [marker for marker in WEAK_CIPHER_MARKERS if marker in upper]
    if weak:
        findings.append(
            _finding(
                target,
                endpoint,
                "Cifrados TLS inseguros aceptados",
                "Medium",
                f"Marcadores detectados: {', '.join(weak)} | {clean_text(text, 1400)}",
                "Eliminar cifrados debiles y suites anonimas/NULL/EXPORT/RC4/3DES.",
                raw_output_path,
                "sslscan:text-weak-cipher",
            )
        )
    if any(marker in upper for marker in ("SELF-SIGNED", "EXPIRED", "MD5", "SHA1")):
        findings.append(
            _finding(
                target,
                endpoint,
                "Problemas criptograficos en certificado TLS",
                "Medium",
                clean_text(text, 1800),
                "Reemitir el certificado con parametros criptograficos modernos.",
                raw_output_path,
                "sslscan:text-certificate",
            )
        )
    return _dedupe(findings)


def _enabled_legacy_protocols(root: ET.Element) -> list[str]:
    protocols: list[str] = []
    for node in root.iter():
        tag = node.tag.lower()
        text = " ".join([node.text or "", " ".join(f"{k}={v}" for k, v in node.attrib.items())])
        if "protocol" not in tag and not any(protocol.lower() in text.lower() for protocol in LEGACY_PROTOCOLS):
            continue
        if not _node_enabled(node):
            continue
        label = _protocol_label(node)
        if label in LEGACY_PROTOCOLS and label not in protocols:
            protocols.append(label)
    return protocols


def _weak_ciphers(root: ET.Element) -> list[str]:
    ciphers: list[str] = []
    for node in root.iter():
        if "cipher" not in node.tag.lower():
            continue
        if not _node_enabled(node):
            continue
        text = " ".join([node.text or "", " ".join(str(value) for value in node.attrib.values())])
        upper = text.upper()
        bits = _bits(node)
        if bits and bits <= 56 or any(marker in upper for marker in WEAK_CIPHER_MARKERS):
            label = clean_text(text, 180)
            if label and label not in ciphers:
                ciphers.append(label)
    return ciphers


def _certificate_issues(root: ET.Element) -> list[str]:
    issues: list[str] = []
    for node in root.iter():
        if "certificate" not in node.tag.lower() and "cert" not in node.tag.lower():
            continue
        text = " ".join([node.text or "", " ".join(f"{k}={v}" for k, v in node.attrib.items())])
        lower = text.lower()
        if "self" in lower and "signed" in lower:
            issues.append("Certificado auto-firmado")
        if "expired" in lower or "not valid" in lower:
            issues.append("Certificado expirado o no valido")
        if "md5" in lower:
            issues.append("Firma MD5 en certificado")
        if "sha1" in lower or "sha-1" in lower:
            issues.append("Firma SHA1 en certificado")
        bits = _bits(node)
        if bits and bits < 2048:
            issues.append(f"Longitud de llave debil: {bits} bits")
    return sorted(set(issues))


def _node_enabled(node: ET.Element) -> bool:
    attrs = {key.lower(): str(value).lower() for key, value in node.attrib.items()}
    if any(value in {"true", "1", "yes", "enabled", "accepted"} for value in attrs.values()):
        return True
    if any(key in attrs for key in ("accepted", "enabled", "status")):
        return False
    text = (node.text or "").lower()
    return "enabled" in text or "accepted" in text


def _protocol_label(node: ET.Element) -> str:
    text = " ".join([node.text or "", " ".join(str(value) for value in node.attrib.values())])
    compact = text.replace(" ", "")
    for protocol in LEGACY_PROTOCOLS:
        if protocol.replace(".", "").upper() in compact.replace(".", "").upper() or protocol.upper() in text.upper():
            if protocol == "TLS1.0":
                return "TLSv1.0"
            if protocol == "TLS1.1":
                return "TLSv1.1"
            return protocol
    return ""


def _bits(node: ET.Element) -> int | None:
    text = " ".join([node.text or "", " ".join(str(value) for value in node.attrib.values())])
    match = re.search(r"\b([0-9]{2,5})\s*(?:bits?|bit)\b", text, flags=re.IGNORECASE)
    if match:
        return int(match.group(1))
    for key in ("bits", "strength", "keysize"):
        value = node.attrib.get(key)
        if value and str(value).isdigit():
            return int(value)
    return None


def _enabled_near(text: str, protocol: str) -> bool:
    pattern = re.compile(rf"{re.escape(protocol)}.{{0,80}}(?:enabled|accepted)", flags=re.IGNORECASE | re.DOTALL)
    return bool(pattern.search(text))


def _flatten(value: Any) -> list[str]:
    if isinstance(value, dict):
        out: list[str] = []
        for key, item in value.items():
            out.append(str(key))
            out.extend(_flatten(item))
        return out
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_flatten(item))
        return out
    return [str(value)]


def _finding(
    target: Target,
    endpoint: str,
    title: str,
    severity: str,
    evidence: str,
    recommendation: str,
    raw_output_path: str,
    source_id: str,
) -> Finding:
    return Finding(
        tool="sslscan",
        target=target.display,
        title=title,
        severity=severity,
        ip=target.scan_host,
        port=endpoint,
        service="tls/ssl",
        evidence=clean_text(evidence, 2200),
        raw_output_path=raw_output_path,
        recommendation=recommendation,
        confidence="medium",
        source_id=source_id,
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    out: dict[str, Finding] = {}
    for finding in findings:
        out.setdefault(f"{finding.title}|{finding.port}", finding)
    return list(out.values())
