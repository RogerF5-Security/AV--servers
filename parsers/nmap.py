from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from core.models import Finding, Service, Target, clean_text


VULN_POSITIVE = ("cve-", "vulnerable", "state: vulnerable", "exploit", "vulners.com", "cvss")
VULN_NEGATIVE = ("not vulnerable", "no vulnerabilities found", "state: not_vulnerable", "no cpe")
HTTP_RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE"}
OBSOLETE_TLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
WEAK_TLS_MARKERS = ("RC4", "3DES", "DES-CBC3", "EXPORT", "NULL", "ANON", "MD5")
WEAK_SSH_MARKERS = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "ssh-dss",
    "arcfour",
    "hmac-md5",
    "hmac-sha1-96",
    "-cbc",
)


def parse_services(xml_text: str, target: Target) -> tuple[list[Service], list[Finding]]:
    if not xml_text.strip():
        return [], []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return [], []

    services: list[Service] = []
    findings: list[Finding] = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service_node = port.find("service")
        service = Service(
            host=target.scan_host,
            port=int(port.get("portid", "0")),
            protocol=port.get("protocol", "tcp"),
            name=service_node.get("name", "") if service_node is not None else "",
            product=service_node.get("product", "") if service_node is not None else "",
            version=service_node.get("version", "") if service_node is not None else "",
            tunnel=service_node.get("tunnel", "") if service_node is not None else "",
        )
        services.append(service)
        for script in port.findall("script"):
            findings.extend(_script_findings(target, service, script.get("id", "script"), script.get("output", "")))
    host_service = Service(host=target.scan_host, port=0, protocol="host", name="hostscript")
    for script in root.findall(".//hostscript/script"):
        findings.extend(_script_findings(target, host_service, script.get("id", "script"), script.get("output", "")))
    return services, findings


def parse_line(line: str, target: Target) -> list[Finding]:
    service = Service(host=target.scan_host, port=0, protocol="tcp", name="nmap-live")
    findings = _known_risky_configuration_findings(target, service, "nmap-live", line)
    if findings:
        return findings
    lower = line.lower()
    if not any(marker in lower for marker in VULN_POSITIVE):
        return []
    if any(marker in lower for marker in VULN_NEGATIVE):
        return []
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", line, flags=re.IGNORECASE)))
    return [
        Finding(
            tool="nmap",
            target=target.display,
            title=f"Senal de vulnerabilidad detectada por Nmap: {', '.join(cves[:3]) if cves else clean_text(line, 80)}",
            severity=_severity_from_text(line),
            ip=target.scan_host,
            cve=", ".join(cves[:8]),
            evidence=clean_text(line, 1400),
            confidence="low" if not cves else "medium",
            source_id="nmap-live",
        )
    ]


def _script_findings(target: Target, service: Service, script_id: str, output: str) -> list[Finding]:
    text = f"{script_id} {output}"
    lower = text.lower()
    findings = _known_risky_configuration_findings(target, service, script_id, output)
    if not any(marker in lower for marker in VULN_POSITIVE):
        return findings
    if any(marker in lower for marker in VULN_NEGATIVE):
        return findings
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", output, flags=re.IGNORECASE)))
    findings.append(
        _make_finding(
            target=target,
            service=service,
            script_id=script_id,
            title=f"Hallazgo NSE de Nmap en {_endpoint(service)}: {', '.join(cves[:5]) if cves else script_id}",
            severity=_severity_from_text(output),
            evidence=output,
            recommendation="Validar versiones afectadas, aplicar parches del fabricante y restringir la exposicion del servicio cuando sea posible.",
            confidence="medium" if cves else "low",
            cve=", ".join(cves[:8]),
        )
    )
    return _dedupe_findings(findings)


def _known_risky_configuration_findings(
    target: Target,
    service: Service,
    script_id: str,
    output: str,
) -> list[Finding]:
    text = f"{script_id}\n{output}"
    lower = text.lower()
    findings: list[Finding] = []

    def add(title: str, severity: str, recommendation: str, source_suffix: str, confidence: str = "medium") -> None:
        findings.append(
            _make_finding(
                target=target,
                service=service,
                script_id=f"{script_id}:{source_suffix}",
                title=title,
                severity=severity,
                evidence=output,
                recommendation=recommendation,
                confidence=confidence,
            )
        )

    if _is_smb_signing_weak(lower):
        add(
            "SMB permite firma no requerida o deshabilitada",
            "High",
            "Exigir SMB signing en clientes y servidores, deshabilitar SMB heredado y reducir el riesgo de relay NTLM.",
            "smb-signing",
        )

    if _is_smb_anonymous_access(lower):
        severity = "High" if re.search(r"anonymous access:\s*(read/write|write)", lower) else "Medium"
        add(
            "SMB permite acceso anonimo, invitado o sesion nula",
            severity,
            "Deshabilitar sesiones nulas/invitado y aplicar ACLs con minimo privilegio en recursos compartidos.",
            "smb-anonymous",
        )

    risky_methods = _http_risky_methods(text)
    if risky_methods:
        severity = "High" if {"PUT", "DELETE", "MOVE", "COPY"}.intersection(risky_methods) else "Medium"
        add(
            f"Servidor HTTP permite metodos riesgosos: {', '.join(sorted(risky_methods))}",
            severity,
            "Deshabilitar metodos HTTP no requeridos y limitar WebDAV/TRACE/PUT/DELETE a rutas estrictamente controladas.",
            "http-methods",
        )

    if "http-security-headers" in lower and _missing_security_header(lower):
        add(
            "Cabeceras de seguridad HTTP ausentes o incompletas",
            "Low",
            "Configurar HSTS, X-Frame-Options o frame-ancestors, X-Content-Type-Options y Content-Security-Policy segun aplique.",
            "http-security-headers",
            confidence="low",
        )

    if "http-git" in lower and (".git" in lower or "repository" in lower) and _has_positive_discovery(lower):
        add(
            "Repositorio .git expuesto por HTTP",
            "High",
            "Bloquear acceso web a directorios .git y revisar si credenciales o codigo sensible fueron expuestos.",
            "http-git",
        )

    if "http-config-backup" in lower and _has_positive_discovery(lower):
        add(
            "Archivo de configuracion o backup expuesto por HTTP",
            "High",
            "Eliminar backups del webroot, restringir descarga de archivos sensibles y rotar secretos que pudieron quedar expuestos.",
            "http-config-backup",
        )

    protocols = _obsolete_tls_protocols(text)
    if protocols:
        add(
            f"TLS/SSL obsoleto aceptado: {', '.join(protocols)}",
            "High" if any(proto in {"SSLv2", "SSLv3", "TLSv1.0"} for proto in protocols) else "Medium",
            "Deshabilitar SSLv2/SSLv3/TLS 1.0/1.1 y permitir solo TLS 1.2/1.3 con suites fuertes.",
            "obsolete-tls",
        )

    weak_tls = _weak_tls_markers(text)
    if weak_tls:
        add(
            f"Suites TLS debiles aceptadas: {', '.join(weak_tls[:8])}",
            "High" if {"EXPORT", "NULL", "ANON"}.intersection(weak_tls) else "Medium",
            "Eliminar suites anonimas, NULL, EXPORT, RC4, 3DES, MD5 y priorizar cifrados AEAD modernos.",
            "weak-tls-ciphers",
        )

    if "ssl-enum-ciphers" in lower and re.search(r"least strength:\s*[fcd]\b", lower):
        add(
            "Nmap califico la configuracion TLS con fortaleza debil",
            "Medium",
            "Revisar la configuracion TLS completa y eliminar protocolos/cifrados marcados con baja fortaleza.",
            "weak-tls-grade",
        )

    if "ftp-anon" in lower and ("anonymous ftp login allowed" in lower or "anonymous@" in lower):
        severity = "Critical" if any(marker in lower for marker in ("writeable", "writable", "upload")) else "High"
        add(
            "FTP permite inicio de sesion anonimo",
            severity,
            "Deshabilitar login anonimo FTP o limitarlo a un area aislada sin escritura ni datos sensibles.",
            "ftp-anonymous",
        )

    if "smtp-open-relay" in lower and ("open relay" in lower or "relay accepted" in lower):
        add(
            "Servidor SMTP funciona como open relay",
            "Critical",
            "Restringir relay SMTP a origenes autorizados y exigir autenticacion para envio externo.",
            "smtp-open-relay",
        )

    if "rdp-enum-encryption" in lower and ("native rdp: success" in lower or "nla" in lower and "not required" in lower):
        add(
            "RDP permite conexion sin NLA obligatoria",
            "Medium",
            "Exigir Network Level Authentication y deshabilitar capas RDP heredadas.",
            "rdp-nla",
        )

    if "rdp-enum-encryption" in lower and re.search(r"\b(40-bit|56-bit|rc4)\b", lower):
        add(
            "RDP acepta cifrado debil o heredado",
            "Medium",
            "Forzar cifrado alto en RDP, exigir TLS/NLA y bloquear clientes heredados.",
            "rdp-weak-encryption",
        )

    weak_ssh = _weak_ssh_algorithms(lower)
    if weak_ssh:
        add(
            f"SSH anuncia algoritmos debiles: {', '.join(weak_ssh[:8])}",
            "Medium",
            "Deshabilitar algoritmos SHA1/CBC/arcfour/DSA y usar KEX, MAC y host keys modernas.",
            "ssh-weak-algos",
        )

    if "dns-recursion" in lower and ("recursion appears to be enabled" in lower or "recursion: enabled" in lower):
        add(
            "DNS recursivo expuesto",
            "Medium",
            "Limitar recursion DNS a redes internas/autorizadas y bloquear consultas recursivas desde Internet.",
            "dns-recursion",
        )

    if script_id.startswith("snmp-") and _snmp_information_exposed(lower):
        add(
            "SNMP expone informacion con comunidad accesible",
            "Medium",
            "Cambiar comunidades por defecto, restringir SNMP por ACL y migrar a SNMPv3 con autenticacion y cifrado.",
            "snmp-info",
        )

    if _empty_password_detected(lower):
        add(
            "Servicio acepta credenciales con password vacio",
            "Critical",
            "Deshabilitar cuentas sin password, rotar credenciales y restringir acceso administrativo por red.",
            "empty-password",
        )

    if "redis-info" in lower and _has_positive_discovery(lower):
        add(
            "Redis expuesto y responde sin autenticacion fuerte",
            "High",
            "Restringir Redis a interfaces internas, exigir autenticacion robusta y revisar configuracion protected-mode.",
            "redis-exposed",
        )

    if "docker-version" in lower and _has_positive_discovery(lower):
        add(
            "API Docker expuesta por red",
            "High",
            "No exponer el socket/API Docker sin TLS mutuo y restringir acceso a hosts administrativos.",
            "docker-api-exposed",
        )

    return _dedupe_findings(findings)


def _severity_from_text(text: str) -> str:
    upper = text.upper()
    scores = [float(match) for match in re.findall(r"\b(?:CVSS[:\s]*)?(10\.0|[0-9]\.[0-9])\b", text, flags=re.IGNORECASE)]
    score = max(scores) if scores else 0.0
    if score >= 9.0 or "CRITICAL" in upper:
        return "Critical"
    if score >= 7.0 or "HIGH" in upper or "EXPLOIT" in upper:
        return "High"
    if score >= 4.0 or "MEDIUM" in upper or "VULNERABLE" in upper:
        return "Medium"
    return "Low"


def _make_finding(
    *,
    target: Target,
    service: Service,
    script_id: str,
    title: str,
    severity: str,
    evidence: str,
    recommendation: str,
    confidence: str = "medium",
    cve: str = "",
) -> Finding:
    return Finding(
        tool="nmap",
        target=target.display,
        title=title,
        severity=severity,
        ip=target.scan_host,
        port=_endpoint(service),
        service=service.label,
        cve=cve,
        evidence=clean_text(evidence, 2000),
        recommendation=recommendation,
        confidence=confidence,
        source_id=f"nmap:{script_id}",
    )


def _endpoint(service: Service) -> str:
    if service.port <= 0:
        return ""
    return service.endpoint


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        key = f"{finding.source_id}|{finding.title}|{finding.port}"
        deduped.setdefault(key, finding)
    return list(deduped.values())


def _is_smb_signing_weak(lower: str) -> bool:
    patterns = (
        r"message[_ ]signing:\s*disabled",
        r"message signing enabled but not required",
        r"message signing.*not required",
        r"\bsigning:\s*disabled\b",
    )
    return any(re.search(pattern, lower) for pattern in patterns)


def _is_smb_anonymous_access(lower: str) -> bool:
    if "anonymous access" in lower and not re.search(r"anonymous access:\s*(<none>|none|denied|disabled)", lower):
        return True
    return any(marker in lower for marker in ("null session", "account_used: guest", "guest session"))


def _http_risky_methods(text: str) -> set[str]:
    if "http-methods" not in text.lower() and "supported methods" not in text.lower():
        return set()
    found = {match.upper() for match in re.findall(r"\b[A-Z]{3,10}\b", text)}
    return found.intersection(HTTP_RISKY_METHODS)


def _missing_security_header(lower: str) -> bool:
    headers = (
        "strict-transport-security",
        "x-frame-options",
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
    )
    markers = ("missing", "not present", "not configured", "header not set", "does not contain", "could not find")
    return any(header in lower for header in headers) and any(marker in lower for marker in markers)


def _has_positive_discovery(lower: str) -> bool:
    negative = ("not found", "no valid", "not vulnerable", "error", "failed", "timeout", "no response")
    positive = ("found", "allowed", "enabled", "success", "version", "exposed", "anonymous", "open relay")
    return any(marker in lower for marker in positive) and not any(marker in lower for marker in negative)


def _obsolete_tls_protocols(text: str) -> list[str]:
    if "ssl-enum-ciphers" not in text.lower():
        return []
    protocols = []
    for protocol in OBSOLETE_TLS:
        if re.search(rf"\b{re.escape(protocol)}\b", text, flags=re.IGNORECASE):
            protocols.append(protocol)
    return protocols


def _weak_tls_markers(text: str) -> list[str]:
    if "ssl-enum-ciphers" not in text.lower():
        return []
    upper = text.upper()
    return [marker for marker in WEAK_TLS_MARKERS if marker in upper]


def _weak_ssh_algorithms(lower: str) -> list[str]:
    if "ssh2-enum-algos" not in lower:
        return []
    return [marker for marker in WEAK_SSH_MARKERS if marker in lower]


def _snmp_information_exposed(lower: str) -> bool:
    if any(marker in lower for marker in ("timeout", "no response", "authorization error", "failed", "error")):
        return False
    return any(marker in lower for marker in ("sysdescr", "sysname", "enterprise", "engineid", "contact", "location"))


def _empty_password_detected(lower: str) -> bool:
    if "empty-password" not in lower and "empty password" not in lower:
        return False
    return any(marker in lower for marker in ("empty password", "password is empty", "<empty>", "no password"))
