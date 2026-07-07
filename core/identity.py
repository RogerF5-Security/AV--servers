from __future__ import annotations

import getpass
import os
import re
import socket
import subprocess
import uuid
from datetime import datetime
from pathlib import Path

from .models import AuditIdentity


class IdentityDetector:
    @staticmethod
    def detect(route_probe: str = "1.1.1.1") -> AuditIdentity:
        started_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z%z")
        hostname = socket.gethostname()
        username = getpass.getuser()
        interface, source_ip = IdentityDetector._default_route(route_probe)
        if not source_ip:
            source_ip = IdentityDetector._udp_source_ip(route_probe)
        if not interface and source_ip:
            interface = IdentityDetector._interface_for_ip(source_ip)
        source_mac = IdentityDetector._mac_for_interface(interface)
        if not source_mac:
            source_mac = IdentityDetector._uuid_mac()
        all_interfaces = IdentityDetector._all_interfaces()
        return AuditIdentity(
            started_at=started_at,
            hostname=hostname,
            username=username,
            interface=interface or "no detectada",
            source_ip=source_ip or "no detectada",
            source_mac=source_mac or "no detectada",
            route_probe=route_probe,
            all_interfaces=all_interfaces,
        )

    @staticmethod
    def _default_route(route_probe: str) -> tuple[str, str]:
        try:
            result = subprocess.run(
                ["ip", "route", "get", route_probe],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return "", ""
        text = result.stdout.strip()
        interface = IdentityDetector._match(r"\bdev\s+(\S+)", text)
        source_ip = IdentityDetector._match(r"\bsrc\s+(\S+)", text)
        return interface, source_ip

    @staticmethod
    def _udp_source_ip(route_probe: str) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((route_probe, 80))
                return str(sock.getsockname()[0])
        except OSError:
            return ""

    @staticmethod
    def _interface_for_ip(source_ip: str) -> str:
        try:
            result = subprocess.run(
                ["ip", "-o", "addr", "show"],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        for line in result.stdout.splitlines():
            if f" {source_ip}/" in line:
                parts = line.split()
                return parts[1] if len(parts) > 1 else ""
        return ""

    @staticmethod
    def _mac_for_interface(interface: str) -> str:
        if not interface:
            return ""
        sys_path = Path("/sys/class/net") / interface / "address"
        try:
            if sys_path.exists():
                return sys_path.read_text(encoding="utf-8").strip()
        except OSError:
            pass
        try:
            result = subprocess.run(
                ["ip", "link", "show", "dev", interface],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return IdentityDetector._match(r"\blink/ether\s+([0-9a-fA-F:]{17})", result.stdout)

    @staticmethod
    def _uuid_mac() -> str:
        node = uuid.getnode()
        if node & (1 << 40):
            return ""
        return ":".join(f"{(node >> shift) & 0xff:02x}" for shift in range(40, -1, -8))

    @staticmethod
    def _all_interfaces() -> list[dict[str, str]]:
        interfaces: list[dict[str, str]] = []
        if os.name == "nt":
            return interfaces
        try:
            result = subprocess.run(
                ["ip", "-o", "-4", "addr", "show", "scope", "global"],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return interfaces
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            ip_cidr = parts[3]
            interfaces.append(
                {
                    "interface": iface,
                    "ip": ip_cidr.split("/", 1)[0],
                    "cidr": ip_cidr,
                    "mac": IdentityDetector._mac_for_interface(iface) or "-",
                }
            )
        return interfaces

    @staticmethod
    def _match(pattern: str, text: str) -> str:
        match = re.search(pattern, text)
        return match.group(1) if match else ""
