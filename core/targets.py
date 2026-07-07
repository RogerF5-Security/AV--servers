from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

from .models import Target


TARGET_FILE_TEMPLATE = """# Add one authorized target per line.
# Supported formats:
#   192.0.2.10
#   example.internal
#   https://app.example.internal
#
# Lines starting with # are ignored.
"""


class TargetLoader:
    def __init__(self, targets_file: Path, target_override: str | None = None) -> None:
        self.targets_file = targets_file
        self.target_override = target_override

    def ensure_file(self) -> None:
        if not self.targets_file.exists():
            self.targets_file.parent.mkdir(parents=True, exist_ok=True)
            self.targets_file.write_text(TARGET_FILE_TEMPLATE, encoding="utf-8")

    def load(self) -> list[Target]:
        self.ensure_file()
        raw_items = [self.target_override] if self.target_override else self._read_file()
        targets: list[Target] = []
        seen: set[str] = set()
        for raw in raw_items:
            target = self._normalize(str(raw or "").strip())
            if not target:
                continue
            key = target.display.lower()
            if key in seen:
                continue
            seen.add(key)
            targets.append(target)
        return targets

    def _read_file(self) -> list[str]:
        lines = self.targets_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]

    def _normalize(self, raw: str) -> Target | None:
        if not raw:
            return None
        if raw.startswith(("http://", "https://")):
            parsed = urlparse(raw)
            host = parsed.hostname or ""
            if not host:
                return None
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            ip = self._resolve(host)
            return Target(
                raw=raw,
                host=host,
                display=host,
                kind="url",
                scheme=parsed.scheme,
                port=port,
                url=parsed._replace(fragment="").geturl(),
                ip=ip,
            )

        host = raw.split("/", 1)[0].strip().strip("[]")
        if not host:
            return None
        kind = "ip" if self._is_ip(host) else "host"
        ip = host if kind == "ip" else self._resolve(host)
        return Target(raw=raw, host=host, display=host, kind=kind, ip=ip)

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _resolve(self, host: str) -> str:
        try:
            return socket.gethostbyname(host)
        except OSError:
            return ""
