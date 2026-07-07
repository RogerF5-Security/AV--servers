from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable

from .models import CommandResult, Finding


LineFindingParser = Callable[[str, str], list[Finding]]
FindingHandler = Callable[[Finding], None]


class ToolUnavailable(RuntimeError):
    pass


class CommandRunner:
    def __init__(self, timeout: int) -> None:
        self.timeout = timeout

    def available(self, binary: str) -> bool:
        return shutil.which(binary) is not None

    def require(self, binary: str) -> str:
        resolved = shutil.which(binary)
        if not resolved:
            raise ToolUnavailable(f"{binary} no se encontro en PATH")
        return resolved

    def run(
        self,
        *,
        tool: str,
        profile: str,
        command: list[str],
        raw_output_path: Path,
        timeout: int | None = None,
        line_parser: LineFindingParser | None = None,
        finding_handler: FindingHandler | None = None,
    ) -> CommandResult:
        started = time.monotonic()
        raw_output_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_parts: list[str] = []
        timed_out = False
        returncode: int | None = None
        deadline = started + float(timeout or self.timeout)

        with raw_output_path.open("w", encoding="utf-8", errors="replace") as raw:
            raw.write("$ " + " ".join(command) + "\n\n")
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
            except OSError as exc:
                raw.write(f"\n[runner-error] {exc}\n")
                return CommandResult(tool, profile, command, raw_output_path, None, False, time.monotonic() - started, "", str(exc))

            assert process.stdout is not None
            try:
                for line in iter(process.stdout.readline, ""):
                    stdout_parts.append(line)
                    raw.write(line)
                    raw.flush()
                    if line_parser and finding_handler:
                        for finding in line_parser(line, str(raw_output_path)):
                            finding_handler(finding)
                    if time.monotonic() > deadline:
                        timed_out = True
                        self._terminate(process)
                        break
                if not timed_out:
                    returncode = process.wait(timeout=5)
                else:
                    returncode = process.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                self._terminate(process)
                returncode = process.returncode
            finally:
                try:
                    if process.stdout:
                        process.stdout.close()
                except Exception:
                    pass

            duration = time.monotonic() - started
            raw.write(f"\n[runner] returncode={returncode} timed_out={timed_out} duration={duration:.2f}s\n")

        return CommandResult(
            tool=tool,
            profile=profile,
            command=command,
            raw_output_path=raw_output_path,
            returncode=returncode,
            timed_out=timed_out,
            duration_seconds=duration,
            stdout="".join(stdout_parts),
            stderr="",
        )

    def _terminate(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
