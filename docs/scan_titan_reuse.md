# Scan Titan Reuse Analysis

This project reuses the practical architecture patterns from the local Scan Titan codebase at:

`C:\Users\R0G3R\Documents\Tools\History`

## Reused Concepts

- Finding model: normalized severity, deterministic fingerprinting, evidence fields, remediation fields, and report-ready serialization.
- Target loading: line-based `targets.txt`, comment skipping, URL/IP/host normalization, deduplication.
- External tool execution: Nmap and Nuclei are treated as first-class evidence producers with raw output stored on disk.
- Parser strategy: Nmap XML parsing, Nuclei JSONL parsing, and line-based extraction for terminal-native tools.
- Reporting: executive summary, severity counts, detailed technical findings, raw evidence references, and false-positive appendix.
- Workspace hygiene: scan artifacts are written under one structured scan folder and not mixed into source directories.

## Intentional Refactor

Scan Titan is a web-focused asynchronous scanner. `AV--servers` is a Kali-oriented network and web assessment runner. The code therefore refactors the reusable ideas into a smaller service-driven CLI:

- `core/runner.py` streams external tool output and stores raw logs.
- `core/interactive.py` pauses on Medium+ findings by default and lets the auditor confirm, discard, open a shell, or continue without pauses for that target.
- `parsers/` contains one parser per Kali tool so new modules can be added without touching the orchestration core.
- `reporting/` generates Markdown and HTML reports suitable for printing to PDF.

## Tool Coverage

- Nmap discovery and service/NSE validation.
- SMB enumeration through `smbmap` and `enum4linux-ng`.
- Web fingerprinting through `whatweb`.
- Vulnerability template validation through `nuclei`.
- Web server checks through `nikto`.
- Auxiliary Nmap modules for FTP, RDP, and WinRM where those services are detected.
