# Analisis de Reutilizacion de Scan Titan

Este proyecto toma patrones practicos del framework local Scan Titan ubicado en:

`C:\Users\R0G3R\Documents\Tools\History`

## Conceptos Reutilizados

- Modelo de hallazgos con severidad normalizada, fingerprint deterministico, evidencia, remediacion y serializacion para reporte.
- Carga de objetivos desde `targets.txt`, ignorando comentarios y duplicados.
- Ejecucion de herramientas externas con salida cruda persistida en disco.
- Parseo de Nmap XML y Nuclei JSONL.
- Separacion entre orquestacion, parseo, evidencia y reporting.
- Reportes con resumen ejecutivo, metodologia, tabla de riesgo, detalle tecnico y anexo de falsos positivos.
- Higiene de workspace: los artefactos de auditoria viven dentro de `scans/`.

## Refactor Intencional

Scan Titan es un scanner web asincrono. AV--servers esta orientado a auditoria de servidores en Kali Linux, por eso se refactorizo hacia una CLI modular basada en herramientas del sistema:

- `core/runner.py` ejecuta comandos, captura salida y aplica timeouts.
- `core/orchestrator.py` decide fases por objetivo y activa fallbacks zero-touch.
- `core/interactive.py` solo se usa cuando el auditor pasa `--interactive`.
- `parsers/` contiene un parser por herramienta.
- `reporting/` genera Markdown y HTML en espanol.

## Cobertura de Herramientas

- Nmap para descubrimiento y deteccion de servicios.
- Smbmap y enum4linux-ng para SMB.
- WhatWeb para fingerprinting HTTP/HTTPS.
- Nuclei para CVEs, vulnerabilidades y misconfigurations.
- Nikto para checks web complementarios.

## Mejora Zero-Touch

La version actual evita que el flujo termine solo con Nmap:

- usa `-sT` por defecto para no requerir sudo;
- reintenta con `-sT` si `-sS` falla por privilegios;
- lanza deteccion sobre puertos comunes si no se obtienen servicios;
- prueba URLs HTTP/HTTPS basicas cuando no hay servicios web detectados;
- confirma hallazgos automaticamente en modo zero-touch para que aparezcan en el reporte formal.
