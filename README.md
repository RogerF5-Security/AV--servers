# AV--servers

Escaner modular de vulnerabilidades de red y web para Kali Linux, orientado a auditorias tecnicas de servidores, servicios SMB y superficies HTTP/HTTPS.

El motor combina automatizacion zero-touch con revision humana controlada: ejecuta herramientas nativas de Kali, detecta hallazgos relevantes en tiempo real, pausa ante evidencia importante y genera reportes formales en Markdown y HTML.

## Capacidades Principales

- Lectura de objetivos desde `targets.txt` o mediante `--target`.
- Descubrimiento y fingerprinting con Nmap.
- Enumeracion SMB con `smbmap` y `enum4linux-ng`.
- Fingerprinting web con `whatweb`.
- Validacion de CVEs, misconfigurations y vulnerabilidades web con `nuclei`.
- Checks web complementarios con `nikto`.
- Pausas interactivas para confirmar o descartar hallazgos.
- Evidencia cruda por herramienta en `raw_outputs/`.
- Notas del auditor en `evidence_notes/`.
- Reportes ejecutivos y tecnicos en Markdown y HTML.
- Estado JSON para trazabilidad y continuidad operativa.

## Arquitectura

```text
AV--servers/
  vulnerability_engine.py
  targets.txt
  requirements.txt
  core/
    config.py
    interactive.py
    models.py
    orchestrator.py
    runner.py
    targets.py
    workspace.py
  parsers/
    enum4linux.py
    nikto.py
    nmap.py
    nuclei.py
    smbmap.py
    whatweb.py
  reporting/
    generator.py
    templates.py
  docs/
    scan_titan_reuse.md
```

## Instalacion en Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap whatweb nikto smbmap enum4linux-ng
python3 -m pip install -r requirements.txt
```

Instalar o actualizar Nuclei:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

Validar dependencias disponibles:

```bash
which nmap nuclei smbmap enum4linux-ng whatweb nikto
python3 vulnerability_engine.py --help
```

## Configuracion de Objetivos

Editar `targets.txt` y agregar un objetivo por linea:

```text
192.0.2.10
server.internal
https://app.example.internal
```

Las lineas que empiezan con `#` se ignoran.

## Uso Rapido

Ejecutar usando `targets.txt`:

```bash
python3 vulnerability_engine.py
```

Ejecutar un unico objetivo:

```bash
python3 vulnerability_engine.py --target 192.0.2.10
```

Ejecutar sin prompts interactivos:

```bash
python3 vulnerability_engine.py --target 192.0.2.10 --non-interactive
```

Smoke test rapido sin herramientas pesadas:

```bash
python3 vulnerability_engine.py \
  --target 192.0.2.10 \
  --non-interactive \
  --skip-tool nuclei \
  --skip-tool nikto
```

## Flujo Interactivo del Auditor

Cuando una herramienta detecta una vulnerabilidad potencial con severidad `Medium`, `High` o `Critical`, el motor pausa el flujo de esa IP y muestra la evidencia exacta.

Opciones disponibles:

| Opcion | Accion |
|---|---|
| `A` | Agregar el hallazgo al reporte formal y adjuntar una nota del auditor. |
| `D` | Descartar el hallazgo como falso positivo y guardarlo en `exclusions.jsonl`. |
| `P` | Abrir una shell temporal para validar manualmente y luego volver al menu. |
| `C` | Continuar sin mas pausas para esa IP y autoagregar los hallazgos siguientes. |

## Perfiles y Argumentos Utiles

Cambiar argumentos de descubrimiento Nmap:

```bash
python3 vulnerability_engine.py \
  --target 192.0.2.10 \
  --nmap-discovery-args "-sS -p- --min-rate 3000 -Pn"
```

Limitar severidades de Nuclei:

```bash
python3 vulnerability_engine.py \
  --target https://app.example.internal \
  --nuclei-severity critical,high
```

Omitir herramientas especificas:

```bash
python3 vulnerability_engine.py \
  --target 192.0.2.10 \
  --skip-tool nikto \
  --skip-tool enum4linux-ng
```

Cambiar severidades que activan pausa:

```bash
python3 vulnerability_engine.py \
  --target https://app.example.internal \
  --pause-severities Critical,High
```

## Salida y Reportes

Cada objetivo genera un workspace independiente:

```text
scans/
  latest_campaign_summary.md
  <timestamp>_<target_name>/
    raw_outputs/
      nmap_discovery.log
      nmap_discovery.xml
      nuclei_<url>.log
      whatweb_<url>.log
    reports/
      <target>_report.md
      <target>_report.html
    evidence_notes/
      <severity>_<tool>_<finding>.md
    commands.jsonl
    exclusions.jsonl
    state.json
```

El reporte incluye:

- resumen ejecutivo;
- alcance y metodologia;
- servicios identificados;
- vulnerabilidades confirmadas ordenadas por severidad;
- evidencia cruda parseada;
- notas del auditor;
- recomendaciones de remediacion;
- anexo de falsos positivos descartados.

## Modulos de Herramientas

| Herramienta | Fase | Funcion |
|---|---|---|
| `nmap` | Descubrimiento y validacion | Puertos, servicios, versiones y scripts NSE. |
| `smbmap` | SMB | Shares, permisos y acceso anonimo. |
| `enum4linux-ng` | SMB | Enumeracion de usuarios, grupos, shares y sesiones nulas. |
| `whatweb` | Web | Fingerprinting de tecnologias HTTP/HTTPS. |
| `nuclei` | Web/Vuln | Templates de CVEs, vulnerabilities y misconfiguration. |
| `nikto` | Web | Checks de servidor web y configuraciones debiles. |

## Relacion con Scan Titan

Este proyecto refactoriza patrones utiles del framework local Scan Titan:

- modelo de hallazgos con severidad normalizada;
- fingerprinting deterministico;
- parseo de Nmap/Nuclei;
- separacion entre ejecucion, parseo y reporting;
- enfoque zero-touch con evidencia formal.

Detalles en `docs/scan_titan_reuse.md`.

## Troubleshooting

Si una herramienta no se ejecuta:

```bash
which <tool>
<tool> --help
```

Si Nuclei no encuentra templates:

```bash
nuclei -update
nuclei -update-templates
```

Si Nmap requiere privilegios para SYN scan:

```bash
sudo python3 vulnerability_engine.py --target 192.0.2.10
```

Si se prefiere evitar `sudo`, usar un perfil TCP connect:

```bash
python3 vulnerability_engine.py \
  --target 192.0.2.10 \
  --nmap-discovery-args "-sT -p- --min-rate 2000 -Pn"
```

## Estado del Proyecto

Version inicial funcional:

- CLI operativa.
- Parsers por herramienta.
- Menu interactivo.
- Reportes Markdown/HTML.
- Workspace estructurado por ejecucion.
- Documentacion de instalacion y uso.
