# AV--servers

Escaner modular zero-touch para auditorias de servidores y superficies web en Kali Linux.

AV--servers ejecuta herramientas nativas de Kali, guarda evidencia cruda, genera reportes en espanol y no se detiene esperando confirmaciones. Si el auditor quiere revisar manualmente cada hallazgo, puede activar el modo interactivo con `--interactive`.

## Que Hace

- Lee objetivos desde `targets.txt` o desde `--target`.
- Ejecuta Nmap para descubrimiento de puertos y deteccion de servicios.
- Si el barrido inicial no devuelve servicios, ejecuta un fallback sobre puertos comunes para no finalizar con reportes vacios.
- Ejecuta enumeracion SMB con `smbmap` y `enum4linux-ng` cuando corresponde.
- Ejecuta fingerprinting web con `whatweb`.
- Ejecuta validacion de vulnerabilidades con `nuclei`.
- Ejecuta checks web con `nikto`.
- Genera evidencia en `raw_outputs/`.
- Genera notas por hallazgo en `evidence_notes/`.
- Genera reportes Markdown y HTML completamente en espanol.
- Mantiene `state.json`, `commands.jsonl` y `exclusions.jsonl` para trazabilidad.

## Instalacion Automatica

En Kali:

```bash
git clone https://github.com/RogerF5-Security/AV--servers.git
cd AV--servers
chmod +x install.sh
./install.sh
```

El instalador:

- ejecuta `sudo apt update`;
- ejecuta `sudo apt upgrade -y`;
- instala `nmap`, `whatweb`, `nikto`, `smbmap`, `enum4linux-ng`, Python, Go y utilidades base;
- crea `.venv`;
- instala dependencias Python;
- instala o actualiza Nuclei;
- actualiza templates de Nuclei;
- valida la sintaxis del motor.

Si no quieres actualizar todos los paquetes del sistema:

```bash
./install.sh --no-upgrade
```

Activar entorno:

```bash
source .venv/bin/activate
```

## Uso Zero-Touch

Editar `targets.txt`:

```text
10.189.169.130
10.189.169.131
https://app.example.internal
```

Ejecutar todo el escaneo:

```bash
python3 vulnerability_engine.py
```

Ejecutar un objetivo unico:

```bash
python3 vulnerability_engine.py --target 10.189.169.130
```

En modo zero-touch, todos los hallazgos detectados se agregan al reporte con nota automatica:

```text
Confirmado automaticamente por modo zero-touch.
```

## Modo Interactivo Opcional

Si quieres pausar ante hallazgos `Medium`, `High` o `Critical`:

```bash
python3 vulnerability_engine.py --interactive
```

Opciones del menu:

| Opcion | Accion |
|---|---|
| `A` | Agregar el hallazgo al reporte formal y adjuntar una nota. |
| `D` | Descartar como falso positivo y registrarlo en `exclusions.jsonl`. |
| `P` | Abrir una shell temporal para validar manualmente. |
| `C` | Continuar sin mas pausas para esa IP. |

## Por Que Ya No Se Queda Solo En Nmap

La version actual corrige el comportamiento observado donde se ejecutaba Nmap y luego terminaba. Ahora:

- usa `-sT` por defecto para funcionar sin `sudo`;
- si se fuerza `-sS` sin privilegios, reintenta automaticamente con `-sT`;
- si no hay servicios detectados en el primer barrido, ejecuta deteccion sobre puertos comunes;
- si no se detectan servicios web pero el objetivo es una IP, prueba `http://IP` y `https://IP`;
- SMB se intenta cuando se detecta 139/445 o cuando no hay datos de servicios y el fallback esta activo;
- Nuclei recibe templates como argumentos separados para mayor compatibilidad.

## Ejemplos Utiles

Escaneo normal:

```bash
python3 vulnerability_engine.py
```

Escaneo con timeout mas largo:

```bash
python3 vulnerability_engine.py --timeout 3600
```

Escaneo con SYN scan usando sudo:

```bash
sudo .venv/bin/python vulnerability_engine.py \
  --target 10.189.169.130 \
  --nmap-discovery-args "-sS -p- --min-rate 2000 -Pn"
```

Omitir una herramienta:

```bash
python3 vulnerability_engine.py --target 10.189.169.130 --skip-tool nikto
```

Usar solo severidades altas en Nuclei:

```bash
python3 vulnerability_engine.py \
  --target https://app.example.internal \
  --nuclei-severity critical,high
```

Desactivar fallbacks:

```bash
python3 vulnerability_engine.py --target 10.189.169.130 --no-fallback-checks
```

## Estructura de Salida

```text
scans/
  latest_campaign_summary.md
  <timestamp>_<target>/
    raw_outputs/
      nmap_discovery.log
      nmap_discovery.xml
      nmap_servicios_detectados.log
      nmap_servicios_detectados.xml
      whatweb_http_<target>.log
      nuclei_http_<target>.log
      nikto_http_<target>.log
    reports/
      <target>_reporte.md
      <target>_reporte.html
    evidence_notes/
      <severidad>_<herramienta>_<hallazgo>.md
    commands.jsonl
    exclusions.jsonl
    state.json
```

## Herramientas Integradas

| Herramienta | Uso |
|---|---|
| `nmap` | Descubrimiento, puertos, servicios, versiones y NSE. |
| `smbmap` | Enumeracion de shares, permisos y acceso SMB. |
| `enum4linux-ng` | Enumeracion SMB/NetBIOS. |
| `whatweb` | Fingerprinting HTTP/HTTPS. |
| `nuclei` | Validacion con templates de CVEs, vulnerabilities y misconfiguration. |
| `nikto` | Checks de servidor web. |

## Reporte

Cada reporte incluye:

- resumen ejecutivo;
- conteo por severidad;
- alcance y metodologia;
- servicios identificados;
- herramientas ejecutadas;
- vulnerabilidades confirmadas;
- evidencia cruda;
- notas del auditor;
- recomendaciones de remediacion;
- falsos positivos descartados.

## Arquitectura

```text
AV--servers/
  vulnerability_engine.py
  install.sh
  targets.txt
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

## Troubleshooting

Verificar herramientas:

```bash
which nmap nuclei smbmap enum4linux-ng whatweb nikto
```

Actualizar templates:

```bash
nuclei -update-templates
```

Si Nmap es lento en `-p-`, ajustar el perfil:

```bash
python3 vulnerability_engine.py \
  --target 10.189.169.130 \
  --nmap-discovery-args "-sT --top-ports 1000 -Pn"
```

Si necesitas evidencia mas profunda en Nmap:

```bash
sudo .venv/bin/python vulnerability_engine.py \
  --target 10.189.169.130 \
  --nmap-discovery-args "-sS -p- --min-rate 2000 -Pn"
```
