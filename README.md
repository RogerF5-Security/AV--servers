# AV--servers

Escaner modular zero-touch para auditorias de servidores y superficies web en Kali Linux.

AV--servers ejecuta herramientas nativas de Kali, guarda evidencia cruda, genera reportes en espanol y no se detiene esperando confirmaciones. Si el auditor quiere revisar manualmente cada hallazgo, puede activar el modo interactivo con `--interactive`.

## Que Hace

- Lee objetivos desde `targets.txt` o desde `--target`.
- Ejecuta Nmap para descubrimiento de puertos y deteccion de servicios.
- Ejecuta `nmap --script vuln` para validar scripts NSE de vulnerabilidad.
- Ejecuta perfiles NSE profundos por servicio: SMB, HTTP, TLS, FTP, SSH, RDP, SMTP, MySQL, MSSQL, PostgreSQL, Redis, Docker y VNC.
- Ejecuta un perfil UDP profundo para DNS, NTP y SNMP cuando se usa el modo `deep`.
- Correlaciona versiones detectadas contra Exploit-DB con `searchsploit --nmap`.
- Si el barrido inicial no devuelve servicios, ejecuta un fallback sobre puertos comunes para no finalizar con reportes vacios.
- Ejecuta enumeracion SMB con `smbmap` y `enum4linux-ng` cuando corresponde.
- Ejecuta fingerprinting web con `whatweb`.
- Ejecuta validacion de vulnerabilidades con `nuclei` en modo automatico y por templates.
- Ejecuta checks web con `nikto`.
- Genera evidencia en `raw_outputs/`.
- Genera notas por hallazgo en `evidence_notes/`.
- Genera reportes Markdown y HTML completamente en espanol.
- Genera un reporte final consolidado con todas las IPs/URLs de la campana.
- Muestra al iniciar fecha/hora, hostname, IP origen, interfaz y MAC para whitelist del SOC.
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
- instala `nmap`, `whatweb`, `nikto`, `smbmap`, `enum4linux-ng`, `exploitdb`, Python, Go y utilidades base;
- crea `.venv`;
- instala dependencias Python;
- instala o actualiza Nuclei;
- actualiza templates de Nuclei;
- valida que existan templates reales de Nuclei (`.yaml`/`.yml`);
- valida si la herramienta tiene todo completo para iniciar.

Si no quieres actualizar todos los paquetes del sistema:

```bash
./install.sh --no-upgrade
```

Activar entorno:

```bash
source .venv/bin/activate
```

Verificar en cualquier momento si todo esta listo:

```bash
./install.sh --check-only
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

Por defecto se usa perfil `deep` y timeout de `3600` segundos por comando. La herramienta esta pensada para completar un escaneo real, no para terminar rapido con conteos vacios.

Al iniciar, la herramienta imprime un bloque como este para que el SOC pueda dar lista blanca:

```text
Identidad de ejecucion para SOC
Fecha/hora de inicio        2026-07-07 14:30:00 CST-0600
Hostname                    kali
Usuario local               kali
Interfaz origen             eth0
IP origen para whitelist    10.189.169.200
MAC origen para whitelist   00:11:22:33:44:55
Objetivos cargados          15
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
- Nuclei corre dos perfiles por URL: automatico (`-as`) y templates (`cves/`, `vulnerabilities/`, `misconfiguration/`);
- Nmap ejecuta una fase dedicada `--script vuln`;
- Nmap ejecuta scripts dirigidos para misconfiguraciones reales como SMB signing no requerido, FTP anonimo, HTTP TRACE/PUT/DELETE, TLS obsoleto/debil, RDP sin NLA, SMTP open relay, credenciales vacias en bases de datos, Redis expuesto, Docker API expuesta, SNMP legible y DNS recursivo;
- Searchsploit correlaciona el XML de Nmap contra Exploit-DB.
- El parser de Nmap convierte evidencia NSE de configuracion vulnerable en hallazgos aunque no exista una cadena `CVE-...`.
- El parser de Nuclei entiende JSONL y tambien la salida textual clasica de Nuclei.

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
  <timestamp>_reporte_final_todos_los_objetivos.md
  <timestamp>_reporte_final_todos_los_objetivos.html
  <timestamp>_<target>/
    raw_outputs/
      nmap_discovery.log
      nmap_discovery.xml
      nmap_servicios_detectados.log
      nmap_servicios_detectados.xml
      nmap_vuln_scripts.xml
      nmap_smb_deep.xml
      nmap_tls_deep.xml
      nmap_udp_deep.xml
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
| `searchsploit` | Correlacion de servicios/versiones con Exploit-DB. |

## Reporte

Cada objetivo genera su reporte individual y cada corrida genera un reporte final consolidado con todas las IPs/URLs.

El reporte final incluye:

- fecha/hora de inicio y fin;
- hostname local;
- usuario local;
- interfaz de salida;
- IP origen para whitelist SOC;
- MAC origen para whitelist SOC;
- tabla de todos los objetivos;
- conteo global por severidad;
- vulnerabilidades consolidadas;
- falsos positivos descartados.

Cada reporte individual incluye:

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
./install.sh --check-only
```

Si el reporte vuelve a quedar en cero, revisa primero la tabla `Herramientas ejecutadas` del HTML/Markdown. Ahi queda el comando exacto, retorno, duracion y cola de salida de cada herramienta; si Nuclei no cargo templates o Nmap no pudo ejecutar un script, la evidencia queda visible ahi.

Forzar resolucion local de templates:

```bash
export NUCLEI_TEMPLATES="$HOME/.local/nuclei-templates"
./install.sh --check-only
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
