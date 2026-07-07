#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NO_UPGRADE=0
CHECK_ONLY=0
REQUIRED_TOOLS=(python3 nmap whatweb nikto smbmap enum4linux-ng nuclei searchsploit)
OPTIONAL_TOOLS=()

for arg in "$@"; do
  case "$arg" in
    --no-upgrade)
      NO_UPGRADE=1
      ;;
    --check-only)
      CHECK_ONLY=1
      ;;
    -h|--help)
      cat <<'HELP'
Uso:
  ./install.sh
  ./install.sh --no-upgrade
  ./install.sh --check-only

Acciones:
  - Ejecuta apt update.
  - Actualiza paquetes del sistema salvo que uses --no-upgrade.
  - Instala dependencias Kali: nmap, whatweb, nikto, smbmap, enum4linux-ng, exploitdb.
  - Instala Python/Rich y herramientas auxiliares.
  - Instala o actualiza Nuclei y sus templates.
  - Verifica si AV--servers esta listo para iniciar.
HELP
      exit 0
      ;;
    *)
      echo "[!] Argumento no reconocido: $arg" >&2
      exit 2
      ;;
  esac
done

log() {
  printf '\n[+] %s\n' "$1"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

find_nuclei_template_dir() {
  local candidates=()
  if [[ -n "${NUCLEI_TEMPLATES:-}" ]]; then
    candidates+=("$NUCLEI_TEMPLATES")
  fi
  candidates+=(
    "$HOME/.local/nuclei-templates"
    "$HOME/nuclei-templates"
    "$PROJECT_DIR/nuclei-templates"
    "$PROJECT_DIR/nuclei-templates-full"
  )
  local dir count
  for dir in "${candidates[@]}"; do
    if [[ -d "$dir" ]]; then
      count="$(find "$dir" -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | wc -l | tr -d ' ')"
      if [[ "${count:-0}" -gt 0 ]]; then
        printf '%s|%s\n' "$dir" "$count"
        return 0
      fi
    fi
  done
  return 1
}

check_ready() {
  local missing=0
  log "Verificando herramientas requeridas"
  for tool in "${REQUIRED_TOOLS[@]}"; do
    if need_cmd "$tool"; then
      printf '[OK] %s -> %s\n' "$tool" "$(command -v "$tool")"
    else
      printf '[FALTA] %s no esta en PATH\n' "$tool" >&2
      missing=1
    fi
  done

  log "Verificando herramientas recomendadas"
  for tool in "${OPTIONAL_TOOLS[@]}"; do
    if need_cmd "$tool"; then
      printf '[OK] %s -> %s\n' "$tool" "$(command -v "$tool")"
    else
      printf '[WARN] %s no esta en PATH\n' "$tool" >&2
    fi
  done

  log "Verificando entorno Python"
  if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    "$PROJECT_DIR/.venv/bin/python" - <<'PY'
import rich
print("[OK] Python venv y rich disponibles")
PY
  else
    printf '[FALTA] .venv/bin/python no existe. Ejecuta ./install.sh\n' >&2
    missing=1
  fi

  log "Verificando motor"
  if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    "$PROJECT_DIR/.venv/bin/python" -B -m py_compile vulnerability_engine.py core/*.py parsers/*.py reporting/*.py || missing=1
    "$PROJECT_DIR/.venv/bin/python" vulnerability_engine.py --help >/dev/null || missing=1
  else
    python3 -B -m py_compile vulnerability_engine.py core/*.py parsers/*.py reporting/*.py || missing=1
    python3 vulnerability_engine.py --help >/dev/null || missing=1
  fi

  log "Verificando templates de Nuclei"
  if need_cmd nuclei; then
    local templates_info templates_dir templates_count
    if templates_info="$(find_nuclei_template_dir)"; then
      templates_dir="${templates_info%%|*}"
      templates_count="${templates_info##*|}"
      printf '[OK] Templates de Nuclei -> %s (%s archivos)\n' "$templates_dir" "$templates_count"
    else
      printf '[FALTA] No se encontraron templates de Nuclei con archivos .yaml/.yml\n' >&2
      printf '        Ejecuta: nuclei -update-templates o vuelve a correr ./install.sh\n' >&2
      missing=1
    fi
  else
    printf '[FALTA] nuclei no esta disponible para validar templates\n' >&2
    missing=1
  fi

  log "Verificando targets.txt"
  if [[ -f targets.txt ]] && grep -Ev '^\s*(#|$)' targets.txt >/dev/null 2>&1; then
    printf '[OK] targets.txt contiene objetivos\n'
  else
    printf '[WARN] targets.txt no tiene objetivos activos. Agrega una IP, host o URL por linea.\n' >&2
  fi

  if [[ "$missing" -eq 0 ]]; then
    log "AV--servers esta listo para iniciar"
    return 0
  fi
  log "AV--servers aun no esta completo para iniciar"
  return 1
}

cd "$PROJECT_DIR"

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  check_ready
  exit $?
fi

log "Actualizando indices de paquetes"
sudo apt update

if [[ "$NO_UPGRADE" -eq 0 ]]; then
  log "Actualizando paquetes instalados del sistema"
  sudo DEBIAN_FRONTEND=noninteractive apt -y upgrade
else
  log "Se omite apt upgrade por --no-upgrade"
fi

log "Instalando herramientas de Kali y dependencias Python"
sudo apt install -y \
  python3 \
  python3-pip \
  python3-venv \
  python3-rich \
  git \
  curl \
  nmap \
  whatweb \
  nikto \
  smbmap \
  enum4linux-ng \
  exploitdb \
  golang-go

log "Preparando entorno Python local"
python3 -m venv .venv
"$PROJECT_DIR/.venv/bin/python" -m pip install --upgrade pip
"$PROJECT_DIR/.venv/bin/python" -m pip install -r requirements.txt

if ! need_cmd nuclei; then
  log "Nuclei no esta en PATH; instalando con Go"
  GOPATH="${GOPATH:-$HOME/go}"
  GOBIN="${GOBIN:-$GOPATH/bin}"
  mkdir -p "$GOBIN"
  GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    echo "export PATH=\"\$PATH:$GOBIN\"" >> "$HOME/.bashrc"
    export PATH="$PATH:$GOBIN"
  fi
else
  log "Nuclei detectado en PATH"
fi

if need_cmd nuclei; then
  log "Actualizando Nuclei y templates"
  nuclei -update || true
  nuclei -update-templates || true
  if ! find_nuclei_template_dir >/dev/null 2>&1; then
    log "Descargando nuclei-templates desde GitHub"
    template_target=""
    for candidate in "$HOME/.local/nuclei-templates" "$PROJECT_DIR/nuclei-templates" "$PROJECT_DIR/nuclei-templates-full" "$HOME/nuclei-templates-avservers"; do
      if [[ ! -e "$candidate" ]]; then
        template_target="$candidate"
        break
      fi
    done
    if [[ -z "$template_target" ]]; then
      echo "[!] No hay una ruta libre para descargar nuclei-templates. Define NUCLEI_TEMPLATES con una ruta valida." >&2
      exit 1
    fi
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$template_target"
  fi
else
  echo "[!] Nuclei no quedo disponible en PATH. Reabre la terminal o agrega ~/go/bin al PATH." >&2
fi

if [[ ! -f targets.txt ]]; then
  log "Creando targets.txt"
  cat > targets.txt <<'TARGETS'
# Agrega un objetivo autorizado por linea.
# Ejemplos:
# 192.0.2.10
# server.internal
# https://app.example.internal
TARGETS
fi

log "Validando sintaxis del motor"
"$PROJECT_DIR/.venv/bin/python" -B -m py_compile vulnerability_engine.py core/*.py parsers/*.py reporting/*.py

check_ready

log "Instalacion finalizada"
cat <<EOF

Uso recomendado:
  cd "$PROJECT_DIR"
  source .venv/bin/activate
  python3 vulnerability_engine.py

Modo interactivo opcional:
  python3 vulnerability_engine.py --interactive

Verificacion rapida:
  ./install.sh --check-only

EOF
