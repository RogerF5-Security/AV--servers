#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NO_UPGRADE=0

for arg in "$@"; do
  case "$arg" in
    --no-upgrade)
      NO_UPGRADE=1
      ;;
    -h|--help)
      cat <<'HELP'
Uso:
  ./install.sh
  ./install.sh --no-upgrade

Acciones:
  - Ejecuta apt update.
  - Actualiza paquetes del sistema salvo que uses --no-upgrade.
  - Instala dependencias Kali: nmap, whatweb, nikto, smbmap, enum4linux-ng.
  - Instala Python/Rich y herramientas auxiliares.
  - Instala o actualiza Nuclei y sus templates.
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

cd "$PROJECT_DIR"

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

log "Instalacion finalizada"
cat <<EOF

Uso recomendado:
  cd "$PROJECT_DIR"
  source .venv/bin/activate
  python3 vulnerability_engine.py

Modo interactivo opcional:
  python3 vulnerability_engine.py --interactive

EOF
