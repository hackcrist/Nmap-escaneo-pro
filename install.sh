#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

detect_script_file() {
  if [[ -f "nmap pro.py" ]]; then
    echo "nmap pro.py"
    return
  fi
  if [[ -f "nmap_pro.py" ]]; then
    echo "nmap_pro.py"
    return
  fi
  local found
  found="$(find . -maxdepth 1 -type f -name "*nmap*pro*.py" | head -n 1 | sed 's|^\./||')"
  if [[ -n "${found}" ]]; then
    echo "$found"
    return
  fi
  found="$(find . -maxdepth 1 -type f -name "*.py" | head -n 1 | sed 's|^\./||')"
  if [[ -n "${found}" ]]; then
    echo "$found"
    return
  fi
  echo ""
}

is_termux() {
  [[ "${PREFIX:-}" == *"com.termux"* ]]
}

install_python_packages() {
  local allow_pip_upgrade="${1:-yes}"
  if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
  else
    echo "[ERROR] Python no encontrado."
    exit 1
  fi

  if [[ "$allow_pip_upgrade" == "yes" ]]; then
    "$PY_BIN" -m pip install --upgrade pip
  fi
  if [[ -f "requirements.txt" ]]; then
    "$PY_BIN" -m pip install -r requirements.txt
  else
    "$PY_BIN" -m pip install colorama
  fi
}

if is_termux; then
  echo "[INFO] Entorno detectado: Termux"
  pkg update -y
  pkg install -y python nmap git python-colorama
  # En Termux no se debe instalar paquetes Python globales con pip.
  # Se usa python-colorama desde pkg para evitar el error de "Installing pip is forbidden".
  SCRIPT_FILE="$(detect_script_file)"
  echo "[OK] Instalacion completada en Termux."
  if [[ -n "$SCRIPT_FILE" ]]; then
    echo "[RUN] python '$SCRIPT_FILE' --help"
  else
    echo "[WARN] No se detecto automaticamente el script principal."
  fi
  exit 0
fi

if command -v apt-get >/dev/null 2>&1; then
  echo "[INFO] Entorno detectado: Debian/Ubuntu/Kali"
  SUDO=""
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      SUDO="sudo"
    else
      echo "[ERROR] Necesitas root o sudo para instalar dependencias del sistema."
      exit 1
    fi
  fi

  $SUDO apt-get update -y
  $SUDO apt-get install -y python3 python3-pip nmap git
  install_python_packages "yes"
  SCRIPT_FILE="$(detect_script_file)"
  echo "[OK] Instalacion completada en Linux."
  if [[ -n "$SCRIPT_FILE" ]]; then
    echo "[RUN] python3 '$SCRIPT_FILE' --help"
  else
    echo "[WARN] No se detecto automaticamente el script principal."
  fi
  exit 0
fi

echo "[ERROR] Sistema no soportado por install.sh."
echo "Usa install.ps1 en Windows o instala manualmente Python, pip y nmap."
exit 1
