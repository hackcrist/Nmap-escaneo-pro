#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

is_termux() {
  [[ "${PREFIX:-}" == *"com.termux"* ]]
}

install_python_packages() {
  if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
  else
    echo "[ERROR] Python no encontrado."
    exit 1
  fi

  "$PY_BIN" -m pip install --upgrade pip
  if [[ -f "requirements.txt" ]]; then
    "$PY_BIN" -m pip install -r requirements.txt
  else
    "$PY_BIN" -m pip install colorama
  fi
}

if is_termux; then
  echo "[INFO] Entorno detectado: Termux"
  pkg update -y
  pkg install -y python nmap git
  install_python_packages
  echo "[OK] Instalacion completada en Termux."
  echo "[RUN] python 'nmap pro.py' --help"
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
  install_python_packages
  echo "[OK] Instalacion completada en Linux."
  echo "[RUN] python3 'nmap pro.py' --help"
  exit 0
fi

echo "[ERROR] Sistema no soportado por install.sh."
echo "Usa install.ps1 en Windows o instala manualmente Python, pip y nmap."
exit 1
