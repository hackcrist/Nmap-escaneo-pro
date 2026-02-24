# Nmap Pro Wrapper

Wrapper en Python para automatizar escaneos con `nmap` en:
- Windows
- Kali Linux
- Termux

Incluye:
- Modo CLI (argumentos)
- Modo menu interactivo
- Reportes `CSV`, `JSON` y `XML`
- Logs en consola y archivo
- Modo monitor continuo
- Deteccion automatica de red (`auto`)

## Aviso Legal
Usa esta herramienta solo en sistemas/redes donde tengas autorizacion explicita.

## Requisitos
- Python 3.8+
- `nmap` instalado y disponible en `PATH`
- `colorama` (opcional, solo para colores)

## Clonar desde GitHub
```bash
git clone https://github.com/hackcrist/Nmap-escaneo-pro.git
cd Nmap-escaneo-pro
```

## Instalacion rapida (recomendada)
- Kali/Linux:
```bash
chmod +x install.sh
./install.sh
```

- Termux:
```bash
pkg install -y git
git clone https://github.com/hackcrist/Nmap-escaneo-pro.git
cd Nmap-escaneo-pro
chmod +x install.sh
./install.sh
```

- Windows (PowerShell):
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

## Instalacion de Nmap
- Kali/Linux:
```bash
sudo apt update && sudo apt install nmap
```
- Termux:
```bash
pkg update && pkg install nmap
```
- Windows:
Instala Nmap desde su instalador oficial y verifica que `nmap` funcione en terminal.

## Ejecutar
```bash
python "nmap pro.py"
```

En Linux tambien puedes usar:
```bash
python3 "nmap pro.py"
```

## Uso CLI (sin menu)
Ejecuta directo usando `--target`:

```bash
python "nmap pro.py" --target 192.168.1.10
python "nmap pro.py" --target 192.168.1.0/24 -P full
python "nmap pro.py" --target auto --preset accurate
python "nmap pro.py" --target auto --monitor
python "nmap pro.py" --target 10.0.0.0/24 --udp-too --top-ports 500
python "nmap pro.py" --target 127.0.0.1 --dry-run
```

Forzar menu:
```bash
python "nmap pro.py" --menu
```

## Parametros principales
- `--target`: host/IP/CIDR o `auto`
- `-P, --profile`: `fast|stealth|full|udp|vuln|web|allports`
- `--preset`: `fast|balanced|accurate`
- `--monitor`: escaneo continuo cada 60s
- `--top-ports`: cantidad de puertos top (>0)
- `--udp-too`: agrega barrido UDP adicional
- `--skip-os`: omite deteccion de sistema operativo
- `--skip-version`: omite deteccion de version
- `--extra-nse`: scripts NSE extra
- `-o, --outdir`: carpeta base de reportes
- `--log-file`: ruta de log (si no se define, usa `scan.log` en el reporte)
- `--dry-run`: muestra el comando sin ejecutar

## Profiles vs Presets
- `profile`: define estilo base de escaneo (puertos/scripts/opciones principales).
- `preset`: ajusta velocidad/precision:
  - `fast`: mas rapido, menor reintento
  - `balanced`: equilibrio
  - `accurate`: mas validacion, menos falsos positivos

## Privilegios (root/admin)
- En Linux/Termux, para escaneo SYN completo necesitas root.
- En Windows, para capacidades completas necesitas ejecutar como administrador.
- Si no hay privilegios, el script degrada automaticamente:
  - cambia `-sS` por `-sT`
  - quita `-O`

## Reportes generados
Por cada ejecucion crea una carpeta en `reports/` (o `--outdir`) con:
- `scan.nmap`
- `scan.xml`
- `scan.gnmap`
- `command.txt`
- `scan.log`
- `summary.csv`
- `summary.json`
- `summary.xml`

## Auto deteccion de red (`--target auto`)
- En Kali/Termux/Linux intenta detectar CIDR real desde interfaces (`ip ...`).
- Si no puede, usa fallback `/24`.
- El metodo usado se muestra en logs (`ip` o `fallback_/24`).

## Ejemplos recomendados
- Rapido en LAN:
```bash
python "nmap pro.py" --target auto -P fast --preset fast
```
- Mas confiable:
```bash
python "nmap pro.py" --target auto -P full --preset accurate
```
- Ver comando antes de ejecutar:
```bash
python "nmap pro.py" --target 192.168.1.0/24 --dry-run
```

## Creador
- Creador: HackCrist
- Firma: HackCrist

## Licencia
Este proyecto esta licenciado bajo Apache License 2.0. Ver [LICENSE](LICENSE).
