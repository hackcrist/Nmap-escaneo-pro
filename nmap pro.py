#!/usr/bin/env python3
import argparse
import csv
import ctypes
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init
except ImportError:
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        RESET_ALL = ""
        BRIGHT = ""

    Fore = Style = _NoColor()

    def init(*_args, **_kwargs):
        return None


init(autoreset=True)

PROFILES = {
    "fast": "-Pn -T4 -F -sS -sV",
    "stealth": "-Pn -T2 -sS -sV --max-retries 2 --defeat-rst-ratelimit",
    "full": "-Pn -T4 -sS -sV -O -p-",
    "udp": "-Pn -T3 -sU --top-ports 400",
    "vuln": "-Pn -T4 -sS -sV --script vuln",
    "web": "--top-ports {top} -Pn -T4 -sS -sV --script http-title,http-headers,http-server-header,http-methods",
    "allports": "-Pn -T4 -sS -sV -p-",
}

SCAN_PRESETS = {
    "fast": ["--max-retries", "1", "--min-rate", "1200", "--host-timeout", "10m"],
    "balanced": [],
    "accurate": ["--max-retries", "3", "--defeat-rst-ratelimit", "--version-all"],
}

LOG_COLORS = {
    "INFO": Fore.CYAN,
    "WARN": Fore.YELLOW,
    "ERROR": Fore.RED,
    "OK": Fore.GREEN,
}

LOG_FILE_PATH = None


def set_log_file(path):
    global LOG_FILE_PATH
    LOG_FILE_PATH = path
    if LOG_FILE_PATH:
        LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)


def log(level, message):
    lvl = level.upper()
    color = LOG_COLORS.get(lvl, Fore.WHITE)
    print(color + f"[{lvl}] {message}")
    if LOG_FILE_PATH:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
                f.write(f"{stamp} [{lvl}] {message}\n")
        except OSError:
            pass


def banner():
    neon = Fore.CYAN + Style.BRIGHT
    print(neon + "+-+-+-+-+")
    print(neon + "|N|m|a|p|")
    print(neon + "+-+-+-+-+\n")
    msg = ">>> NMAP PRO WRAPPER INICIALIZADO <<<"
    for c in msg:
        print(neon + c, end="", flush=True)
        time.sleep(0.015)
    print("\n")


def running_on_termux():
    prefix = os.environ.get("PREFIX", "")
    return "com.termux" in prefix


def install_hint_for_nmap():
    if running_on_termux():
        return "Instala Nmap en Termux con: pkg update && pkg install nmap"
    system = platform.system().lower()
    if system == "linux":
        return "Instala Nmap en Linux con: sudo apt update && sudo apt install nmap"
    if system == "windows":
        return "Instala Nmap en Windows y agrega nmap al PATH."
    return "Instala Nmap y asegurate de que el comando 'nmap' este en PATH."


def is_privileged():
    system = platform.system().lower()
    if system == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def local_cidr():
    system = platform.system().lower()

    # Kali/Termux/Linux: intenta extraer IP/mascara real desde interfaz activa.
    if system == "linux":
        try:
            output = subprocess.check_output(
                ["ip", "-o", "-f", "inet", "addr", "show", "scope", "global"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            candidates = []
            for line in output.splitlines():
                match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b", line)
                if not match:
                    continue
                iface = ipaddress.ip_interface(match.group(1))
                network = iface.network
                cidr = f"{network.network_address}/{network.prefixlen}"
                if iface.ip.is_private:
                    return cidr, "ip"
                candidates.append(cidr)
            if candidates:
                return candidates[0], "ip"
        except Exception:
            pass

    ip = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
    except OSError:
        pass

    if not ip:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = "192.168.1.10"

    if ip.startswith("127."):
        ip = "192.168.1.10"

    # Fallback universal: asume /24 si no hay mascara disponible.
    base = ".".join(ip.split(".")[:3])
    return base + ".0/24", "fallback_/24"


def safe_scan_name(target, profile, ts):
    raw = f"{target}_{profile}_{ts}"
    # Evita caracteres invalidos en nombres de carpeta (especialmente en Windows).
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "_", raw)
    return sanitized.strip(" .") or f"scan_{ts}"


def build_cmd(
    profile,
    target,
    out_base,
    top_ports=1000,
    udp_too=False,
    skip_os=False,
    skip_version=False,
    extra_nse="",
    privileged=False,
    preset="balanced",
):
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise RuntimeError(f"Nmap no encontrado en PATH. {install_hint_for_nmap()}")

    opts = PROFILES[profile].format(top=top_ports).split()
    if udp_too and profile != "udp":
        opts += ["-sU", "--top-ports", "100"]
    if not skip_os and "-O" not in opts:
        opts += ["-O"]
    if skip_version:
        opts = [o for o in opts if o != "-sV"]
    if extra_nse:
        opts += ["--script", extra_nse]

    # Presets para balancear velocidad/precision segun necesidad.
    opts += SCAN_PRESETS[preset]

    # Aporta contexto para validar por que Nmap marca un puerto como abierto.
    if "--reason" not in opts:
        opts += ["--reason"]

    if not privileged:
        opts = ["-sT" if o == "-sS" else o for o in opts]
        opts = [o for o in opts if o != "-O"]

    opts += ["-oA", str(out_base), target]
    return [nmap_path] + opts


def run_scan(cmd):
    log("OK", "Iniciando escaneo Nmap...")
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in iter(process.stdout.readline, ""):
            if line:
                print(Fore.CYAN + line.strip())
        return process.wait()
    except KeyboardInterrupt:
        log("WARN", "Escaneo cancelado por usuario.")
        return 130
    except Exception as e:
        log("ERROR", f"Error ejecutando Nmap: {e}")
        return 1


def parse_gnmap(gnmap_path):
    results = []
    seen = set()
    host_re = re.compile(r"Host:\s+(\S+)(?:\s+\(([^)]*)\))?")
    ports_re = re.compile(r"Ports:\s+(.*)")
    with open(gnmap_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "Ports:" not in line:
                continue

            host_m = host_re.search(line)
            ports_m = ports_re.search(line)
            if not host_m or not ports_m:
                continue

            ip = host_m.group(1)
            hostname = (host_m.group(2) or "").strip()
            host = hostname if hostname else ip
            ports_str = ports_m.group(1).strip()
            if not ports_str:
                continue

            for entry in ports_str.split(","):
                parts = entry.strip().split("/")
                if len(parts) < 5 or parts[1] != "open":
                    continue
                port, _state, proto, _owner, service = parts[:5]
                row = {"host": host, "port": port, "proto": proto, "service": service}
                key = (row["host"], row["port"], row["proto"], row["service"])
                if key in seen:
                    continue
                seen.add(key)
                results.append(row)
    return results


def write_summary(rows, base_dir):
    if not rows:
        return False
    csv_path = base_dir / "summary.csv"
    json_path = base_dir / "summary.json"
    xml_path = base_dir / "summary.xml"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host", "port", "proto", "service"])
        writer.writeheader()
        writer.writerows(rows)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    root = ET.Element("scan_summary")
    for row in rows:
        item = ET.SubElement(root, "entry")
        ET.SubElement(item, "host").text = row["host"]
        ET.SubElement(item, "port").text = str(row["port"])
        ET.SubElement(item, "proto").text = row["proto"]
        ET.SubElement(item, "service").text = row["service"]
    ET.ElementTree(root).write(xml_path, encoding="utf-8", xml_declaration=True)
    return True


def gnmap_signature(gnmap_path):
    try:
        st = gnmap_path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def parse_args():
    def positive_int(value):
        ivalue = int(value)
        if ivalue <= 0:
            raise argparse.ArgumentTypeError("debe ser un entero positivo")
        return ivalue

    p = argparse.ArgumentParser(description="Nmap Pro Wrapper (menu + modo CLI)")
    p.add_argument("--target", help="Host/IP/CIDR o 'auto' para escaneo LAN")
    p.add_argument("-P", "--profile", choices=PROFILES.keys(), default="fast", help="Perfil de escaneo")
    p.add_argument("--monitor", action="store_true", help="Escaneo continuo cada 60 segundos")
    p.add_argument("--preset", choices=SCAN_PRESETS.keys(), default="balanced", help="Prioriza velocidad o precision")
    p.add_argument("--top-ports", type=positive_int, default=1000, help="Cantidad de puertos top")
    p.add_argument("--udp-too", action="store_true", help="Agregar barrido UDP adicional")
    p.add_argument("--skip-os", action="store_true", help="Omitir deteccion de sistema operativo")
    p.add_argument("--skip-version", action="store_true", help="Omitir deteccion de version")
    p.add_argument("--extra-nse", default="", help="Scripts NSE extra separados por coma")
    p.add_argument("-o", "--outdir", default="reports", help="Directorio base de reportes")
    p.add_argument("--log-file", default="", help="Ruta de archivo log (default: scan.log del reporte)")
    p.add_argument("--dry-run", action="store_true", help="Muestra comando sin ejecutar")
    p.add_argument("--menu", action="store_true", help="Forzar modo menu interactivo")
    return p.parse_args()


def menu():
    while True:
        print(Fore.CYAN + "Selecciona tarea:")
        print(Fore.CYAN + "1) Escanear LAN automaticamente")
        print(Fore.CYAN + "2) Escanear IP/CIDR especifica")
        print(Fore.CYAN + "3) Escaneo continuo (monitor)")
        print(Fore.RED + "0) Salir\n")
        choice = input(Fore.YELLOW + "Ingresa numero: ").strip()
        if choice in {"0", "1", "2", "3"}:
            return choice
        log("WARN", "Opcion invalida, intenta de nuevo.")


def run_once(
    target,
    profile,
    privileged,
    monitor=False,
    top_ports=1000,
    udp_too=False,
    skip_os=False,
    skip_version=False,
    extra_nse="",
    outdir="reports",
    log_file="",
    dry_run=False,
    preset="balanced",
):
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    scan_name = safe_scan_name(target, profile, ts)
    base_dir = Path(outdir) / scan_name
    base_dir.mkdir(parents=True, exist_ok=True)
    out_base = base_dir / "scan"
    selected_log_file = Path(log_file) if log_file else (base_dir / "scan.log")
    if not selected_log_file.is_absolute():
        selected_log_file = base_dir / selected_log_file
    set_log_file(selected_log_file)
    log("INFO", f"Artefactos y logs en: {base_dir}")
    log("INFO", f"Preset activo: {preset}")

    try:
        cmd = build_cmd(
            profile,
            target,
            out_base,
            top_ports=top_ports,
            udp_too=udp_too,
            skip_os=skip_os,
            skip_version=skip_version,
            extra_nse=extra_nse,
            privileged=privileged,
            preset=preset,
        )
    except RuntimeError as e:
        log("ERROR", str(e))
        return

    (base_dir / "command.txt").write_text(" ".join(cmd), encoding="utf-8")
    if dry_run:
        log("INFO", f"[SIMULACION] Comando: {' '.join(cmd)}")
        return

    exit_code = run_scan(cmd)
    if exit_code != 0:
        log("ERROR", f"Nmap finalizo con codigo {exit_code}")

    gnmap = out_base.with_suffix(".gnmap")
    rows = []
    last_gnmap_sig = None
    if gnmap.exists():
        last_gnmap_sig = gnmap_signature(gnmap)
        rows = parse_gnmap(gnmap)
        if write_summary(rows, base_dir):
            log("OK", "Resumen guardado en summary.csv, summary.json y summary.xml")
        else:
            log("WARN", "Sin puertos abiertos o sin datos parseables.")
    else:
        log("ERROR", "No se encontro el archivo .gnmap para resumir.")

    if monitor:
        log("INFO", "[MODO MONITOR] Escaneando cada 60s. Ctrl+C para salir.")
        seen = {r["host"] for r in rows}
        try:
            while True:
                try:
                    cmd = build_cmd(
                        profile,
                        target,
                        out_base,
                        top_ports=top_ports,
                        udp_too=udp_too,
                        skip_os=skip_os,
                        skip_version=skip_version,
                        extra_nse=extra_nse,
                        privileged=privileged,
                        preset=preset,
                    )
                except RuntimeError as e:
                    log("ERROR", str(e))
                    break

                exit_code = run_scan(cmd)
                if exit_code == 0 and gnmap.exists():
                    current_sig = gnmap_signature(gnmap)
                    if current_sig == last_gnmap_sig:
                        log("INFO", "Sin cambios en gnmap; se omite re-analisis.")
                    else:
                        last_gnmap_sig = current_sig
                        rows = parse_gnmap(gnmap)
                        write_summary(rows, base_dir)
                        current_hosts = {r["host"] for r in rows}
                        new_hosts = current_hosts - seen
                        if new_hosts:
                            log("WARN", f"[NUEVOS DISPOSITIVOS] {', '.join(sorted(new_hosts))}")
                        seen.update(current_hosts)
                time.sleep(60)
        except KeyboardInterrupt:
            log("WARN", "Monitor detenido por usuario.")


def main():
    args = parse_args()
    banner()
    system = platform.system()
    log("INFO", f"Sistema detectado: {system}{' (Termux)' if running_on_termux() else ''}")

    privileged = is_privileged()
    if not privileged:
        log("WARN", "Sin root/admin: se usara -sT y se omitira deteccion de SO (-O).")

    if args.target and not args.menu:
        if args.target.lower() == "auto":
            target, auto_method = local_cidr()
            log("INFO", f"Auto CIDR detectado por {auto_method}: {target}")
        else:
            target = args.target
        log("INFO", f"Objetivo CLI: {target}")
        run_once(
            target=target,
            profile=args.profile,
            privileged=privileged,
            monitor=args.monitor,
            preset=args.preset,
            top_ports=args.top_ports,
            udp_too=args.udp_too,
            skip_os=args.skip_os,
            skip_version=args.skip_version,
            extra_nse=args.extra_nse,
            outdir=args.outdir,
            log_file=args.log_file,
            dry_run=args.dry_run,
        )
        return

    while True:
        choice = menu()
        if choice == "0":
            log("INFO", "Saliendo...")
            break
        if choice == "1":
            target, auto_method = local_cidr()
            log("INFO", f"Escaneando LAN automaticamente ({auto_method}): {target}")
            run_once(target, profile="fast", privileged=privileged, monitor=False)
        elif choice == "2":
            target = input(Fore.YELLOW + "Ingresa IP o CIDR: ").strip()
            if not target:
                log("WARN", "Objetivo vacio. Intenta otra vez.")
                continue
            run_once(target, profile="fast", privileged=privileged, monitor=False)
        elif choice == "3":
            target, auto_method = local_cidr()
            log("INFO", f"Escaneo continuo activado ({auto_method}) para: {target}")
            run_once(target, profile="fast", privileged=privileged, monitor=True)


if __name__ == "__main__":
    main()
