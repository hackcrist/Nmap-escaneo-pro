# Changelog

Todos los cambios importantes de este proyecto se documentan en este archivo.

## [1.0.0] - 2026-02-23
### Added
- Soporte multiplataforma para Windows, Kali Linux y Termux.
- Modo CLI y modo menu interactivo.
- Deteccion automatica de red con `--target auto`.
- Modo monitor continuo (`--monitor`).
- Perfiles de escaneo (`fast`, `stealth`, `full`, `udp`, `vuln`, `web`, `allports`).
- Presets de ejecucion (`fast`, `balanced`, `accurate`) para velocidad/precision.
- Exportacion de resultados a `summary.csv`, `summary.json` y `summary.xml`.
- Registro en consola y en archivo (`scan.log`), con soporte para `--log-file`.
- Instaladores:
  - `install.sh` para Linux/Kali/Termux.
  - `install.ps1` para Windows.
- Documentacion inicial en `README.md`.
- Licencia Apache 2.0 en `LICENSE`.

### Changed
- Mejoras de robustez en parsing de `.gnmap` (deduplicacion y tolerancia a lineas incompletas).
- Sanitizacion de nombres de carpeta para evitar errores en rutas (especialmente Windows).
- Ajuste automatico de flags cuando no hay privilegios (`-sS` -> `-sT`, sin `-O`).
- Optimizacion de monitor para evitar reprocesar `.gnmap` cuando no cambia.

### Fixed
- Validacion de `--top-ports` para impedir valores invalidos.
- Manejo de errores cuando `nmap` no esta disponible en `PATH`.

### Security
- Aviso legal de uso autorizado incluido en la documentacion.
