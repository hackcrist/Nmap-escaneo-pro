# Contributing

Gracias por contribuir a este proyecto.

## Requisitos

- Python 3.8+
- `nmap` instalado en tu sistema

## Flujo recomendado

1. Haz fork del repositorio.
2. Crea una rama descriptiva:
   - `feature/nombre-corto`
   - `fix/nombre-corto`
3. Aplica cambios pequenos y claros.
4. Ejecuta validaciones locales:
   - `python "nmap pro.py" --help`
   - `python -m py_compile "nmap pro.py"`
5. Actualiza `README.md` y `CHANGELOG.md` si aplica.
6. Abre Pull Request con descripcion tecnica.

## Estilo de codigo

- Mantener compatibilidad con Windows, Kali Linux y Termux.
- No introducir dependencias innecesarias.
- Usar mensajes de log claros (`INFO`, `WARN`, `ERROR`, `OK`).
- Mantener nombres y salidas en espanol simple.

## Pull Requests

Un PR ideal incluye:
- Problema que resuelve
- Enfoque aplicado
- Riesgos/tradeoffs
- Evidencia de prueba

## Seguridad

Para reportes de seguridad revisa `SECURITY.md`.
