# Guía para agentes: ingeniería inversa de la Nikon D750

Repo de investigación sobre el firmware de la cámara Nikon D750 de Daniel. Objetivo: entender el formato del
firmware y ver si el WiFi (2,4 GHz, PTP/IP, ~2-4 MB/s) tiene un límite editable (ancho de canal, MCS, país, pila PTP).

## Dónde está cada cosa

| Tarea | Leer |
|-------|------|
| **Cualquier trabajo de este repo (empezar aquí)** | `.claude/skills/d750-firmware/SKILL.md` (fases, reglas, trampas) |
| Usar REA (MCP/CLI), Ghidra vía REA, evidencia, comparar versiones | skill `rea:reverse-engineer-anything` del plugin `rea@rea` (instalado a nivel de proyecto) y el MCP `rea` de `.mcp.json` |
| Plan, decisiones, contexto del proyecto | `docs/PLAN.md` |
| Hallazgos con evidencia (hash, offsets, comandos) | `docs/HALLAZGOS.md` |

## Reglas que aplican siempre

- **Solo lectura sobre la cámara.** No flashear ni modificar firmware sin petición explícita de Daniel.
- **El firmware no se versiona** (`firmware/`, `work/`, `*.bin` ignorados). Se registra nombre, tamaño y SHA-256.
- **Marcar cada afirmación** como verificado (con comando y salida) o por confirmar.
- **Archivos nuevos en `docs/`**: el gitignore global ignora `docs`; se agregan con `git add -f`.
- **REA**: plugin `rea@rea` (skill) + MCP en `.mcp.json` fijado a `rea-agents@6.8.0` con Ghidra 12.1.4 (`~/tools/ghidra_12.1.4_PUBLIC`, decompilador arm64 compilado a mano) y JDK 25. Si falla: `GHIDRA_INSTALL_DIR=~/tools/ghidra_12.1.4_PUBLIC JAVA_HOME=/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home npx -y rea-agents@6.8.0 doctor --provider ghidra --json`.
- Herramientas: `scripts/setup.sh --check`. Python del repo en `.venv/` (capstone, unicorn, keystone, pyelftools).
- Flujo de git: rama corta (`feat/`, `docs/`, `chore/`) → PR; commits Conventional Commits en español.
