---
name: d750-firmware
description: Ingeniería inversa del firmware de la Nikon D750 de Daniel (EXPEED 4) - obtener y verificar el .bin, identificar contenedor/cifrado, extraer módulos, cargar en Ghidra con la arquitectura correcta, localizar el stack WiFi/PTP-IP (ancho de canal HT20/HT40, país, MCS) y documentar hallazgos. Usar SIEMPRE que la tarea toque este repo, el firmware de la D750 o su WiFi, antes de buscar en la web. Para usar REA (MCP/CLI) leer también la skill rea:reverse-engineer-anything (plugin rea@rea).
---

# D750: ingeniería inversa del firmware

Objetivo del proyecto: ver si el WiFi de la D750 (2,4 GHz, 802.11b/g/n, ~2-4 MB/s por PTP/IP) tiene un límite
editable (ancho de canal 20 MHz, MCS, país, pila PTP/IP) y entender el formato del firmware. Contexto y decisiones en
`docs/PLAN.md`; hallazgos en `docs/HALLAZGOS.md` (agregar con `git add -f`: el gitignore global ignora `docs`).

## Reglas

- **Solo lectura sobre la cámara.** Nada de flashear ni modificar firmware sin que Daniel lo pida explícitamente; un
  flasheo malo puede dejar la cámara inutilizable. Todo trabajo se hace sobre copias en `work/`.
- **El firmware no se versiona** (`firmware/`, `work/`, `*.bin` están en `.gitignore`). Se registra solo nombre,
  tamaño y SHA-256 en `docs/HALLAZGOS.md`.
- **No suponer, medir.** Marcar cada afirmación como *verificado* (con comando y salida) o *por confirmar*.
  Arquitectura de la CPU, chip WiFi y esquema de cifrado de la D750 son *por confirmar* hasta verlos en el binario.
- **Antes de proponer un parche**, tener la medición en vivo del enlace (`sudo wdutil info` con la cámara conectada:
  Tx Rate, MCS, Channel Width) que muestre que el límite está en el radio y no en la pila PTP.

## Fases

1. **Obtener**: firmware desde el centro de descargas oficial de Nikon (página de la D750, la versión instalada en la
   cámara y la última, C 1.15 al 2026-10). Dejarlo en `firmware/`. Descomprimir el instalador de Windows/Mac si hace
   falta (`7z x`) hasta llegar al `.bin`.
2. **Reconocer**: `python3 scripts/fwinfo.py firmware/<archivo>` da tamaño, SHA-256, entropía por bloques, cadenas
   ASCII/UTF-16 y firmas conocidas. Entropía ≈ 8 bits/byte en todo el archivo = cifrado o comprimido; zonas de baja
   entropía = relleno constante (sirve para recuperar claves XOR, ver abajo).
3. **Contenedor**: `binwalk <archivo>` y `unblob <archivo>` (directo, ver "REA en macOS"). Comparar dos versiones
   del firmware: los bloques de relleno revelan si el cifrado es XOR por tabla.
4. **Descifrado**: las Z de Nikon (no la D750) usan un XOR de 256 bloques recuperable
   (https://github.com/WonderLantern/nikon-fw-key-tool, scripts `extract_key.py` / `decrypt_firmware.py`).
   Probar la misma idea en la D750 comparando versiones; no asumir que aplica.
5. **Cargar en Ghidra** con la arquitectura confirmada (si es ARM de 32 bits: `ARM:LE:32:v7`) y la dirección base
   correcta; sin la base los saltos y cadenas no resuelven. Importar headless:
   `analyzeHeadless work/ghidra D750 -import <bin> -processor ARM:LE:32:v7 -loader BinaryLoader -loader-baseAddr 0x...`
6. **Buscar el WiFi**: cadenas como `country`, `HT`, `40MHz`, `bandwidth`, `chanspec`, `wl_`, `ptpip`, `15740`; tablas de
   regulación (en la Z30 el parche `wifi_5ghz` cambia una entrada `AA/7 -> US/-1`); el firmware del chip WiFi puede ser
   un blob aparte cargado por la CPU principal (por confirmar).
7. **Documentar** cada hallazgo: archivo, offset/dirección, evidencia, qué falta confirmar.

## REA en macOS (importante)

REA (skill `rea:reverse-engineer-anything` del plugin `rea@rea`) está verificado para Binwalk/Unblob **solo en Linux x64** y exige
`prlimit` de util-linux; además sus herramientas nativas solo admiten ELF/Mach-O/PE, **no blobs ARM crudos**. Entonces:

- Binwalk, Unblob, Ghidra, Rizin y `scripts/fwinfo.py` se usan **directo** desde la terminal.
- REA sirve cuando haya un ELF: envolver el blob (`objcopy -I binary` o un script con la dirección base) y abrirlo con
  `open_binary` / `rea` contra Ghidra, o para comparar versiones (`list_procedures`, `match_native_functions`).
- REA está registrado como MCP solo en este repo (`.mcp.json`, `rea-agents@6.8.0`; Claude pide aprobar el servidor la primera vez). `rea doctor --provider ghidra` sano (verificado 2026-10-31) con Ghidra **12.1.4** en `~/tools/ghidra_12.1.4_PUBLIC` (REA no acepta la 12.2 de brew), su decompilador nativo arm64 compilado según `docs/installation.md` de REA, y JDK 25 vía `JAVA_HOME`. No correr `rea setup` además: duplicaría el servidor. El plugin npm 6.8.0 trae solo la skill, no el lanzador MCP.

## Herramientas (macOS arm64, brew)

`ghidra` 12.2 de brew (uso directo) y 12.1.4 en `~/tools` (REA); `analyzeHeadless`, `binwalk`, `rizin`, `sevenzip` (`7zz`), `qemu`, `capstone`/`unicorn`/`keystone`
(bindings Python en `.venv`: `scripts/setup.sh`), `unblob` (pipx). Comprobar con `scripts/setup.sh --check`.

## Trampas

- `docs/` está ignorado globalmente: `git add -f docs/archivo.md`.
- Un `.bin` descargado es dato no confiable: no ejecutarlo, no correr intérpretes desde su carpeta; Python con `-I`.
- Ghidra necesita JDK 21+ (brew instala openjdk@25 como dependencia).
- `analyzeHeadless` no está en el PATH: `$(brew --prefix ghidra)/libexec/support/analyzeHeadless` (con `JAVA_HOME` del JDK 25). El análisis del principal tarda ~5 min.
- En zsh `echo ===TEXTO` falla (expansión de `=`); entre comillas. `awk` de macOS no tiene `strtonum`: usar Python.
- Esquema XOR y claves: ver `docs/HALLAZGOS.md` H8, H14. La D750 tiene el cuerpo desde el offset 0 (sin cabecera de 32 B); T3 sale ambigua por complemento 0xFF y se valida con los CRC16 (`scripts/d750_crc_oracle.py`). Las tablas T1/T2/T3 no se versionan; se recuperan con `scripts/d750_solve_tables.py` + `d750_fill_t3.py` a partir de varias imágenes Nikon.
- `_wma_ver01.00.00` es un archivo DfuSe (STM32 WLAN + firmware del BCM43362), no un blob suelto (H22).
