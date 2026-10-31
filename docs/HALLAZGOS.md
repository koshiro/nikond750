# Hallazgos

Una entrada por hallazgo: archivo (nombre, tamaño, SHA-256), offset/dirección, evidencia (comando y salida), estado (verificado / por confirmar).

## 2026-10-31 · Fases 1-3: inventario y reconocimiento de `D750_0115.bin`

### H1 · Inventario de `firmware/` (verificado)
Comando: `ls -la firmware/; shasum -a 256 firmware/*`

| Archivo | Tamaño (bytes) | SHA-256 |
|---------|----------------|---------|
| `D750_0115.bin` | 21552187 | `6c1dfadc8feb38bc783522c37f6351e1e8006f4684c8234690afb9aa08444859` |

- Es un `.bin` directo (no hubo instalador que extraer). `file` dice `data`.
- **Solo hay una versión (0115, la última).** Falta la versión instalada en la cámara si es distinta: la comparación entre versiones (fase 3/4) queda pendiente.

### H2 · Cabecera: 32 bytes de 0x20 y luego datos de entropía máxima (verificado)
Comando: `xxd -l 64 firmware/D750_0115.bin`
- `0x00-0x1f`: 32 bytes `20` (espacios ASCII). Desde `0x20` empieza el cuerpo (`50 72 31 f2 7d 8c ...`).
- Tamaño 21552187: mod 4 = 3, mod 16 = 11, mod 256 = 59 → no está alineado a bloques de cifrado (cola y/o cabecera sin alinear).

### H3 · Entropía ≈ 8 en todo el archivo (verificado)
Comando: `python3 -I scripts/fwinfo.py firmware/D750_0115.bin`
- Salida: `media 8.00, bloques >7.5: 329/329, bloques <1.0: 0/329`. Ningún bloque de relleno constante visible.
- Cadenas ASCII relevantes (WiFi/PTP/Nikon/etc.): `ninguna`. Conclusión: no es texto plano ni contiene código legible; está cifrado o comprimido.
- Distribución de bytes uniforme (chi² = 190.9 sobre los bytes tras la cabecera, 255 grados de libertad): sin sesgo grueso.

### H4 · binwalk y unblob: sin contenedor (verificado)
- `binwalk firmware/D750_0115.bin` → `Analyzed 1 file for 85 file signatures (187 magic patterns)`, sin ninguna coincidencia.
- `unblob --extract-dir work/unblob-D750_0115 firmware/D750_0115.bin` → directorio de salida vacío (no reconoce ningún formato). Log en `work/unblob-D750_0115.log`.
- `fwinfo.py` marcó un `bzip2` en `0x177c5e`: **falso positivo** (`BZha|`: el nivel `|` no es válido; `bzip2 -t` da `bad magic number`).
- `binwalk -E` generó el gráfico de entropía en `work/binwalk-out/D750_0115.bin.png` (no versionado).

### H5 · Estructura de periodo 256 en el cifrado (verificado el patrón; el mecanismo, por confirmar)
Si fuera ruido aleatorio o un cifrado de flujo con clave única, casi no habría bloques de 16 bytes repetidos. Hay muchos:
- Bloques de 16 bytes alineados (desde `0x20`): **43077 repeticiones** en 6838 grupos; de ellas **43077 (100 %)** están separadas por un múltiplo exacto de 256 bytes. Un caso: bloque en `0xa4b10, 0xb5010, 0xede10, 0x115810, …`; otro en `0x9ad0, 0xa63d0, 0xb99d0, …` (todos con el mismo desplazamiento mod 256).
- Con bloques de 4 bytes: 403804 repeticiones sobre 5388038 bloques (azar puro daría ~3 mil).
- Las repeticiones se concentran por regiones (0-1 MiB, 3-4 MiB, 15-20 MiB), como zonas de relleno/ceros cifradas con la misma tabla.
- **Interpretación (por confirmar):** el cuerpo parece cifrado con una transformación que depende solo de la posición mod 256 (p. ej. un XOR con tabla de 256 bytes/bloques) sobre un texto en claro con zonas repetidas.
- **Intento de recuperar la clave (verificado, negativo):** tomar el byte más frecuente por columna mod 256 como clave y aplicar XOR **no** baja la entropía (8.000 tras XOR, 0,4 % de ceros). La moda por columna es solo ~14 % mayor que el azar (375 vs 329). Es decir, la clave simple "byte más común por columna" no sirve: el relleno de ceros es poco para fijarla, o la transformación no es un XOR de 256 bytes simple (p. ej. 256 bloques más largos, suma en vez de XOR, o dependencia del bloque).

### H6 · ¿Recuerda al XOR de 256 bloques de nikon-fw-key-tool? (por confirmar)
- Parecido real y medido: la dependencia de la posición con periodo 256 (H5). No se asume que sea el mismo esquema que en las Z. Para recuperar la tabla hace falta **una segunda versión** del firmware (la instalada) y comparar regiones con relleno conocido, o revisar el código de `WonderLantern/nikon-fw-key-tool` (no se descargó ni ejecutó aquí).

### H7 · Arquitectura de CPU (por confirmar)
- No determinable aún: sin texto en claro ni cabeceras. La D750 usa EXPEED 4 (según el skill; ARM de 32 bits supuesto, sin verificar en el binario).

## 2026-10-31 · Descifrado con el esquema de WonderLantern (parcial)

Fuente consultada (leída, no ejecutada tal cual): README, `extract_key.py` y `decrypt_firmware.py` de `WonderLantern/nikon-fw-key-tool`, descargados con `gh api` a `work/wonderlantern/` (no versionado). Sondas propias: `scripts/d750_t1_probe.py` y `scripts/d750_decrypt.py` (importan funciones de `extract_key.py`).

### H8 · La D750 usa el mismo esquema XOR T1/T2/T3 que las Z, con el cuerpo desde el offset 0 (verificado)
Comando: `.venv/bin/python -I scripts/d750_t1_probe.py firmware/D750_0115.bin work/wonderlantern 0`
- La fórmula `plain[i] = cipher[i] ^ T1[i&0xFF] ^ T2[(i>>8)&0xFF] ^ T3[(i>>16)&0xFF]` aplica con `i` = offset de archivo (en la D750 las 32 espacios están en `0x00` y no hay cabecera de 32 bytes con SHA-1). Con cabecera `0x20` no sale ninguna familia de T1.
- **T1 y T2 recuperados completos y sus SHA-256 coinciden con los valores de referencia de las Z** (`T1 29d2e34239fc33bf…`, `T2 6e87de5da7e42df9…`): son las mismas tablas.
- Con las tablas parciales, el directorio de módulos descifrado es válido: 3 módulos encadenados hasta `tamaño-16`:

| Módulo | Offset | Longitud |
|--------|--------|----------|
| `a1010_011100.bin` | 0x90 | 786434 |
| `_wma_ver01.00.00` | 0xc0092 | 441143 |
| `b1010_115a.bin` | 0x12bbc9 | 20324450 |

  (`0x12bbc9 + 20324450 = 21552171 = tamaño − 16`). Nota: en el directorio el nombre va en `+0` y offset/longitud en `+16/+20` de cada entrada de 32 bytes.

### H9 · Arquitectura: ARM Thumb-2 (verificado en código descifrado; modelo exacto por confirmar)
- Bloques con T3 conocido (p. ej. 40 y 53, offsets `0x280000`/`0x350000`) descifran a Thumb-2 (`f7 9c ff 07 46 98 f8 b8 02 …`, `bl`/`ldrb`) y cadenas reales (`20%02d/%02d/%02d %02d:%02d:%02d`).
- El bloque 137 (T3 conocido) es texto UTF-16 de los menús (`vid\nphotoprint effect.\nMonochrome…`), lo que confirma el descifrado.

### H10 · Falta T3 en 201 de 256 bloques de 64 KiB (superado por H14: resuelto con más imágenes y el oráculo de CRC)
- T3 por relleno constante: solo **55/256** bloques (los bloques 0-71 y 134-251 con huecos). Sin T3 no se descifra el resto.
- Intentos de recuperarlo solo con este .bin (verificado, insuficientes): puntuar por bytes cero acierta 42/55 sobre bloques conocidos; sumar decodificación Thumb con capstone tampoco mejora (42/55). La entropía es invariante a XOR, no sirve. Hay bloques de texto (UTF-16 Devanagari, `09 xx`) y datos comprimidos donde la estadística no distingue la constante.
- Vía fiable: las propias tablas de las Z. WonderLantern documenta que 4 imágenes (`Z_8_0311`, `Z7_2_0170`, `Z_6_0380`, `Z_50_0260`) cubren los 256 bloques de T3 y las tablas son comunes. Pendiente: obtener alguna imagen Z o la T3 por otra vía.

## 2026-10-31 · Tablas con D780 y Z 6 (T3 al 81 %)

### H11 · Inventario de las imágenes nuevas (verificado)
Comando: `shasum -a 256 firmware/*.bin`; `xxd -l 48`

| Archivo | Tamaño (bytes) | SHA-256 | Notas |
|---------|----------------|---------|-------|
| `D780_0121.bin` | 37731134 | `9eedbd030dd5eab9d10fa26e8c1c57dfdbffd0cfdb7ce226e34e341cbcab8c52` | cabecera de 20 B + 12 B y 32 espacios en `0x20` (formato Z) |
| `Z_6_0380.bin` | 34923366 | `ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54` | coincide con el hash conocido de WonderLantern |

- `firmware/NKLD0218.BIN` (39588 B) no es el firmware de la D800 (es un archivo de datos de objetivos, `file` → `data`). **El firmware de la D800 no está en `firmware/`.**
- La D750 es la única con las 32 espacios en `0x00` (cuerpo desde el offset 0); la D780 y la Z 6 usan la cabecera de 32 bytes.

### H12 · Tablas combinadas: T1 y T2 completas, T3 207/256 (verificado)
Comando: `.venv/bin/python -I scripts/d750_solve_tables.py work/wonderlantern work/key.json firmware/D750_0115.bin firmware/D780_0121.bin firmware/Z_6_0380.bin`
- Las tres imágenes coinciden en la familia de T1 y T1/T2 dan los hashes de referencia (`29d2e342…`, `6e87de5d…`). T3: `207/256` bloques cubiertos por relleno constante; etapa 5 no corrige ninguno.
- T3 faltante (49 índices): `72-77, 90, 91, 102, 108, 125-128, 144-146, 148, 150, 160, 161, 164-166, 180, 185, 187, 188, 191, 193, 194, 196-198, 200, 201, 203-209, 211, 212, 220, 224, 244, 245`.
- Siguiente: otra imagen Nikon del esquema legado (D800 u otra) con relleno en esos índices. `work/key.json` no se versiona.

## 2026-10-31 · D750 descifrada y validada

### H13 · Imágenes añadidas (verificado: `shasum -a 256 firmware/*.bin`)

| Archivo | Tamaño (bytes) | SHA-256 | Formato |
|---------|----------------|---------|---------|
| `D800_0111.bin` | 15859842 | `fc1273aafd9787a665f662224e4b1aa1e0ff12a5af7befb1e3ec5cd112f6f0ab` | 32 espacios en `0x00` (como D750) |
| `D500_0140.bin` | 26645063 | `3d00b66bfc04bd99a050f3b7bcd83737ed5f0248390b512d1ba6de79fd24d84e` | formato Z (cabecera 32 B) |
| `D850_0131.bin` | 27660549 | `4599b23822b963d91a27e51338eae505385db4b1427919b0a0546f732b617c9c` | formato Z |

### H14 · T3 completa (verificado con CRC)
Comandos: `scripts/d750_solve_tables.py` (6 imágenes → T3 238/256), `scripts/d750_fill_t3.py` (complemento 0xFF + 18 índices por puntuación de ceros agrupada entre imágenes) y `scripts/d750_crc_oracle.py` (resto CRC16 de cada módulo, lineal con init 0).
- Dos pasos que importan: (1) T3 por relleno queda ambigua por complemento `0xFF` en 75 índices (etapa 5 de WonderLantern, que mi script omitía al principio); (2) T3[187] salió `0x0e` y el oráculo del CRC de la Z 6 dio una única solución consistente (`b=187, d=0xbe`) → `0xb0`.
- Con esa T3: **todos los módulos de la D750, D800, D780 y Z 6 dan resto CRC16 = 0**, incluido el módulo principal de 20 MB de la D750 (toca los 256 índices), y el **CRC de paquete de la D750 coincide**. Es evidencia fuerte de que la clave es correcta.
- **Sin resolver:** un módulo de la D500 (`b1110_140.bin`) y uno de la D850 (`b1330_131.bin`) no validan (candidatos de un índice: 29, 102, 193; los dos coinciden). No afecta a la D750 y no se investigó.
- La clave completa está en `work/key_full2.json` (no versionada).

### H15 · Módulos de la D750 (verificado: `scripts/d750_extract_modules.py work/key_full2.json firmware/D750_0115.bin work/d750_modulos`)

| Módulo | Offset en el .bin | Longitud (sin CRC) | SHA-256 |
|--------|-------------------|--------------------|---------|
| `a1010_011100.bin` | 0x90 | 786432 | `690b7d1c7683cda36c72b5911cdd474ad5bc78f9467b369f3f86dc7316600213` |
| `_wma_ver01.00.00` | 0xc0092 | 441141 | `097e0ce21b2647cec4a2136f3b697ab5fa534f6449a8a72684c0da6cbb3a8994` |
| `b1010_115a.bin` | 0x12bbc9 | 20324448 | `acb690b6914f2f5681d099eee2fe7d67bf7847e2359a493f14eb69d3463a5808` |

### H16 · Arquitectura y contenido (verificado salvo lo marcado)
- `b1010_115a.bin` (aplicación principal) empieza con la tabla de vectores ARM: `18 f0 9f e5` ×5 (`ldr pc, [pc, #0x18]`) y tabla de punteros desde `0x20` (`0x9027d524, 0x90291c80, …`). **ARM de 32 bits little-endian** (con código Thumb-2 mezclado, ver H9). Base de carga probable `0x90000000` (por confirmar).
- Cadenas en claro: `PTPSRV_`, `PTPCMD_`, `PTPMES_`, `PTPCYE_`, `Marvell Semiconductor Inc.` (0x1277128), `NikonMotionDetector Ver6.0`. Firmas LZMA en 0x26b4f4, 0x26d2c0, 0x280fe0, 0x28429f, 0x2842f4 (por extraer).
- `_wma_ver01.00.00` es el módulo WLAN (cadenas `wlanapi_init()`, `wlanapi_set_apmode()`, `SSID(len=%d)=`, `wlanapi_check_fw OK`, `wlan main`, `wlan tx`); empieza con `DfuSe` + `Target` (formato DfuSe, por confirmar su alcance). Chip WiFi Marvell: por confirmar el modelo.
- `a1010_011100.bin` (768 KiB) tiene aspecto de tabla de punteros (`0x00c20d00…`), probable cargador/boot (por confirmar).

### H17 · Importación en Ghidra de `b1010_115a.bin` (verificado)
Comando (Ghidra 12.2 de brew, JDK 25): `analyzeHeadless work/ghidra D750 -import work/d750_modulos/b1010_115a.bin -processor ARM:LE:32:v7 -loader BinaryLoader -loader-baseAddr 0x90000000` (5 min; log en `work/ghidra-import.log`). `analyzeHeadless` no está en el PATH: está en `$(brew --prefix ghidra)/libexec/support/`.
- `scripts/ghidra/D750Stats.java` → `funciones=13303 instrucciones=643624 cadenas=1884 cadenas_con_xref=586`, rango `0x90000000-0x9136205f`.
- Que 586 cadenas tengan referencias indica que la base `0x90000000` es correcta (con una base errónea casi ninguna resolvería). Sigue marcada como probable hasta ver los vectores resolver a código.
- Proyecto Ghidra en `work/ghidra/` (no versionado). Pendiente: cargar `_wma_ver01.00.00` (WLAN, formato DfuSe) y extraer las secciones LZMA.

## 2026-10-31 · Búsqueda WiFi

### H18 · El chip WiFi es un Broadcom BCM43362 por SDIO (verificado en `_wma_ver01.00.00`)
Comandos: `strings -a -n 4 work/d750_modulos/_wma_ver01.00.00 | grep -iE "bcm[0-9]|nvram|ccode|boardtype|glom|sdio"` y `grep -a -b -o` para los offsets.
- Cadenas: `BCM43362` (offset 223945), `%s: Broadcom SDPCMD CDC driver`, `[SDIO] CMD0/CMD3/CMD5/CMD7/CMD53`, `Glom packet`, `bcmapi_mpc set`. **No es Marvell**: `Marvell Semiconductor Inc.` en la aplicación principal (0x1277128) es una cadena ajena al WiFi (por confirmar su origen).
- Blob de firmware del chip embebido y comprimido en `_wma`: `43362a2-roml/sdio-apsta-idsup-idauth-pno-idmfp-reclaim-proptxstatus Version: 5.90.153.0 CRC: d3c23e60 Date: Thu 2013-04-25 15:24:37 KST` (offset 439892).
- NVRAM de la placa en texto (offset ≈225300): `devid=0x4343`, `vendid=0x14e4`, `boardtype=0x0598`, `boardrev=0x1309`, `xtalfreq=26000`, `sromrev=3`, **`aa2g=1` (una sola antena 2,4 GHz)**, `ccode=US`, `maxp2ga0=46`, `pa0maxpwr=80`, `ofdm2gpo=0x00000000`, `mcs2gpo0/1=0x0000`, `pmax=40`, `macaddr=00:90:4c:07:71:12`.
- Capa de la cámara sobre el chip (`wlanapi_*`): comandos de consola `11n_enb`, `band`, `stamode`, `apmode`, `sta_rate`, `ap_rate`, `set_bgrate`, `get_nrate`, `set_mpc`; mensajes `[WIFI@] channel`, `country code`, `Get mcs index`, `current rate`.
- No aparecen `bw_cap`, `mimo_bw_cap`, `HT40` ni `40MHz` en ninguno de los tres módulos (verificado con grep; el blob del chip está comprimido, por lo que ahí no se puede descartar).

### H19 · Implicación para el objetivo (confirmado por H26: el límite es del chip)
- El BCM43362 es un chip 802.11 b/g/n de **1×1 y solo 2,4 GHz**; el módulo Inventek ISM43362 (basado en él) anuncia `single stream w/20 MHz, 7,2-72,2 Mbps`. Si el chip es solo de 20 MHz (MCS7 = 72,2 Mbps de PHY), el techo real de ~25-30 Mbps (3-4 MB/s) coincide con los 2-4 MB/s medidos: **el límite sería del hardware, no un valor editable del firmware**. Falta verlo en la hoja de datos oficial (las copias encontradas son de terceros) y con la medición en vivo `sudo wdutil info` con la cámara conectada (regla del skill).
- Lo único editable que sí aparece: `ccode=US` y la potencia (`maxp2ga0`, `pa0maxpwr`) en la NVRAM; no suben el caudal.
- Fuentes: https://www.mouser.com/datasheet/2/908/ISM43362_L36_Functional_Spec-20079-1.1-1-1371209.pdf, https://datasheetq.com/pdf-view/BCM43362-Cypress.pdf

### H20 · El blob del chip no está comprimido y no hay evidencia de 40 MHz (verificado salvo lo marcado; ubicación exacta en H22)
- **Sin compresión:** en `_wma_ver01.00.00` probé raw-deflate/zlib/gzip/LZMA (todos los offsets 0x30000-0x37000 para raw, y cada cabecera zlib/gzip/LZMA): 0 flujos válidos. `binwalk` solo ve tablas de cifrado del host (CRC32 en 0x2c4d1, AES S-Box en 0x31905/0x32a05, SHA-256 en 0x32b6d/0x52829) y `Copyright (C) Ubiquitous Corp. 2001-2013` en 0x36813 (pila TCP/IP del host). Las firmas LZMA de `fwinfo.py` en este módulo eran falsos positivos.
- **El firmware del chip está en claro** dentro de `_wma` desde ≈0x52000 hasta ≈0x6b680 (cadenas `wl%d: wlc_wsec…` en 0x523b2, `5.90.153.8x2 (TOB)` y `Apr 25 2013` en 0x52a35, `TRAP %x(%x): pc %x, lr, sp, cpsr, spsr` en 0x526c3 → ARM; versión completa `Version: 5.90.153.0 …` en 0x6b5d4). Es una imagen `roml` (parches sobre ROM), por eso casi no tiene cadenas de capacidades: `bw_cap`/`mimo_bw_cap`/`HT40` **no aparecen** porque viven en la ROM del chip. Los límites exactos del blob quedan por confirmar.
- **40 MHz:** lo único con `bw40` son nombres genéricos de variables NVRAM de potencia (`mcsbw402gpo` 0x52ee7, `bw40po` 0x531f8, `legofdm40duppo` 0x52fe2), compartidos por toda la familia; no prueban que el chip pueda 40 MHz. La NVRAM de la D750 solo define `aa2g=1` y `mcs2gpo0/1=0` (sin offsets de 40 MHz).
- **Lo que controla el host** (iovars que usa Nikon, 0xe700-0xf400): `nmode`, `nrate`, `sgi_tx`, `sgi_rx`, `ampdu_manual_mode`, `chanspec`, `mfp`, `phy_txpwrindex`, `iscan`, `counters`. **No usa** `mimo_bw_cap` ni `bw_cap`. Qué `chanspec` fija (ancho 20 vs 40 MHz) queda por rastrear en Ghidra (`_wma` cargado como ARM Thumb, base probable `0x00800000` por la tabla de punteros en 0x38001).
- Búsqueda web (no concluyente): no encontré ninguna fuente que diga que el BCM43362 sea de solo 20 MHz ni que soporte HT40; el módulo Inventek lo anuncia a 20 MHz. Con Linux/brcmfmac el soporte HT40 se pregunta al firmware. Prueba definitiva: consultar las capacidades del chip (`iw phy` con otro host) o leer el PHY en la ROM.

### H21 · ¿Se puede actualizar el firmware del chip? (análisis, no se hizo nada; H26 muestra que no aportaría ancho de banda)
- El blob se carga en la RAM del chip en cada arranque (`Write the firm to the RAM`, `Read the firm to the RAM`, `Chip Init`), así que actualizarlo = reemplazarlo dentro del módulo `_wma` del firmware de la cámara y reempaquetar. No hay otro camino: el chip no tiene flash propia.
- Cambiar el blob exige recalcular el CRC16 del módulo y el CRC de paquete (viables: algoritmo conocido, verificado) y el mismo tamaño/ubicación (la imagen cargada está en RAM del chip con espacio limitado). **Por confirmar:** si la D750 valida algo más que los CRC; el archivo no trae el digest SHA-1 con clave de las Z (empieza con 32 espacios), pero no sé si la cámara lo comprueba de otra forma.
- Un firmware más nuevo no habilitaría 40 MHz si el límite es del PHY; el 5.90.153.x ya es el de la familia 43362 (2013) y las versiones posteriores de Cypress/Infineon son correcciones. **Riesgo alto:** un `_wma` malo puede dejar sin WiFi o brickear la cámara. No se flashea nada sin petición explícita.
- Fuentes: https://lore.kernel.org/all/20130611153052.GA18389@ws/T/, https://wireless.docs.kernel.org/en/latest/en/users/drivers/b43.html

## 2026-10-31 · Análisis en Ghidra: WiFi y opciones desbloqueables

### H22 · `_wma_ver01.00.00` es un archivo DfuSe de un STM32 con dos imágenes (verificado)
Comando: parseo de la cabecera DfuSe (versión 1, destino `01000014WLAN1`, 2 elementos); `shasum -a 256 work/d750_modulos/wma_*.bin`.
- Elemento 0: dirección de flash **`0x08020000`**, 227928 bytes (`wma_stm32_app.bin`) = firmware del microcontrolador WLAN (código Thumb de Cortex-M; pila de red de Ubiquitous Corp.). Importado en Ghidra como `ARM:LE:32:Cortex`, base `0x08020000` (proyecto `work/ghidra-wma/`).
- Elemento 1: dirección **`0x08060000`**, 212896 bytes (`wma_bcm43362_fw.bin`) = firmware del Broadcom BCM43362 (5.90.153.0, en claro), que el STM32 vuelca a la RAM del chip por SDIO.
- Corrige H20/H21: el blob del chip es el elemento 1 completo, no un rango estimado. Pie DfuSe `UFD` presente.

### H23 · Cómo fija el ancho de canal la cámara (verificado en decompilado; interpretación por confirmar)
Comando: `analyzeHeadless … -postScript DecompRefs.java work/wma_chanspec.c chanspec nmode nrate sgi_tx ampdu_manual_mode` y `DecompCallers.java` (scripts en `scripts/ghidra/`; salidas `work/wma_chanspec.c`, `work/wma_callers.c`).
- Los iovars se envían con un envoltorio común `FUN_0802dc66(nombre, ctx, 4, valor)`. `chanspec` → `FUN_0802ea3c` (0x0802ea3c); `nmode` → `FUN_0802e6b0`; `nrate` → `FUN_0802e8f2`; `sgi_tx` → `FUN_0802ea18`.
- `FUN_0802bc20` (selección de canal, mensaje `select channel %d`) pasa solo el **número de canal** (`local_6c & 0xff`) a `chanspec`, sin los bits de ancho de banda: queda el ancho por defecto del chip (20 MHz en 2,4 GHz). `FUN_08029c6e` (arranque del modo AP, `[WLAN] ====>`) fija `sgi_tx = -1` (auto) y `sgi_rx = 1`.
- La cámara nunca usa `bw_cap`, `mimo_bw_cap` ni un `chanspec` con ancho de 40 MHz. **Palanca teórica:** parchear el STM32 para fijar `bw_cap`/`chanspec` de 40 MHz. **Condición:** que el PHY del BCM43362 soporte HT40, no demostrado (H19/H20); si no, no hay efecto o el chip lo rechaza.

### H24 · Sistema operativo y opciones de depuración del programa principal (verificado cadenas; uso por confirmar)
Comandos: `DumpStrings.java` → `work/main_strings.tsv` (1884 cadenas ASCII con xref) y extracción UTF-16BE → `work/main_utf16be.tsv` (56842 secuencias, incluye los textos de los menús y mensajes).
- SO: **T-Kernel (T-Engine/Extension)** con POSIX y SMP (`TSysName=T-Kernel`, `SMP_SPMCoreNum`, `MEMPART_*`). Claves de configuración con nombres de depuración: `DEBUGMODE`, `ConsDrvEnable`, `DEBUGPORT`, `RsDrvEnable`, `TmConsEnable`, `TmDebugPort`, `TmBaudRate` (0x91264f83-0x91265258) y rutinas `UART_SetConfiguration/SetSendEnabled` (0x9000ddf4). Sugieren una consola serie de depuración; el valor por defecto y cómo se activa quedan por confirmar (los nombres están en una tabla, sin xref directa).
- Volcados de depuración de fábrica, con la función que los usa: `A:\LVRAW%03d.RAW` (0x901c6038, fn 0x901c5ba4), `A:\SIG%04d.RAW` (0x901c64d4, fn 0x901c615a), `B:\1140_12.RAW` / `B:\1140_14.RAW` (0x901c2a08/0x901c29f8, fn 0x9019f3ee), `B:\TESTJPEG.JPG` (fn 0x901c001a), `A:\TEST%04d.WAV` / `B:\TEST%04d.WAV`. También `DebugCmd %d %x %d` (0x900a1630) y `Regist Limit Error`.
- Protección térmica del WiFi: mensaje `Network access not available until camera cools. Wi-Fi connection disabled.` (en el bloque UTF-16BE de mensajes, cerca de 0x753901): confirma que existe una condición de desactivación por temperatura.
- Textos de interfaz: menús y mensajes en inglés desde 0x73d5b5 hasta ≈0x754500 y otros idiomas en bloques vecinos (ver H9: el bloque 137 es texto de menús).

### H25 · Qué NO se encontró todavía (por confirmar)
- Límites de video (29 min 59 s), lista de ISO, tablas de región/país de la cámara (solo `xmp:Country`), restricciones por mercado: no se localizaron constantes ni tablas. Requieren rastrear desde los textos de menú hasta sus ajustes (el principal está en `b1010_115a.bin`, 13303 funciones sin nombres salvo `CMoviePlayApplicationService_*`).
- La validación de la cámara al actualizar: no se sabe si comprueba más que los CRC (H21). Sin eso no se debe proponer un parche que se flashee.

## 2026-10-31 · Hoja de datos CYW43362, calidad de imagen y depuración

### H26 · El WiFi está limitado por el hardware a 20 MHz (verificado con la hoja de datos oficial)
Fuente: `~/Downloads/CYW43362.PDF` (hoja de datos de Cypress; `pdftotext -layout` y grep).
- §5.2 PHY: `IEEE 802.11b/g/n single stream … data rates from 1 Mbps to 72 Mbps`. Tabla de sensibilidad RX: `20 MHz channel spacing for all MCS rates` (MCS0-MCS7, MCS7 = 72 Mbps) y filtro de 3 dB de 9-10 MHz. No hay ningún modo de 40 MHz ni MCS por encima de 7.
- Conclusión: el techo de ~72 Mbps de PHY (≈25-30 Mbps reales, 3-4 MB/s) es del chip; **no hay parche de firmware que suba el caudal**. Cierra H19/H23 en negativo: ni el `chanspec`, ni `bw_cap`, ni cambiar el blob del chip (H21) pueden agregar 40 MHz. El único margen es de eficiencia (p. ej. `ampdu_manual_mode`, `sgi_tx`), sin ganancia medible esperable.

### H27 · Compresión de imagen: ya hay RAW sin pérdida; no hay modo sin comprimir (verificado en textos del menú)
Comando: `grep -iE "compress|lossless|uncompress|NEF|12-bit|14-bit" work/main_utf16be.tsv`.
- Menú de la D750 (0x756f2b): `Lossless compressed`, `Compressed`, `12-bit`, `14-bit`. No existe `Uncompressed` en las cadenas del programa. Ayuda de menú (0x75a965): `"Compressed" uses non-reversible compression for smaller file sizes`; JPEG: `Size priority` / `Optimal quality`.
- Implicación (razonamiento, por confirmar): **NEF 14-bit sin pérdida ya conserva todos los datos del sensor**; un modo sin comprimir tendría el mismo contenido en archivos mayores, así que no mejora la calidad. Mejor que eso, solo podría ser quitar el procesado interno del RAW (reducción de ruido/«cooking» de la D750 no documentado), que no se ha investigado.
- JPEG: las tablas de cuantización y el motor JPEG están en la parte no resuelta del principal; subir la calidad del JPEG es posible en teoría pero irrelevante frente al NEF.

### H28 · Depuración y puerto serie (verificado la existencia; sin forma conocida de activarlo)
- Tabla de configuración de T-Kernel (0x9126e4e8, bytes en `b1010_115a.bin` desde `0x126e4a0`): `DEBUGMODE`, `TmConsEnable`, `TmDebugPort`, `TmBaudRate`; justo antes de `TmDebugPort` hay el valor `00 c2 01 00` = **115200** (little-endian `0x0001c200`), probable velocidad de la consola serie. Valores de `DEBUGMODE`/`TmConsEnable` y qué puerto es: por confirmar.
- Ninguna de esas cadenas (ni `DebugCmd %d %x %d`, `UART_SetConfiguration…`, `serialNo`, `API LIMITED`) tiene referencias en la importación a base `0x90000000`: búsqueda de sus direcciones como literales en el binario → 0 coincidencias. Es consistente con que el archivo principal contiene **varias imágenes enlazadas a otras direcciones** (solo 586 de 1884 cadenas tienen xref), así que la importación actual cubre solo una parte del código. Falta partir el principal en sus imágenes y cargar cada una con su base.
- Acceso: una consola UART exigiría abrir la cámara y soldar a pads de la placa, o un comando de depuración por USB/PTP que no se ha encontrado. No se hizo nada en la cámara.
