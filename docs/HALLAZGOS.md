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

### H10 · Falta T3 en 201 de 256 bloques de 64 KiB (por resolver)
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
