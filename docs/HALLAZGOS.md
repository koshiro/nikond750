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
