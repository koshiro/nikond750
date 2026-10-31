# Plan

## Pregunta
¿Hay en el firmware de la D750 un límite de ancho de canal (HT20 vs HT40), de MCS u otro que explique ~2-4 MB/s por
WiFi, y se puede cambiar?

## Contexto verificado en la sesión de origen (2026-10-31)
- nikon_snoop: cliente PTP/IP simple (un socket TCP, un comando a la vez, archivo completo a RAM). No es el cuello.
- WonderLantern (https://github.com/WonderLantern): solo Z (AArch64, EXPEED 6/7). `nikon-fw-key-tool` descifra Z5/6/7/8/9/
  30/50/fc con un XOR de 256 bloques; Z8/Z9 se reempaquetan con firma válida. D750 no está cubierta.
- Parche `wifi_5ghz` de la Z30: cambia una entrada de país (`AA/7` por `US/-1`); sus autores no establecen mejora de velocidad.
- REA (morluto/rea): Binwalk/Unblob verificados solo en Linux x64; análisis nativo solo admite ELF/Mach-O/PE.

## Por confirmar
CPU/arquitectura del firmware de la D750, esquema de cifrado, chip WiFi y si su firmware es un blob aparte.

## Fases
1. Medir el enlace en vivo (`sudo wdutil info`: Tx Rate, MCS, Channel Width) con la cámara conectada.
2. Obtener firmware (versión instalada y C 1.15), `scripts/fwinfo.py`, comparar versiones.
3. Resolver contenedor/cifrado. 4. Ghidra con arquitectura y base correctas. 5. Localizar WiFi/PTP-IP. 6. Informe.
Parchear solo si 1-5 muestran un límite concreto y Daniel lo pide.

## Estado (2026-10-31): cerrado
- Fases 2-5 hechas: firmware descifrado y validado por CRC (H8-H15), arquitectura y chip WiFi identificados (H9, H16, H18, H22), Ghidra cargado (H17, H23-H24).
- Respuesta a la pregunta: **el límite es del hardware** (BCM43362 solo 20 MHz, MCS0-7, hoja de datos CYW43362; H26). No hay nada que parchear para subir el caudal por WiFi.
- Abierto, para quien tenga cámaras de prueba: partir el programa principal en sus imágenes (H28), rutina de actualización y qué valida la cámara (H21/H25), tablas de ajustes. Nunca se flasheó ni se tocó una cámara.
