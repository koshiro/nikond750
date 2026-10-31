#!/usr/bin/env python3
"""Reconocimiento rápido de un firmware: tamaño, SHA-256, entropía por bloques, cadenas y firmas.

Solo lectura, solo biblioteca estándar. Uso: python3 -I scripts/fwinfo.py firmware/D750_0115.bin [--block 65536]
"""
import argparse
import hashlib
import math
import re
import sys
from collections import Counter
from pathlib import Path

# Firmas habituales de contenedores; (offset fijo o None=buscar, bytes, nombre)
MAGICS = [
    (b"\x7fELF", "ELF"), (b"PK\x03\x04", "ZIP"), (b"\x1f\x8b\x08", "gzip"), (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"), (b"hsqs", "SquashFS LE"), (b"sqsh", "SquashFS BE"), (b"\x5d\x00\x00", "LZMA"),
    (b"UBI#", "UBI"), (b"\x27\x05\x19\x56", "U-Boot uImage"), (b"\xd0\x0d\xfe\xed", "FDT/DTB"),
]
KEYWORDS = [b"country", b"40MHz", b"HT40", b"HT20", b"chanspec", b"bandwidth", b"wlan", b"wifi", b"Wi-Fi",
            b"15740", b"PTP", b"ptpip", b"SSID", b"Broadcom", b"Marvell", b"Realtek", b"Atheros", b"Nikon", b"EXPEED"]


def entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    n = len(chunk)
    return -sum(c / n * math.log2(c / n) for c in Counter(chunk).values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--block", type=int, default=65536, help="tamaño de bloque para la entropía")
    ap.add_argument("--min-str", type=int, default=6)
    a = ap.parse_args()

    data = a.path.read_bytes()
    print(f"archivo : {a.path.name}\ntamaño  : {len(data)} bytes\nsha256  : {hashlib.sha256(data).hexdigest()}")
    print(f"cabecera: {data[:32].hex(' ')}")

    print("\n== entropía por bloque (bits/byte; ~8 = cifrado/comprimido, <1 = relleno) ==")
    ents = [entropy(data[i:i + a.block]) for i in range(0, len(data), a.block)]
    for i, e in enumerate(ents):
        bar = "#" * int(e * 4)
        print(f"{i * a.block:#010x}  {e:5.2f}  {bar}")
    if ents:
        print(f"media {sum(ents) / len(ents):.2f}, bloques >7.5: {sum(e > 7.5 for e in ents)}/{len(ents)}, "
              f"bloques <1.0: {sum(e < 1.0 for e in ents)}/{len(ents)}")

    print("\n== firmas de contenedor (cualquier offset) ==")
    found = 0
    for magic, name in MAGICS:
        for m in list(re.finditer(re.escape(magic), data))[:5]:
            print(f"{m.start():#010x}  {name}")
            found += 1
    if not found:
        print("ninguna (consistente con firmware cifrado o formato propietario)")

    print("\n== cadenas ASCII relevantes ==")
    asc = re.compile(rb"[\x20-\x7e]{%d,}" % a.min_str)
    hits = 0
    for m in asc.finditer(data):
        if any(k in m.group() for k in KEYWORDS):
            print(f"{m.start():#010x}  {m.group()[:100].decode()}")
            hits += 1
            if hits >= 200:
                print("... (truncado a 200)")
                break
    if not hits:
        print("ninguna")
    return 0


if __name__ == "__main__":
    sys.exit(main())
