#!/usr/bin/env python3
"""Descifra la D750 con la clave completa y vuelca los módulos (sin el CRC final de 2 bytes). Solo lectura sobre el .bin.
Uso: python3 -I scripts/d750_extract_modules.py <key.json> <bin> <dir_salida>"""
import sys, json, struct, os, binascii
import numpy as np
k = json.load(open(sys.argv[1]))
t1, t2, t3 = (np.frombuffer(bytes.fromhex(k[x]), dtype=np.uint8).copy() for x in ('T1', 'T2', 'T3'))
raw = open(sys.argv[2], 'rb').read(); hdr = 0 if raw[:32] == b' ' * 32 else 0x20
body = np.frombuffer(raw[hdr:], dtype=np.uint8); j = np.arange(len(body))
ks = t1[j & 0xFF] ^ t2[(j >> 8) & 0xFF] ^ t3[(j >> 16) & 0xFF]; ks[:0x20] = 0
plain = (body ^ ks).tobytes()
os.makedirs(sys.argv[3], exist_ok=True)
open(os.path.join(sys.argv[3], 'cuerpo_descifrado.bin'), 'wb').write(plain)
cnt, _ = struct.unpack_from('>II', plain, 0x20)
for i in range(cnt):
    o = 0x30 + 32 * i
    name = plain[o:o+16].rstrip(b'\0').decode('latin1'); st, ln = struct.unpack_from('>II', plain, o + 16)
    m = plain[st:st+ln-2]
    ok = binascii.crc_hqx(plain[st:st+ln], 0) == 0
    open(os.path.join(sys.argv[3], name), 'wb').write(m)
    print('%-18s off=0x%08x len=%9d CRC16 %s' % (name, st, len(m), 'OK' if ok else 'MAL'))
print('CRC paquete:', 'OK' if binascii.crc_hqx(plain[:-16], 0) == struct.unpack_from('>H', plain, len(plain) - 16)[0] else 'no coincide (formato D750 distinto o trailer)')
