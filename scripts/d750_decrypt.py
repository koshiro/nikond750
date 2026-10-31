#!/usr/bin/env python3
"""Recupera T1/T2/T3 de la D750 con el método de WonderLantern (cuerpo desde el offset 0) y descifra a work/.
Uso: python3 -I scripts/d750_decrypt.py <bin> <wonderlantern_dir> <salida.dec>. Solo lectura sobre el .bin."""
import sys, math
sys.path.insert(0, sys.argv[2])
import numpy as np
import extract_key as ek
raw = open(sys.argv[1], 'rb').read()
n = len(raw) // 256
sec = np.frombuffer(raw[:n*256], dtype=np.uint8).reshape(n, 256)
t1, table = ek.fix_constant(sec, ek.recover_family(sec))
obs = ek.collect_observations([('d', '', sec)], t1)
t2d, t3d = ek.solve_tables(obs)
print('T2 %d/256, T3 %d/256 (por relleno)' % (len(t2d), len(t3d)))
if len(t2d) < 256:
    sys.exit('T2 incompleto')
t2 = np.array([t2d[i] for i in range(256)], dtype=np.uint8)
def ent(a):
    c = np.bincount(a.ravel(), minlength=256); p = c[c > 0] / c.sum()
    return float(-(p * np.log2(p)).sum())
t3 = np.zeros(256, dtype=np.uint8)
for b in range(256):
    idx = np.arange(b * 256, min((b + 1) * 256, n))
    if len(idx) == 0: continue
    blk = sec[idx] ^ t1 ^ t2[idx & 0xFF][:, None]
    # XOR con constante no cambia la entropía: se puntúa por bytes cero (como en WonderLantern)
    best = max(range(256), key=lambda c: int(((blk ^ np.uint8(c)) == 0).sum()))
    if b in t3d:
        if t3d[b] != best:
            print('  T3[%d] relleno=%02x ceros=%02x' % (b, t3d[b], best))
        best = t3d[b]
    t3[b] = best
out = bytearray(raw)
for j in range(n):
    k = t1 ^ t2[j & 0xFF] ^ t3[(j >> 8) & 0xFF]
    out[j*256:(j+1)*256] = (sec[j] ^ k).tobytes()
# la etiqueta de 32 espacios queda en claro (índices < 0x20)
out[:0x20] = raw[:0x20]
open(sys.argv[3], 'wb').write(out)
print('T1', bytes(t1).hex()[:32], 'T2', bytes(t2).hex()[:32], 'T3', bytes(t3).hex()[:32])
sub = np.frombuffer(bytes(out[:1 << 20]), dtype=np.uint8)
print('entropía primer MiB descifrado: %.3f' % ent(sub))
print(bytes(out[0x20:0x70]).hex(' '))

import struct
def crc16(d):
    c = 0
    for x in d:
        c ^= x << 8
        for _ in range(8): c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c
cnt, dsz = struct.unpack_from('>II', out, 0x20)
print('módulos', cnt, 'dir', dsz)
for i in range(cnt):
    o = 0x30 + 32 * i
    name = bytes(out[o:o+16]).rstrip(b'\0'); off, ln = struct.unpack_from('>II', out, o + 16)
    print(' ', name, hex(off), ln, 'CRC16(módulo)=%04x' % crc16(bytes(out[off:off+ln])))
print('CRC16 paquete (todo menos 16 finales) vs últimos 2 antes de 14 ceros: %04x' % crc16(bytes(out[:-16])), bytes(out[-16:]).hex())
