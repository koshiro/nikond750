#!/usr/bin/env python3
"""Usa los CRC16 de módulo (lineales) como oráculo para corregir T3 de a un índice. Solo lectura.
Uso: python3 -I scripts/d750_crc_oracle.py <key_full.json> <bin>..."""
import sys, json, struct, binascii
import numpy as np
k = json.load(open(sys.argv[1]))
t1, t2, t3 = (np.frombuffer(bytes.fromhex(k[x]), dtype=np.uint8).copy() for x in ('T1', 'T2', 'T3'))
def keystream(n):
    j = np.arange(n); ks = t1[j & 0xFF] ^ t2[(j >> 8) & 0xFF] ^ t3[(j >> 16) & 0xFF]; ks[:0x20] = 0; return ks
def contrib(length, start_blk, b, bit):
    """crc_hqx(0) del patrón: byte (1<<bit) en las posiciones del módulo cuyo índice T3 es b"""
    pat = np.zeros(length, dtype=np.uint8)
    pos = np.arange(start_blk, start_blk + length)
    pat[((pos >> 16) & 0xFF) == b] = 1 << bit
    return binascii.crc_hqx(pat.tobytes(), 0)
res = {}
for p in sys.argv[2:]:
    raw = open(p, 'rb').read(); hdr = 0 if raw[:32] == b' ' * 32 else 0x20
    body = np.frombuffer(raw[hdr:], dtype=np.uint8); plain = (body ^ keystream(len(body))).tobytes()
    cnt, dsz = struct.unpack_from('>II', plain, 0x20)
    for i in range(cnt):
        o = 0x30 + 32 * i
        name = plain[o:o+16].rstrip(b'\0').decode('latin1'); st, ln = struct.unpack_from('>II', plain, o + 16)
        r = binascii.crc_hqx(plain[st:st+ln], 0)
        touched = sorted({int(x) for x in np.unique(((np.arange(st, st + ln, 4096)) >> 16) & 0xFF)})
        print(p.split('/')[-1], i + 1, name, hex(st), ln, 'resto CRC=%04x' % r, 'OK' if r == 0 else 'ERROR', 'índices T3 tocados: %d' % len(touched))
        if r:
            sol = []
            for b in touched:
                basis = [contrib(ln, st, b, bit) for bit in range(8)]
                for d in range(1, 256):
                    c = 0
                    for bit in range(8):
                        if d >> bit & 1: c ^= basis[bit]
                    if c == r: sol.append((b, d))
            print('   soluciones de un solo índice (b, d):', sol[:10], '(n=%d)' % len(sol))
