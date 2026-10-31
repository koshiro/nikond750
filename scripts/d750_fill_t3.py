#!/usr/bin/env python3
"""Completa T3 puntuando cada índice faltante con los bloques de TODAS las imágenes y valida CRC de módulos/paquete.
Uso: python3 -I scripts/d750_fill_t3.py <wonderlantern_dir> <key.json> <key_completa.json> <bin>..."""
import sys, json
sys.path.insert(0, sys.argv[1])
import numpy as np
import decrypt_firmware as fw
k = json.load(open(sys.argv[2]))
t1, t2, t3 = (np.frombuffer(bytes.fromhex(k[x]), dtype=np.uint8).copy() for x in ('T1', 'T2', 'T3'))
known = set(k['T3_cubiertos'])
imgs = []
for p in sys.argv[4:]:
    raw = open(p, 'rb').read(); hdr = 0 if raw[:32] == b' ' * 32 else 0x20
    body = raw[hdr:]; n = len(body) // 256
    imgs.append((p, hdr, raw, np.frombuffer(body[:n*256], dtype=np.uint8).reshape(n, 256)))
def pooled(b):
    parts = []
    for _, _, _, sec in imgs:
        if len(sec) > b * 256:
            idx = np.concatenate([np.arange(s, min(s + 256, len(sec))) for s in range(b * 256, len(sec), 1 << 16)])
            parts.append((sec[idx] ^ t1 ^ t2[idx & 0xFF][:, None]).reshape(-1))
    return np.concatenate(parts)
flips = 0
for b in sorted(known):  # etapa 5: ambigüedad relleno 0x00/0xFF -> elegir el miembro del par con más ceros
    cnt = np.bincount(pooled(b), minlength=256)
    c = int(t3[b])
    if cnt[c ^ 0xFF] > cnt[c]:
        t3[b] = c ^ 0xFF; flips += 1
print('T3 conocidos corregidos por complemento 0xFF:', flips)
for b in sorted(set(range(256)) - known):
    parts = []
    for _, _, _, sec in imgs:
        idx = np.concatenate([np.arange(s, min(s + 256, len(sec))) for s in range(b * 256, len(sec), 1 << 16)]) if len(sec) > b * 256 else np.array([], dtype=int)
        if len(idx): parts.append((sec[idx] ^ t1 ^ t2[idx & 0xFF][:, None]).reshape(-1))
    x = np.concatenate(parts)
    sc = [int(((x ^ np.uint8(c)) == 0).sum()) for c in range(256)]
    order = np.argsort(sc)[::-1]
    t3[b] = order[0]
    print('T3[%3d]=%02x  (%d bytes; ceros %d, 2.º %02x con %d)' % (b, order[0], len(x), sc[order[0]], order[1], sc[order[1]]))
def dec(raw, hdr):
    body = np.frombuffer(raw[hdr:], dtype=np.uint8); n = len(body) // 256
    out = bytearray(raw)
    j = np.arange(len(body))
    ks = (t1[j & 0xFF] ^ t2[(j >> 8) & 0xFF] ^ t3[(j >> 16) & 0xFF])
    ks[:0x20] = 0
    out[hdr:] = (body ^ ks).tobytes()
    return bytes(out)
for p, hdr, raw, _ in imgs:
    try:
        mods = fw.validate_firmware(memoryview(dec(raw, hdr))[hdr:])
        print(p, 'OK', len(mods), 'módulos + CRC paquete')
    except Exception as e:
        print(p, 'FALLA:', e)
json.dump({'T1': bytes(t1).hex(), 'T2': bytes(t2).hex(), 'T3': bytes(t3).hex(), 'T3_cubiertos': list(range(256))}, open(sys.argv[3], 'w'))
