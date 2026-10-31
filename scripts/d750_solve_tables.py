#!/usr/bin/env python3
"""Recupera T1/T2/T3 combinando imágenes (D750 cuerpo en 0x00, resto en 0x20). Solo lectura.
Uso: python3 -I scripts/d750_solve_tables.py <wonderlantern_dir> <salida.json> <bin>..."""
import sys, json, hashlib
sys.path.insert(0, sys.argv[1])
import numpy as np
import extract_key as ek
imgs = []
for p in sys.argv[3:]:
    raw = open(p, 'rb').read()
    hdr = 0 if raw[:32] == b' ' * 32 else 0x20
    assert raw[hdr:hdr+32] == b' ' * 32, p
    body = raw[hdr:]; n = len(body) // 256
    imgs.append((p, hdr, np.frombuffer(body[:n*256], dtype=np.uint8).reshape(n, 256)))
    print(p, 'hdr', hex(hdr), 'sectores', n)
norms = {ek.recover_family(s) for _, _, s in imgs}
print('familias T1 distintas:', len(norms), [None if x is None else x.hex()[:16] for x in norms])
norm = next(x for x in norms if x is not None)
t1, table = ek.fix_constant(imgs[0][2], norm)
obs = ek.collect_observations([(p, '', s) for p, _, s in imgs], t1)
print('T3 cubiertos', len({b for _, b in obs}), '/256')
t2d, t3d = ek.solve_tables(obs)
print('T2 %d/256, T3 %d/256' % (len(t2d), len(t3d)))
t2 = np.array([t2d[i] for i in range(256)], dtype=np.uint8)
t3 = np.array([t3d.get(i, 0) for i in range(256)], dtype=np.uint8)
ch = ek.correct_t3([(p, '', s) for p, _, s in imgs], t1, t2, t3) if len(t3d) == 256 else []
print('T3 corregidos por etapa 5:', len(ch))
for k, t in (('T1', t1), ('T2', t2), ('T3', t3)):
    print(k, hashlib.sha256(bytes(t)).hexdigest()[:32], 'esperado', ek.EXPECTED_SHA[k])
json.dump({'T1': bytes(t1).hex(), 'T2': bytes(t2).hex(), 'T3': bytes(t3).hex(), 'T3_cubiertos': sorted(t3d)}, open(sys.argv[2], 'w'))
