#!/usr/bin/env python3
"""Sonda del esquema XOR T1/T2/T3 (WonderLantern) sobre la D750. Solo lectura. Uso: python3 -I scripts/d750_t1_probe.py <bin> <wonderlantern_dir> [HDR]"""
import sys, collections
sys.path.insert(0, sys.argv[2])
import numpy as np
import extract_key as ek
hdr = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
raw = open(sys.argv[1], 'rb').read()
body = raw[hdr:]
n = len(body) // 256
sec = np.frombuffer(body[:n*256], dtype=np.uint8).reshape(n, 256)
print('HDR', hdr, 'sectores', n)
blob = sec.tobytes()
cnt = collections.Counter(blob[i:i+256] for i in range(0, len(blob), 256))
print('sectores distintos', len(cnt), 'repetidos (>1):', sum(1 for c in cnt.values() if c > 1), 'top', cnt.most_common(1)[0][1])
norm = ek.recover_family(sec)
print('T1^T1[0] familia:', None if norm is None else norm.hex()[:48])
if norm is None: sys.exit(0)
t1, table = ek.fix_constant(sec, norm)
print('constante fijada:', t1 is not None, 'entradas tabla', len(table))
for t in table[:6]: print('  ', t)
img = [('d750', '', sec)]
if t1 is None: sys.exit(0)
obs = ek.collect_observations(img, t1)
cov = {b for _, b in obs}
print('celdas (a,b) observadas', len(obs), 'T3 cubiertos', len(cov), '/256')
