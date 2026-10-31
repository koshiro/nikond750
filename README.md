# nikond750

Ingeniería inversa del firmware de la Nikon D750, con foco en el WiFi y la transferencia PTP/IP.

```bash
scripts/setup.sh            # instala Ghidra, Binwalk, Unblob, Rizin, 7zip, QEMU, bindings Python
scripts/setup.sh --check    # verifica
python3 -I scripts/fwinfo.py firmware/<archivo>.bin   # tamaño, SHA-256, entropía, firmas, cadenas WiFi
```

Estructura: `firmware/` y `work/` (ignorados, locales), `scripts/`, `docs/`, `.claude/skills/` (skill `d750-firmware`
; la skill de [REA](https://github.com/morluto/rea) llega por el plugin `rea@rea` y su MCP está en `.mcp.json`). Plan en `docs/PLAN.md`.

Contexto: el WiFi de la D750 va a ~2-4 MB/s con [nikon_snoop](https://github.com/blefaudeux/nikon_snoop); el USB 2.0
rinde ~10 veces más. Aquí se investiga si hay un límite editable en el firmware.
