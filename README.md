# nikond750

Reverse engineering of the Nikon D750 firmware (`D750_0115.bin`): container, encryption, CPU, WiFi chip.
Research notes and tooling; **no Nikon firmware, keys or derived binaries are included** (you supply your own images).
Everything was done read-only on the firmware file; the camera was never touched or flashed.

## Results (English summary)

- **Encryption**: the same 3-table XOR scheme as the Nikon Z cameras (`plain[i] = c[i] ^ T1[i&255] ^ T2[(i>>8)&255] ^ T3[(i>>16)&255]`,
  see [WonderLantern/nikon-fw-key-tool](https://github.com/WonderLantern/nikon-fw-key-tool)), but the body starts at file offset 0.
  T1/T2 are identical to the Z tables; T3 was recovered from the D750, D800, D500, D850, D780 and Z 6 images plus a CRC16 oracle.
  All three modules and the package CRC of the D750 verify.
- **Modules**: main application (ARM 32-bit LE, Thumb-2 mixed, T-Kernel), a bootloader-like blob, and `_wma` = a DfuSe file with
  an STM32 WLAN firmware (flash `0x08020000`) and the Broadcom **BCM43362** firmware 5.90.153.0 (`0x08060000`, plaintext).
- **WiFi speed**: the chip is 1x1 802.11n, 20 MHz channel only, MCS0-7 (CYW43362 datasheet). The ~3-4 MB/s ceiling is hardware;
  there is nothing in the firmware to patch to raise it.
- **Open for anyone with test bodies**: split the main image into its linked sub-images, find what the update routine validates
  (only CRCs?), settings tables, debug console (`DEBUGMODE`/`TmConsEnable`, 115200 baud entry), live-view hooks.

Full evidence (hashes, offsets, commands, verified vs. to-confirm): [`docs/HALLAZGOS.md`](docs/HALLAZGOS.md). Plan and status: [`docs/PLAN.md`](docs/PLAN.md).

## Reproduce (Spanish notes in docs)

```bash
scripts/setup.sh --check                         # Ghidra, binwalk, unblob, rizin, 7zip, Python venv
python3 -I scripts/fwinfo.py firmware/D750_0115.bin
# clone WonderLantern/nikon-fw-key-tool into work/wonderlantern (GPL-3.0, used only as a library, not bundled)
.venv/bin/python -I scripts/d750_solve_tables.py work/wonderlantern work/key.json firmware/D750_0115.bin firmware/D800_0111.bin ...
.venv/bin/python -I scripts/d750_fill_t3.py work/wonderlantern work/key.json work/key_full.json firmware/*.bin
.venv/bin/python -I scripts/d750_crc_oracle.py work/key_full.json firmware/*.bin   # per-module CRC16 remainder
.venv/bin/python -I scripts/d750_extract_modules.py work/key_full.json firmware/D750_0115.bin work/d750_modulos
```

Ghidra helper scripts are in `scripts/ghidra/`. `firmware/` and `work/` are git-ignored.

## Disclaimer

Independent research on firmware you own, for interoperability and documentation. Not affiliated with Nikon.
Modifying or flashing camera firmware can permanently damage the camera; do it at your own risk. Nikon is a trademark of Nikon Corporation.

## License

[MIT](LICENSE) for the code and notes in this repository. `nikon-fw-key-tool` (GPL-3.0) is referenced and imported at run time
but not included.

Contexto original (español): el WiFi de la D750 va a ~2-4 MB/s con [nikon_snoop](https://github.com/blefaudeux/nikon_snoop);
la skill de [REA](https://github.com/morluto/rea) llega por el plugin `rea@rea` y su MCP está en `.mcp.json`.
