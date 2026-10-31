#!/usr/bin/env bash
# Instala (o comprueba con --check) las herramientas para el firmware de la D750. macOS + Homebrew.
set -euo pipefail
cd "$(dirname "$0")/.."

FORMULAS=(ghidra binwalk rizin sevenzip qemu capstone unicorn keystone)  # ghidra de brew = 12.2 (uso directo); REA necesita 12.1.4 en ~/tools (ver AGENTS.md)
BINS=(ghidraRun binwalk rizin 7zz qemu-system-arm unblob)

if [[ "${1:-}" == "--check" ]]; then
  for b in "${BINS[@]}"; do printf '%-18s' "$b"; command -v "$b" || echo "FALTA"; done
  printf '%-18s' analyzeHeadless; ls "$(brew --prefix ghidra)"/libexec/support/analyzeHeadless 2>/dev/null || echo FALTA
  printf '%-18s' "python bindings"; .venv/bin/python -I -c 'import capstone, unicorn, keystone; print("ok")' 2>/dev/null || echo FALTA
  exit 0
fi

# Un solo `brew install` a la vez: dos procesos se bloquean entre sí (Cellar lock).
brew install "${FORMULAS[@]}"
pipx install --backend pip unblob || true
[[ -d .venv ]] || python3 -m venv .venv
.venv/bin/pip install -q capstone unicorn keystone-engine pyelftools numpy
"$0" --check
