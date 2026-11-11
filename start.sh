#!/usr/bin/env bash
# Linux / macOS launcher (same features as START.bat)
set -e
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
[ -f .venv/.installed ] || { .venv/bin/pip install -r requirements.txt && touch .venv/.installed; }
exec .venv/bin/python -m secure_transfer "$@"
