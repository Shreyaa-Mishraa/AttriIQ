#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
python -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
if grep -q '^DEMO_MODE: false' config.yaml; then
  sed -i.bak 's/^DEMO_MODE: false/DEMO_MODE: true/' config.yaml
fi
python run_all.py
echo "Dashboard at http://127.0.0.1:8050"
