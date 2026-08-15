#!/usr/bin/env sh
# Hunt Sift local installer. Creates a virtual environment and installs this repository only.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python 3.10+ is required. Set PYTHON_BIN if your Python command uses another name." >&2
  exit 1
fi

if [ ! -d "$ROOT/.venv" ]; then
  "$PYTHON_BIN" -m venv "$ROOT/.venv"
fi

"$ROOT/.venv/bin/python" -m pip install --no-build-isolation -e "$ROOT"
echo "Hunt Sift installed locally. Activate with: . "$ROOT/.venv/bin/activate""
echo "Then run: hunt-sift boundaries"
