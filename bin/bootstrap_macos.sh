#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[+] Bootstrapping Decentralized Archive Box on macOS..."

if ! command -v brew >/dev/null 2>&1; then
    echo "[X] Homebrew is required. Install from https://brew.sh and re-run this script."
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[X] python3 not found. Install Python 3.13+ first."
    exit 1
fi

PYTHON_VERSION_STR="$(python3 -c 'import sys; print(f\"{sys.version_info[0]}.{sys.version_info[1]}\")')"
PYTHON_MINOR="${PYTHON_VERSION_STR#*.}"
if [[ "${PYTHON_VERSION_STR%%.*}" -lt 3 ]] || [[ "${PYTHON_VERSION_STR%%.*}" -eq 3 && "$PYTHON_MINOR" -lt 13 ]]; then
    echo "[X] Python 3.13+ is required (found $PYTHON_VERSION_STR)."
    exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
    brew install uv
fi

brew install uv node ffmpeg yt-dlp ripgrep

if [[ ! -x "$ROOT_DIR/.venv/bin/python" ]]; then
    uv venv "$ROOT_DIR/.venv"
fi

source "$ROOT_DIR/.venv/bin/activate"
uv sync --dev --all-extras --no-sources
uv pip install -e ./abxpkg -e ./abx-plugins[dev] -e ./abx-dl

mkdir -p tests/out/data
DATA_DIR="$PWD/tests/out/data" uv run --no-sync --no-sources archivebox version < /dev/null
uv run --no-sync --no-sources pytest -q tests/test_archiveteam_mvp.py tests/test_archiveteam_api.py

cat <<'EOF'
[√] macOS bootstrap complete.
Next:
  source .venv/bin/activate
  archivebox server
EOF
