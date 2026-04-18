#!/usr/bin/env pwsh
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python launcher 'py' not found. Install Python 3.13+ from python.org, then rerun."
}

try {
    py -3.13 --version | Out-Null
}
catch {
    throw "Python 3.13 is required. Install it and ensure py -3.13 works."
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "[i] Installing uv..."
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    $env:Path = "$HOME\.cargo\bin;$env:Path"
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    throw "uv install failed. Install uv manually: https://docs.astral.sh/uv/getting-started/installation/"
}

Write-Host "[i] Creating .venv with Python 3.13..."
uv venv --python 3.13 .venv

Write-Host "[i] Syncing dependencies..."
uv sync --dev --all-extras --no-sources

Write-Host "[i] Installing ArchiveBox monorepo plugin dependencies..."
uv pip install -e ./abxpkg -e ./abx-plugins[dev] -e ./abx-dl

Write-Host "[i] Running Archiveteam focused test suites..."
uv run --no-sync --no-sources pytest -q tests/test_archiveteam_mvp.py tests/test_archiveteam_api.py

Write-Host "[√] Windows bootstrap complete."
Write-Host "[i] Activate venv: .\.venv\Scripts\Activate.ps1"
