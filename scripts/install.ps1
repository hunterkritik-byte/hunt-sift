# Hunt Sift local installer. Creates a virtual environment and installs this repository only.
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Python = if ($env:PYTHON_BIN) { $env:PYTHON_BIN } else { "python" }

& $Python --version | Out-Null
if (-not (Test-Path (Join-Path $Root ".venv"))) {
  & $Python -m venv (Join-Path $Root ".venv")
}

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
& $VenvPython -m pip install --no-build-isolation -e $Root
Write-Host "Hunt Sift installed locally. Activate with: .\.venv\Scripts\Activate.ps1"
Write-Host "Then run: hunt-sift boundaries"
