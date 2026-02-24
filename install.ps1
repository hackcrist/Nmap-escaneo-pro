param(
    [switch]$SkipNmap
)

$ErrorActionPreference = "Stop"

function Test-Command($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

function Install-WithWinget($id, $label) {
    if (-not (Test-Command "winget")) {
        Write-Host "[WARN] winget no disponible. Instala $label manualmente."
        return
    }
    Write-Host "[INFO] Instalando $label con winget..."
    winget install --id $id --exact --accept-package-agreements --accept-source-agreements
}

if (-not (Test-Command "python")) {
    Install-WithWinget -id "Python.Python.3.12" -label "Python"
} else {
    Write-Host "[INFO] Python detectado."
}

if (-not $SkipNmap) {
    if (-not (Test-Command "nmap")) {
        Install-WithWinget -id "Insecure.Nmap" -label "Nmap"
    } else {
        Write-Host "[INFO] Nmap detectado."
    }
}

if (Test-Command "python") {
    if (Test-Path ".\requirements.txt") {
        python -m pip install --upgrade pip
        python -m pip install -r .\requirements.txt
    } else {
        python -m pip install --upgrade pip
        python -m pip install colorama
    }
} else {
    Write-Host "[ERROR] Python no esta disponible en PATH."
    exit 1
}

Write-Host "[OK] Instalacion completada."
Write-Host "[RUN] python 'nmap pro.py' --help"
