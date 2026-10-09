param(
    [string]$PrometheusDir = (Join-Path $PSScriptRoot 'prometheus-3.15.0.windows-amd64')
)

$ErrorActionPreference = 'Stop'
$exe = Join-Path $PrometheusDir 'prometheus.exe'
$config = Join-Path $PSScriptRoot 'prometheus.yml'
if (-not (Test-Path -LiteralPath $exe)) { throw "Windows Prometheus executable not found: $exe. Extract the Windows AMD64 ZIP and pass its folder with -PrometheusDir." }
if (-not (Test-Path -LiteralPath $config)) { throw "Prometheus config not found: $config" }

& $exe --config.file="$config" --web.listen-address=127.0.0.1:9090
