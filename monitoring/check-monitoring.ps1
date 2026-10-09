$ErrorActionPreference = 'Continue'
$checks = @(
    @{ Name = 'FastAPI metrics'; Url = 'http://127.0.0.1:8000/metrics' },
    @{ Name = 'Analyzer metrics'; Url = 'http://127.0.0.1:8001/metrics' },
    @{ Name = 'Prometheus'; Url = 'http://127.0.0.1:9090/-/ready' },
    @{ Name = 'Grafana'; Url = 'http://127.0.0.1:3001/api/health' },
    @{ Name = 'Next.js'; Url = 'http://127.0.0.1:3000' }
)
foreach ($check in $checks) {
    try {
        $response = Invoke-WebRequest -Uri $check.Url -TimeoutSec 4 -UseBasicParsing
        Write-Host "$($check.Name): reachable (HTTP $([int]$response.StatusCode))"
    } catch {
        Write-Warning "$($check.Name): unavailable at $($check.Url) ($($_.Exception.Message))"
    }
}
try {
    $target = Invoke-RestMethod -Uri 'http://127.0.0.1:9090/api/v1/targets' -TimeoutSec 4
    $backend = $target.data.activeTargets | Where-Object { $_.labels.job -eq 'nigraani-backend' }
    if ($backend) { Write-Host "Prometheus nigraani-backend target: $($backend.health) ($($backend.scrapeUrl))" }
    else { Write-Warning 'Prometheus has no active nigraani-backend target.' }
} catch { Write-Warning "Could not query Prometheus target status: $($_.Exception.Message)" }
