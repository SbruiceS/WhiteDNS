param(
    [string]$Binary = ".\build\whitedns",
    [string]$DomainFile = ".\tests\production_domains.txt",
    [string]$Server = "8.8.8.8",
    [string]$OutputDir = ".\test-results"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Binary)) {
    throw "WhiteDNS binary not found: $Binary"
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Get-Content $DomainFile | Where-Object { $_ -and -not $_.StartsWith("#") } | ForEach-Object {
    $domain = $_.Trim()
    Write-Host "== WhiteDNS smoke: $domain =="
    $output = & $Binary -j -s $Server -r -n -w -x -t A,AAAA,NS,MX,TXT $domain
    if ($LASTEXITCODE -ne 0) {
        throw "WhiteDNS failed for $domain with exit code $LASTEXITCODE"
    }
    $artifact = Join-Path $OutputDir "$domain.json"
    $output | Set-Content -Path $artifact -Encoding UTF8
    $report = $output | ConvertFrom-Json
    $queryErrors = @($report.queries | Where-Object { $_.error }).Count
    $warnings = @($report.checks | Where-Object { $_.status -eq "warning" -or $_.status -eq "critical" }).Count
    Write-Host "queries=$(@($report.queries).Count) checks=$(@($report.checks).Count) query_errors=$queryErrors warnings=$warnings artifact=$artifact"
}
