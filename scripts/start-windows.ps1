$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Install Docker Desktop first, then reopen this launcher."
    }
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        $desktopPath = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
        if (Test-Path $desktopPath) { Start-Process $desktopPath }
        Write-Host "Waiting for Docker Desktop..."
        $ready = $false
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            Start-Sleep -Seconds 2
            docker info *> $null
            if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        }
        if (-not $ready) { throw "Docker is not ready. Finish Docker Desktop setup, then run start.cmd again." }
    }
    if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }
    Write-Host "Building and starting CYVRA. The first start downloads dependencies."
    docker compose up --build -d
    if ($LASTEXITCODE -ne 0) { throw "Startup failed. Copy the error above so it can be diagnosed." }
    Write-Host "Waiting for CYVRA at http://localhost:3000..."
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing -TimeoutSec 3
            if ($response.StatusCode -eq 200) {
                Start-Process "http://localhost:3000"
                Write-Host "CYVRA is ready. Use Website Check, or Launch demo for evidence analysis."
                exit 0
            }
        } catch { }
        Start-Sleep -Seconds 2
    }
    docker compose ps -a
    docker compose logs --tail=40
    throw "CYVRA did not become ready. Review the logs above."
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
