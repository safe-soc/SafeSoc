#!/usr/bin/env pwsh
<#
.SYNOPSIS
    SafeSOC one-command installer/quickstart (SS-072, Windows/PowerShell).

.DESCRIPTION
    Verifies Docker is installed and running, copies .env.example to .env
    if one doesn't exist yet, brings up the full docker-compose stack
    (OpenSearch, PostgreSQL, Redis, backend, Celery worker, Celery beat),
    waits for the backend's own /health check to report healthy, and
    prints the next step (provisioning a demo tenant).

    Safe to re-run: every step is idempotent - an already-running stack
    is left alone (docker compose up is itself idempotent), and an
    existing .env is never overwritten.

.EXAMPLE
    ./scripts/install.ps1
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Write-Step($message) {
    Write-Host "==> $message" -ForegroundColor Cyan
}

function Write-Success($message) {
    Write-Host "OK  $message" -ForegroundColor Green
}

function Write-Failure($message) {
    Write-Host "FAIL $message" -ForegroundColor Red
}

Write-Step "Checking Docker is installed"
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    Write-Failure "Docker was not found on PATH. Install Docker Desktop: https://docs.docker.com/get-docker/"
    exit 1
}
Write-Success "Docker found: $($dockerCmd.Source)"

Write-Step "Checking the Docker daemon is running"
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Failure "Docker daemon is not reachable. Start Docker Desktop and re-run this script."
    exit 1
}
Write-Success "Docker daemon is reachable"

$envFile = Join-Path $repoRoot ".env"
$envExample = Join-Path $repoRoot ".env.example"
Write-Step "Checking for a .env file"
if (Test-Path $envFile) {
    Write-Success ".env already exists - leaving it untouched"
} elseif (Test-Path $envExample) {
    Copy-Item $envExample $envFile
    Write-Success "Copied .env.example -> .env (every setting has a working local-dev default; edit .env to add real API keys/tokens later)"
} else {
    Write-Host "No .env.example found - every service has a working default without one, continuing." -ForegroundColor Yellow
}

Write-Step "Starting the SafeSOC stack (docker compose up --build -d)"
Push-Location $repoRoot
try {
    docker compose up --build -d
    if ($LASTEXITCODE -ne 0) {
        Write-Failure "docker compose up failed - see the output above."
        exit 1
    }
} finally {
    Pop-Location
}
Write-Success "Containers started"

Write-Step "Waiting for the backend to report healthy (up to 2 minutes)"
$backendPort = if ($env:BACKEND_PORT) { $env:BACKEND_PORT } else { "8000" }
$healthUrl = "http://localhost:$backendPort/health"
$healthy = $false
for ($i = 0; $i -lt 24; $i++) {
    try {
        $response = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 5 -ErrorAction Stop
        if ($response.status -eq "healthy") {
            $healthy = $true
            break
        }
    } catch {
        # Not up yet - keep polling.
    }
    Start-Sleep -Seconds 5
}

if (-not $healthy) {
    Write-Failure "Backend did not report healthy within 2 minutes. Check logs: docker compose logs backend"
    exit 1
}
Write-Success "Backend is healthy at $healthUrl"

Write-Host ""
Write-Host "SafeSOC is running." -ForegroundColor Green
Write-Host "  API:        http://localhost:$backendPort"
Write-Host "  API docs:   http://localhost:$backendPort/docs"
Write-Host ""
Write-Host "Next step - provision a demo tenant with realistic data:"
Write-Host "  python injector/demo.py"
Write-Host ""
Write-Host "Then run the frontend dashboard separately:"
Write-Host "  cd frontend; npm install; npm run dev"
