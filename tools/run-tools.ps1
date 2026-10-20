# tools/run-tools.ps1 — run manually when doing an evaluation pass or one-time setup.
# NOT part of daily startup (see start.ps1 for that).

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("es-init", "baseline-up", "baseline-down", "evaluate-full", "evaluate-baseline", "metrics", "self-healing")]
    [string]$Task
)

Set-Location $PSScriptRoot\..   # run from project root so compose file paths resolve

switch ($Task) {
    "es-init" {
        Write-Host "Applying Elasticsearch ILM policies..." -ForegroundColor Green
        docker compose --profile tools run --rm es-init
    }
    "baseline-up" {
        Write-Host "Starting baseline-dispatcher for evaluation..." -ForegroundColor Green
        docker compose --profile tools up -d baseline-dispatcher
    }
    "baseline-down" {
        Write-Host "Stopping baseline-dispatcher..." -ForegroundColor Yellow
        docker compose --profile tools stop baseline-dispatcher
        docker compose --profile tools rm -f baseline-dispatcher
    }
    "evaluate-full" {
        Write-Host "Running evaluation — FULL SYSTEM mode..." -ForegroundColor Green
        docker compose --profile tools run --rm evaluation python run_evaluation.py --mode full
    }
    "evaluate-baseline" {
        Write-Host "Running evaluation — BASELINE mode..." -ForegroundColor Green
        Write-Host "(make sure baseline-dispatcher is up and orchestrator is pointed at it first)" -ForegroundColor Yellow
        docker compose --profile tools run --rm evaluation python run_evaluation.py --mode baseline
    }
    "metrics" {
        Write-Host "Computing Precision/Recall/F1..." -ForegroundColor Green
        docker compose --profile tools run --rm evaluation python compute_metrics.py
    }
    "self-healing" {
        Write-Host "Running self-healing recovery measurement..." -ForegroundColor Green
        docker compose --profile tools run --rm evaluation python measure_self_healing.py
    }
}

Write-Host "`nDone." -ForegroundColor Green



# # one-time, whenever ES policies need (re)applying:
# .\tools\run-tools.ps1 -Task es-init

# # full-system pass:
# .\tools\run-tools.ps1 -Task evaluate-full

# # baseline pass — this is the one with a real sequencing dependency:
# .\tools\run-tools.ps1 -Task baseline-up
# # ...manually confirm/redirect orchestrator traffic to baseline-dispatcher here...
# .\tools\run-tools.ps1 -Task evaluate-baseline
# .\tools\run-tools.ps1 -Task baseline-down

# # after both passes:
# .\tools\run-tools.ps1 -Task metrics
# .\tools\run-tools.ps1 -Task self-healing