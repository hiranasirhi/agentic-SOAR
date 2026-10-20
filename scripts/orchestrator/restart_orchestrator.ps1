# ============================================
# PROTEGO Orchestrator - RESTART
# ============================================

$ProjectDir = "D:\Protego_orchestrator"

Write-Host ""
Write-Host "============================================"
Write-Host "       PROTEGO ORCHESTRATOR RESTART"
Write-Host "============================================"
Write-Host ""

# --------------------------------------------
# STEP 1: Stop existing orchestrator
# --------------------------------------------

Write-Host "[1/3] Stopping orchestrator..."

& "$ProjectDir\stop_orchestrator.ps1"

# --------------------------------------------
# STEP 2: Wait for process to terminate
# --------------------------------------------

Write-Host "[2/3] Waiting 3 seconds..."

Start-Sleep -Seconds 3

# --------------------------------------------
# STEP 3: Start orchestrator
# --------------------------------------------

Write-Host "[3/3] Starting orchestrator..."

& "$ProjectDir\start_orchestrator.ps1"

Write-Host ""
Write-Host "[PROTEGO] Waiting for orchestrator startup..."
Start-Sleep -Seconds 5

Write-Host ""
Write-Host "[PROTEGO] Restart operation completed."
Write-Host ""