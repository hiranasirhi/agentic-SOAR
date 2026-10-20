# ============================================
# PROTEGO Orchestrator - START
# ============================================

$ProjectDir = "D:\Protego_orchestrator"
$Python = "$ProjectDir\venv\Scripts\python.exe"
$LogOut = "$ProjectDir\orchestrator.log"
$LogErr = "$ProjectDir\orchestrator_error.log"

Write-Host "[PROTEGO] Starting orchestrator..."

# Make sure we are in the project directory
Set-Location $ProjectDir

# Check that the virtual-environment Python exists
if (-not (Test-Path $Python)) {
    Write-Host "[PROTEGO] ERROR: Python executable not found:"
    Write-Host $Python
    exit 1
}

# Start the orchestrator in the background
Start-Process `
    -FilePath $Python `
    -ArgumentList "-m orchestrator.main" `
    -WorkingDirectory $ProjectDir `
    -RedirectStandardOutput $LogOut `
    -RedirectStandardError $LogErr

Write-Host "[PROTEGO] Orchestrator start command sent."