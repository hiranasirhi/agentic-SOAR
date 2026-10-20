# ============================================
# PROTEGO Orchestrator - STOP
# ============================================

$ProjectDir = "D:\Protego_orchestrator"

Write-Host "[PROTEGO] Looking for orchestrator process..."

$processes = Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -eq "python.exe" -and
        $_.CommandLine -like "*-m orchestrator.main*"
    }

if (-not $processes) {
    Write-Host "[PROTEGO] Orchestrator process not found."
    exit 0
}

foreach ($process in $processes) {

    Write-Host "[PROTEGO] Stopping PID $($process.ProcessId)..."

    try {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
        Write-Host "[PROTEGO] PID $($process.ProcessId) stopped."
    }
    catch {
        Write-Host "[PROTEGO] Failed to stop PID $($process.ProcessId): $($_.Exception.Message)"
    }
}

Write-Host "[PROTEGO] Stop operation completed."