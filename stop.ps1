# stop.ps1 — clean shutdown

Write-Host "Stopping all containers..." -ForegroundColor Yellow
docker compose down
Write-Host "Done. Data preserved in redis-data and postgres-data volumes." -ForegroundColor Green