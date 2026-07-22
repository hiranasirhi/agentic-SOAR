# start.ps1 — run this every morning instead of docker compose up -d

Write-Host "Stopping any running containers..." -ForegroundColor Yellow
docker compose down

Write-Host "Cleaning Kafka state..." -ForegroundColor Yellow
docker compose rm -f zookeeper kafka kafka-init 2>$null

Write-Host "Starting infrastructure..." -ForegroundColor Green
docker compose up -d zookeeper

Write-Host "Waiting for Zookeeper to be healthy..." -ForegroundColor Yellow
Start-Sleep -Seconds 20

docker compose up -d kafka

Write-Host "Waiting for Kafka to be healthy (this takes ~45 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 45

Write-Host "Starting all services..." -ForegroundColor Green
docker compose up -d

Write-Host "Waiting for kafka-init to create topics..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

Write-Host "`nFinal status:" -ForegroundColor Green
docker compose ps

Write-Host "`nKafka topics:" -ForegroundColor Green
docker exec kafka kafka-topics --list --bootstrap-server kafka:29092

Write-Host "`nAll done. Pipeline is ready." -ForegroundColor Green