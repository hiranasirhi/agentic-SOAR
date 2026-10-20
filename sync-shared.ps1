# sync-shared.ps1 — run before building any service
$targets = @(
    "services/pipeline-monitor/shared",
    "tools/baseline-dispatcher/shared",
    "tools/evaluation/shared"
)
foreach ($t in $targets) {
    Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue
    Copy-Item -Recurse "shared" $t
}