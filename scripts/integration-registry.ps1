[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempDir = Join-Path $tempRoot ("qcap-registry-integration-" + [guid]::NewGuid().ToString("N"))
$storeDir = Join-Path $tempDir "store"
$payloadDir = Join-Path $tempDir "payload"
$registryBinary = Join-Path $tempDir "qcap-registry.exe"
$stdoutLog = Join-Path $tempDir "registry.stdout.log"
$stderrLog = Join-Path $tempDir "registry.stderr.log"
$registryProcess = $null

try {
    New-Item -ItemType Directory -Path $storeDir, $payloadDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $payloadDir "data.txt") -Value "registry integration" -NoNewline
    $seedPath = Join-Path $tempDir "seed.hex"
    Set-Content -LiteralPath $seedPath -Value "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" -NoNewline

    Push-Location $repoRoot
    try {
        cargo build -p qcap-cli
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    }
    finally {
        Pop-Location
    }

    Push-Location (Join-Path $repoRoot "services/qcap-registry")
    try {
        go build -o $registryBinary .
        if ($LASTEXITCODE -ne 0) { throw "registry build failed" }
    }
    finally {
        Pop-Location
    }

    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    $baseUrl = "http://127.0.0.1:$port"

    $previousStore = $env:QCAP_REGISTRY_STORE
    $previousIndex = $env:QCAP_REGISTRY_INDEX
    $previousToken = $env:QCAP_REGISTRY_TOKEN
    $previousAddr = $env:QCAP_REGISTRY_ADDR
    $env:QCAP_REGISTRY_STORE = $storeDir
    $env:QCAP_REGISTRY_INDEX = Join-Path $storeDir "index.json"
    $env:QCAP_REGISTRY_TOKEN = "integration-token"
    $env:QCAP_REGISTRY_ADDR = "127.0.0.1:$port"
    try {
        $registryProcess = Start-Process -FilePath $registryBinary -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog
    }
    finally {
        $env:QCAP_REGISTRY_STORE = $previousStore
        $env:QCAP_REGISTRY_INDEX = $previousIndex
        $env:QCAP_REGISTRY_TOKEN = $previousToken
        $env:QCAP_REGISTRY_ADDR = $previousAddr
    }

    $ready = $false
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        if ($registryProcess.HasExited) {
            throw "registry exited before becoming healthy: $(Get-Content -LiteralPath $stderrLog -Raw)"
        }
        try {
            $health = Invoke-RestMethod -Uri "$baseUrl/health" -TimeoutSec 1
            if ($health.status -eq "ok") {
                $ready = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $ready) {
        throw "registry did not become healthy: $(Get-Content -LiteralPath $stderrLog -Raw)"
    }

    $cli = Join-Path $repoRoot "target/debug/qcap-cli.exe"
    $artifact = Join-Path $tempDir "integration.qcap"
    $fetchedArtifact = Join-Path $tempDir "fetched.qcap"

    & $cli pack $payloadDir --out $artifact --key $seedPath
    if ($LASTEXITCODE -ne 0) { throw "qcap pack failed" }
    & $cli publish $artifact --registry $baseUrl --token "integration-token"
    if ($LASTEXITCODE -ne 0) { throw "artifact publish failed" }
    & $cli fetch "integration.qcap" --out $fetchedArtifact --registry $baseUrl
    if ($LASTEXITCODE -ne 0) { throw "artifact fetch failed" }
    if ((Get-FileHash -Algorithm SHA256 $artifact).Hash -ne (Get-FileHash -Algorithm SHA256 $fetchedArtifact).Hash) {
        throw "fetched artifact differs from published artifact"
    }

    $issuer = Join-Path $tempDir "issuer.identity.json"
    $recipient = Join-Path $tempDir "recipient.identity.json"
    $sealed = Join-Path $tempDir "sealed.qcap"
    $capability = Join-Path $tempDir "capability.json"
    $revocations = Join-Path $tempDir "revocations.json"
    $fetchedRevocations = Join-Path $tempDir "fetched-revocations.json"

    & $cli init --name issuer --out $issuer
    if ($LASTEXITCODE -ne 0) { throw "issuer init failed" }
    & $cli init --name recipient --out $recipient
    if ($LASTEXITCODE -ne 0) { throw "recipient init failed" }
    $recipientIdentity = Get-Content -LiteralPath $recipient -Raw | ConvertFrom-Json
    $audience = $recipientIdentity.signing_public_key.Substring(0, 16)
    & $cli seal $payloadDir --issuer $issuer --recipient $recipient --out $sealed
    if ($LASTEXITCODE -ne 0) { throw "qcap seal failed" }
    & $cli grant $sealed --issuer $issuer --audience $audience --out $capability
    if ($LASTEXITCODE -ne 0) { throw "capability grant failed" }
    & $cli revoke --cap $capability --issuer $issuer --out $revocations --reason "integration-test"
    if ($LASTEXITCODE -ne 0) { throw "capability revoke failed" }
    $revocationList = Get-Content -LiteralPath $revocations -Raw | ConvertFrom-Json
    & $cli publish-revocations $revocations --registry $baseUrl --token "integration-token"
    if ($LASTEXITCODE -ne 0) { throw "revocation publish failed" }
    & $cli fetch-revocations $revocationList.public_key --out $fetchedRevocations --registry $baseUrl
    if ($LASTEXITCODE -ne 0) { throw "revocation fetch failed" }
    if ((Get-FileHash -Algorithm SHA256 $revocations).Hash -ne (Get-FileHash -Algorithm SHA256 $fetchedRevocations).Hash) {
        throw "fetched revocations differ from published revocations"
    }

    Write-Host "Registry integration: OK"
}
finally {
    if ($null -ne $registryProcess -and -not $registryProcess.HasExited) {
        Stop-Process -Id $registryProcess.Id -Force
        $registryProcess.WaitForExit()
    }
    $resolvedTemp = [IO.Path]::GetFullPath($tempDir)
    if ($resolvedTemp.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTemp)) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}
