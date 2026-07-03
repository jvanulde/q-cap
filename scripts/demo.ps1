$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Work = Join-Path $Root "target\qcap-demo"
$RegistryDir = Join-Path $Work "registry"
$Payload = Join-Path $Work "payload"
$Exported = Join-Path $Work "exported"
$RevokedExported = Join-Path $Work "revoked-exported"
$Fetched = Join-Path $Work "fetched.qcap"
$DemoQcap = Join-Path $Work "demo.qcap"
$Cap = Join-Path $Work "cap.json"
$Revocations = Join-Path $Work "revocations.json"
$Issuer = Join-Path $Work "issuer.identity.json"
$Recipient = Join-Path $Work "recipient.identity.json"
$GeoPackage = Join-Path $Payload "reports\observations.gpkg"
$RegistryOut = Join-Path $Work "registry.out.log"
$RegistryErr = Join-Path $Work "registry.err.log"
$RegistryExe = Join-Path $Work "qcap-registry.exe"
$QcapExe = Join-Path $Root "target\debug\qcap-cli.exe"
$CargoExe = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$GoExe = "C:\Program Files\Go\bin\go.exe"

function Step($Message) {
  Write-Host "==> $Message"
}

function Run($FilePath, $Arguments) {
  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$FilePath failed with exit code $LASTEXITCODE"
  }
}

function RunExpectFailure($FilePath, $Arguments, $SuccessMessage) {
  $stdout = [System.IO.Path]::GetTempFileName()
  $stderr = [System.IO.Path]::GetTempFileName()
  $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  Remove-Item -Force $stdout, $stderr -ErrorAction SilentlyContinue
  if ($process.ExitCode -eq 0) {
    throw "$FilePath unexpectedly succeeded"
  }
  Write-Host $SuccessMessage
}

function StopPort($Port) {
  $connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
  foreach ($connection in $connections) {
    Stop-Process -Id $connection.OwningProcess -Force -ErrorAction SilentlyContinue
  }
}

StopPort 8080

if (Test-Path $Work) {
  Remove-Item -Recurse -Force $Work
}
New-Item -ItemType Directory -Force $Payload, $RegistryDir | Out-Null
New-Item -ItemType Directory -Force (Join-Path $Payload "reports"), (Join-Path $Payload "secrets") | Out-Null
Set-Content -NoNewline -Path (Join-Path $Payload "reports\summary.txt") -Value "Q-Cap MVP: this report is allowed."
Set-Content -NoNewline -Path (Join-Path $Payload "secrets\private.txt") -Value "This should stay blocked by the capability."

Push-Location $Root
$registryProcess = $null
try {
  Step "building Rust workspace"
  Run $CargoExe @("build", "--workspace", "--quiet")

  Step "creating issuer and recipient identities"
  Run $QcapExe @("init", "--name", "issuer", "--out", $Issuer)
  Run $QcapExe @("init", "--name", "recipient", "--out", $Recipient)
  $issuerIdentity = Get-Content -Raw $Issuer | ConvertFrom-Json
  $issuerRevocationsUrl = "http://127.0.0.1:8080/revocations/$($issuerIdentity.signing_public_key)/revocations.json"
  $recipientIdentity = Get-Content -Raw $Recipient | ConvertFrom-Json
  $recipientAudience = $recipientIdentity.signing_public_key.Substring(0, 16)

  Step "creating sample GeoPackage payload"
  Run $QcapExe @("sample-geopackage", "--out", $GeoPackage)

  Step "sealing encrypted .qcap"
  Run $QcapExe @("seal", $Payload, "--issuer", $Issuer, "--recipient", $Recipient, "--out", $DemoQcap)
  Run $QcapExe @("verify", $DemoQcap)
  Run $QcapExe @("inspect", $DemoQcap)

  Step "starting registry"
  Push-Location (Join-Path $Root "services\qcap-registry")
  try {
    Run $GoExe @("build", "-o", $RegistryExe, ".")
  } finally {
    Pop-Location
  }
  $env:QCAP_REGISTRY_SEED = $RegistryDir
  $env:QCAP_REGISTRY_TOKEN = "demo-token"
  $registryProcess = Start-Process -FilePath $RegistryExe -WorkingDirectory $Root -WindowStyle Hidden -RedirectStandardOutput $RegistryOut -RedirectStandardError $RegistryErr -PassThru
  Start-Sleep -Seconds 2

  Step "publishing and fetching artifact"
  Run $QcapExe @("publish", $DemoQcap, "--registry", "http://127.0.0.1:8080", "--token", "demo-token")
  Run $QcapExe @("fetch", "demo.qcap", "--out", $Fetched, "--registry", "http://127.0.0.1:8080")
  Run $QcapExe @("verify", $Fetched)

  Step "proving open fails without a capability"
  RunExpectFailure $QcapExe @("open", $Fetched, "--cap", (Join-Path $Work "missing-cap.json"), "--identity", $Recipient, "--out", $Exported) "OK blocked open without capability"

  Step "granting capability for reports/* only"
  Run $QcapExe @("grant", $Fetched, "--issuer", $Issuer, "--audience", $recipientAudience, "--path", "reports/*", "--expires", "unix-seconds:9999999999", "--out", $Cap)

  Step "opening with capability"
  Run $QcapExe @("open", $Fetched, "--cap", $Cap, "--identity", $Recipient, "--out", $Exported)
  if (!(Test-Path (Join-Path $Exported "reports\summary.txt"))) {
    throw "allowed report was not exported"
  }
  if (!(Test-Path (Join-Path $Exported "reports\observations.gpkg"))) {
    throw "sample GeoPackage was not exported"
  }
  $originalGeoPackageHash = (Get-FileHash -Algorithm SHA256 $GeoPackage).Hash
  $exportedGeoPackageHash = (Get-FileHash -Algorithm SHA256 (Join-Path $Exported "reports\observations.gpkg")).Hash
  if ($originalGeoPackageHash -ne $exportedGeoPackageHash) {
    throw "sample GeoPackage changed during seal/open"
  }
  if (Test-Path (Join-Path $Exported "secrets\private.txt")) {
    throw "restricted secret was exported"
  }

  Step "revoking capability and proving it is blocked"
  Run $QcapExe @("revoke", "--cap", $Cap, "--issuer", $Issuer, "--reason", "demo-complete", "--out", $Revocations)
  Run $QcapExe @("publish-revocations", $Revocations, "--registry", "http://127.0.0.1:8080", "--token", "demo-token")
  RunExpectFailure $QcapExe @("open", $Fetched, "--cap", $Cap, "--identity", $Recipient, "--revocations-url", $issuerRevocationsUrl, "--out", $RevokedExported) "OK blocked revoked capability"

  Step "MVP demo complete"
  Write-Host "Allowed output: $(Join-Path $Exported "reports\summary.txt")"
  Write-Host "GeoPackage output: $(Join-Path $Exported "reports\observations.gpkg")"
  Write-Host "Restricted output correctly absent: secrets\private.txt"
} finally {
  if ($registryProcess -and !$registryProcess.HasExited) {
    Stop-Process -Id $registryProcess.Id -Force
  }
  Pop-Location
}
