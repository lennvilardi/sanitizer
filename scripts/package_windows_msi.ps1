param(
  [string]$AppVersion = $env:APP_VERSION,
  [string]$WixUiExtensionVersion = $env:WIX_UI_EXTENSION_VERSION
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($AppVersion)) {
  $AppVersion = "0.1.0"
}
$AppVersion = $AppVersion.TrimStart("v")
if ([string]::IsNullOrWhiteSpace($WixUiExtensionVersion)) {
  $WixUiExtensionVersion = "6.0.2"
}

$PackageVersion = $AppVersion
if ([string]::IsNullOrWhiteSpace($PackageVersion)) {
  $PackageVersion = "0.1.0"
}
$PackageVersion = $PackageVersion -replace '[^0-9A-Za-z._-]', '-'

$ProductVersion = "0.1.0"
if ($AppVersion -match '^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].*)?$') {
  $ProductVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
  if ($Matches[4]) {
    $ProductVersion = "$ProductVersion.$($Matches[4])"
  }
} else {
  Write-Host "INFO: APP_VERSION '$AppVersion' is not a valid MSI product version. Falling back to $ProductVersion"
}

$RootDir = (Resolve-Path "$PSScriptRoot\..").Path
$AppName = "ConfigSanitizer"
$DistDir = Join-Path $RootDir "dist"
$BuildDir = Join-Path $RootDir "build"
$ReleaseDir = Join-Path $RootDir "release"
$ExePath = Join-Path $DistDir "$AppName.exe"
$MsiPath = Join-Path $ReleaseDir "$AppName-$PackageVersion-windows-x64.msi"
$WxsPath = Join-Path $RootDir "packaging\windows\ConfigSanitizer.wxs"

if (Test-Path $DistDir) { Remove-Item -Path $DistDir -Recurse -Force }
if (Test-Path $BuildDir) { Remove-Item -Path $BuildDir -Recurse -Force }
if (Test-Path (Join-Path $RootDir "$AppName.spec")) { Remove-Item -Path (Join-Path $RootDir "$AppName.spec") -Force }
New-Item -ItemType Directory -Path $ReleaseDir -Force | Out-Null

python -m PyInstaller `
  --noconfirm `
  --clean `
  --name $AppName `
  --windowed `
  --onefile `
  (Join-Path $RootDir "sanitize_gui.py")

if (-not (Test-Path $ExePath)) {
  throw "Expected executable not found: $ExePath"
}

function Get-SignToolPath {
  $candidates = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
  if ($candidates.Count -gt 0) {
    return $candidates[0].FullName
  }
  return $null
}

function Sign-File([string]$FilePath) {
  if ([string]::IsNullOrWhiteSpace($env:WINDOWS_CERT_PFX_BASE64) -or [string]::IsNullOrWhiteSpace($env:WINDOWS_CERT_PASSWORD)) {
    Write-Host "INFO: Windows signing secrets missing, skipping signature for $FilePath"
    return
  }

  $signtool = Get-SignToolPath
  if ([string]::IsNullOrWhiteSpace($signtool)) {
    throw "signtool.exe not found on this runner."
  }

  $pfxPath = Join-Path $env:RUNNER_TEMP "codesign.pfx"
  [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:WINDOWS_CERT_PFX_BASE64))
  & $signtool sign /fd SHA256 /f $pfxPath /p $env:WINDOWS_CERT_PASSWORD /tr "http://timestamp.digicert.com" /td SHA256 $FilePath
}

Sign-File -FilePath $ExePath

# WiX (dotnet tool) builds MSI from the .wxs file.
$wixPath = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
if (-not (Test-Path $wixPath)) {
  throw "WiX CLI not found at $wixPath"
}

function Ensure-WixExtension([string]$ExtensionId, [string]$ExtensionVersion) {
  $extensionPackage = $ExtensionId
  if (-not [string]::IsNullOrWhiteSpace($ExtensionVersion)) {
    $extensionPackage = "$ExtensionId/$ExtensionVersion"
  }

  Write-Host "INFO: Installing WiX extension: $extensionPackage"
  & $wixPath extension add --global $extensionPackage
  if ($LASTEXITCODE -ne 0) {
    Write-Host "INFO: Retrying WiX extension install without --global"
    & $wixPath extension add $extensionPackage
  }
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to install WiX extension '$extensionPackage'."
  }
}

Ensure-WixExtension -ExtensionId "WixToolset.UI.wixext" -ExtensionVersion $WixUiExtensionVersion

& $wixPath build `
  $WxsPath `
  -dExecutablePath=$ExePath `
  -dProductVersion=$ProductVersion `
  -ext WixToolset.UI.wixext `
  -o $MsiPath

if (-not (Test-Path $MsiPath)) {
  throw "MSI output not found: $MsiPath"
}

Sign-File -FilePath $MsiPath

Write-Host "Built MSI: $MsiPath"
