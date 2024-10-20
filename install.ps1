$ErrorActionPreference = "Stop"

Write-Host "**************************************"
Write-Host "*                                    *"
Write-Host "*         Installing safeup          *"
Write-Host "*                                    *"
Write-Host "**************************************"

$response = Invoke-WebRequest `
    -Uri "https://api.github.com/repos/maidsafe/safeup/releases/latest" `
    -UseBasicParsing
$json = $response | ConvertFrom-Json
$version = $json.tag_name.TrimStart('v')
Write-Host "Latest version of safeup is $version"
$asset = $json.assets | Where-Object { $_.name -match "safeup-$version-x86_64-pc-windows-msvc.zip" }
$downloadUrl = $asset.browser_download_url

$archivePath = Join-Path $env:TEMP "safeup.zip"
Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath

$autonomiPath = Join-Path $env:USERPROFILE "autonomi"
New-Item -ItemType Directory -Force -Path $autonomiPath
Expand-Archive -Path $archivePath -DestinationPath $autonomiPath -Force
Remove-Item $archivePath
$safeupExePath = Join-Path $autonomiPath "safeup.exe"

$currentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
if ($currentPath -notlike "*$autonomiPath*") {
    $newPath = $currentPath + ";" + $autonomiPath
    [Environment]::SetEnvironmentVariable("PATH", $newPath, [EnvironmentVariableTarget]::User)
    Write-Host "Added $autonomiPath to user PATH"
} else {
    Write-Host "Path $autonomiPath is already in user PATH"
}

Write-Host "You may need to start a new session for safeup to become available."
Write-Host "When safeup is available, please run 'safeup --help' to see how to install network components."