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
$asset = $json.assets | Where-Object { $_.name -match "safeup-$version-x86_64-pc-windows-msvc.tar.gz" }
$downloadUrl = $asset.browser_download_url

$archivePath = Join-Path $env:TEMP "safeup.tar.gz"
Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath

$destination = Join-Path $env:USERPROFILE "safe"
New-Item -ItemType Directory -Force -Path $destination
tar -xf $archivePath -C $destination
Remove-Item $archivePath
$safeupExePath = Join-Path $destination "safeup.exe"

Write-Host "You may need to start a new session for safeup to become available."
Write-Host "When safeup is available, please run 'safeup --help' to see how to install network components."
