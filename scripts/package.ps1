param([switch]$Offline)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $projectRoot
$cargoArgs = @('build', '--locked', '--release', '-j', '2')
if ($Offline) { $cargoArgs += '--offline' }
& cargo @cargoArgs
if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
$hostLine = (& rustc -vV | Select-String '^host: ').ToString()
if ($LASTEXITCODE -ne 0 -or !$hostLine) { throw 'Cannot determine the Rust host.' }
$hostTarget = $hostLine.Substring(6).Trim()
$metadataArgs = @('metadata', '--format-version', '1', '--locked', '--filter-platform', $hostTarget)
if ($Offline) { $metadataArgs += '--offline' }
$metadata = (& cargo @metadataArgs | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Dependency inventory failed.' }
$package = $metadata.packages | Where-Object { $_.name -eq 'sleep-diagnostics' }
$outputDirectory = Join-Path $projectRoot 'dist'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
$assetName = "SleepDiagnostics-v$($package.version).exe"
$assetPath = Join-Path $outputDirectory $assetName
Copy-Item -LiteralPath (Join-Path $projectRoot 'target\release\sleep-diagnostics.exe') -Destination $assetPath -Force
& python (Join-Path $projectRoot 'scripts\verify_artifact.py') $assetPath
if ($LASTEXITCODE -ne 0) { throw 'Packaged resource verification failed.' }
$checksum = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$assetPath.sha256", "$checksum  $assetName`n", [Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination (Join-Path $outputDirectory 'LICENSE') -Force
$attributions = [Collections.Generic.List[string]]::new()
foreach ($dependency in $metadata.packages | Where-Object { $_.source }) {
    $dependencyRoot = Split-Path -Parent $dependency.manifest_path
    $licenseFiles = @(Get-ChildItem -LiteralPath $dependencyRoot -File | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE)([.\-_]|$)' })
    if ($dependency.license_file) {
        $declared = Join-Path $dependencyRoot $dependency.license_file
        if (Test-Path -LiteralPath $declared) { $licenseFiles += Get-Item -LiteralPath $declared }
    }
    $destination = Join-Path $outputDirectory "licenses\$($dependency.name)-$($dependency.version)"
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    foreach ($licenseFile in $licenseFiles | Sort-Object FullName -Unique) {
        Copy-Item -LiteralPath $licenseFile.FullName -Destination (Join-Path $destination $licenseFile.Name) -Force
    }
    if ($licenseFiles.Count -eq 0) { throw "No license file found for $($dependency.name)." }
    $attributions.Add("$($dependency.name) $($dependency.version) | $($dependency.license)")
}
[IO.File]::WriteAllLines((Join-Path $outputDirectory 'THIRD-PARTY-LICENSES.txt'), $attributions, [Text.UTF8Encoding]::new($false))
Write-Output "Prepared $assetName and its SHA-256 checksum. No application was launched."
