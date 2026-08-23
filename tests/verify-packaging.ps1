param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [string]$ReducedExe,
    [string]$CompatibilityExe
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$branding = @{}
Get-Content -LiteralPath (Join-Path $root 'branding.properties') | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]*)=(.*)$') { $branding[$matches[1].Trim()] = $matches[2].Trim() }
}
$brand = $branding['brand.name']
$version = $branding['brand.version']
$compatJar = Join-Path $root "target\$brand-$version-double-click-me.jar"
$reducedJar = Join-Path $root "target\$brand-$version-double-click-me-reduced-av-heuristics.jar"
$downloaderJar = Join-Path $root 'target\toolscreen-downloader.jar'
$legacyMavenJar = Join-Path $root 'target\EasyInjectBundled-1.0.jar'
$legacyMavenDownloaderJar = Join-Path $root 'target\EasyInjectBundled-1.0-toolscreen-downloader.jar'

foreach ($requiredFile in @($compatJar, $reducedJar, $downloaderJar, $legacyMavenJar, $legacyMavenDownloaderJar)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) { throw "Missing packaging artifact: $requiredFile" }
}
$reducedJarOutputs = @(Get-ChildItem -LiteralPath (Join-Path $root 'target') -Filter '*-reduced-av-heuristics.jar' -File)
if ($reducedJarOutputs.Count -ne 1) { throw "Expected exactly one reduced JAR in target; found $($reducedJarOutputs.Count)" }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Read-ZipEntryBytes([string]$archivePath, [string]$entryName) {
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $entry = $archive.GetEntry($entryName)
        if ($null -eq $entry) { throw "Missing $entryName in $archivePath" }
        $stream = $entry.Open()
        try {
            $memory = New-Object IO.MemoryStream
            $stream.CopyTo($memory)
            return $memory.ToArray()
        } finally { $stream.Dispose() }
    } finally { $archive.Dispose() }
}

function Get-EasyInjectClassText([string]$archivePath) {
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $builder = New-Object Text.StringBuilder
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -like 'com/easyinject/*.class') {
                $stream = $entry.Open()
                try {
                    $memory = New-Object IO.MemoryStream
                    $stream.CopyTo($memory)
                    [void]$builder.Append([Text.Encoding]::ASCII.GetString($memory.ToArray()))
                } finally { $stream.Dispose() }
            }
        }
        return $builder.ToString()
    } finally { $archive.Dispose() }
}

$manifest = [Text.Encoding]::UTF8.GetString((Read-ZipEntryBytes $reducedJar 'META-INF/MANIFEST.MF'))
if ($manifest -notmatch 'Main-Class:\s+com\.easyinject\.Main') { throw 'Reduced JAR main class is incorrect' }
if ($manifest -notmatch 'EasyInject-Build-Variant:\s+reduced-av-heuristics') { throw 'Reduced JAR variant manifest entry is missing' }
$compatManifest = [Text.Encoding]::UTF8.GetString((Read-ZipEntryBytes $compatJar 'META-INF/MANIFEST.MF'))
if ($compatManifest -notmatch 'Main-Class:\s+com\.easyinject\.Main') { throw 'Compatibility JAR main class changed' }
$downloaderManifest = [Text.Encoding]::UTF8.GetString((Read-ZipEntryBytes $downloaderJar 'META-INF/MANIFEST.MF'))
if ($downloaderManifest -notmatch 'Main-Class:\s+com\.easyinject\.ToolscreenInstallerMain') { throw 'Downloader JAR main class changed' }

$archive = [IO.Compression.ZipFile]::OpenRead($reducedJar)
try {
    $entryNames = @($archive.Entries | ForEach-Object FullName)
} finally { $archive.Dispose() }
foreach ($resource in @('branding.properties', 'dlls/liblogger_x64.dll', 'fabric.mod.json')) {
    if ($entryNames -notcontains $resource) { throw "Reduced JAR is missing $resource" }
}
foreach ($configuredResource in Get-ChildItem -LiteralPath (Join-Path $root 'custom-dlls') -File) {
    if ($configuredResource.Extension -in @('.dll', '.json') -and $entryNames -notcontains ('dlls/' + $configuredResource.Name)) {
        throw "Reduced JAR is missing configured resource $($configuredResource.Name)"
    }
}
if (-not ($entryNames | Where-Object { $_ -like 'dlls/*.dll' -and $_ -ne 'dlls/liblogger_x64.dll' })) {
    throw 'Reduced JAR is missing configured custom DLLs'
}

$classText = Get-EasyInjectClassText $reducedJar
foreach ($forbidden in @('PROCESS_ALL_ACCESS', 'New-ItemProperty', 'Set-ItemProperty', 'ExecutionPolicy Bypass',
        'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths', 'defender-elevated-selfjar')) {
    if ($classText.Contains($forbidden)) { throw "Reduced EasyInject classes contain forbidden string: $forbidden" }
}
foreach ($required in @('Add-MpPreference', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'LoadLibraryW')) {
    if (-not $classText.Contains($required)) { throw "Reduced EasyInject classes are missing required behavior marker: $required" }
}
foreach ($compatibilityMarker in @('PreLaunchCommand', '--run-prelaunch-chain', '--watcher', 'Uninstall', 'app.db',
        'prismlauncher.exe', 'multimc.exe', 'ATLauncher')) {
    if (-not $classText.Contains($compatibilityMarker)) { throw "Reduced JAR is missing compatibility marker: $compatibilityMarker" }
}
foreach ($failureMarker in @('UAC prompt was cancelled', 'Continue installation without the exclusion', 'exclusion verification failed')) {
    if (-not $classText.Contains($failureMarker)) { throw "Reduced JAR is missing failure-path marker: $failureMarker" }
}

function Assert-ReducedExe([string]$reducedPath, [string]$compatibilityPath) {
    if (-not (Test-Path -LiteralPath $reducedPath -PathType Leaf)) { throw "Missing reduced EXE: $reducedPath" }
    if (-not (Test-Path -LiteralPath $compatibilityPath -PathType Leaf)) { throw "Missing compatibility EXE: $compatibilityPath" }
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $reducedPath))
    $ascii = [Text.Encoding]::ASCII.GetString($bytes)
    $unicode = [Text.Encoding]::Unicode.GetString($bytes)
    foreach ($forbidden in @('PROCESS_ALL_ACCESS', 'New-ItemProperty', 'Set-ItemProperty', 'ExecutionPolicy Bypass',
            'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths', 'defender-elevated-selfexe')) {
        if ($ascii.Contains($forbidden) -or $unicode.Contains($forbidden)) { throw "Reduced EXE contains forbidden string: $forbidden" }
    }
    foreach ($required in @('Add-MpPreference', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'LoadLibraryW', 'liblogger_x64.dll')) {
        if (-not ($ascii.Contains($required) -or $unicode.Contains($required))) { throw "Reduced EXE is missing required marker/resource: $required" }
    }
    $reducedInfo = (Get-Item -LiteralPath $reducedPath).VersionInfo
    $compatInfo = (Get-Item -LiteralPath $compatibilityPath).VersionInfo
    foreach ($property in @('CompanyName', 'ProductName', 'FileDescription', 'LegalCopyright')) {
        if ($reducedInfo.$property -ne $compatInfo.$property) { throw "EXE metadata differs for $property" }
    }
}

if ($ReducedExe -or $CompatibilityExe) {
    if (-not $ReducedExe -or -not $CompatibilityExe) { throw 'Pass both ReducedExe and CompatibilityExe' }
    Assert-ReducedExe $ReducedExe $CompatibilityExe
}

Write-Output "Packaging verification passed for $brand $version."
