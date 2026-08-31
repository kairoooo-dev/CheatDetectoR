<#
.SYNOPSIS
    Minecraft Cheat Detector v6.0
.DESCRIPTION
    Detects known cheat clients by scanning filenames, JAR contents, and class paths.
.EXAMPLE
    .\startScan.ps1
    .\startScan.ps1 -DeepScan
#>

param(
    [switch]$DeepScan,
    [switch]$ExportReport
)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$dbPath = Join-Path $scriptPath "cheats-db.json"

Add-Type -AssemblyName System.IO.Compression

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "    Minecraft Cheat Detector v6.0" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$db = Get-Content $dbPath -Raw | ConvertFrom-Json
Write-Host "[*] Loaded $($db.cheatClients.Count) cheat signatures" -ForegroundColor Green

$findings = [System.Collections.Generic.List[PSObject]]::new()
$scannedJars = @{}

function Add-Finding {
    param($File, $Client, $Severity, $Match)
    foreach ($f in $findings) {
        if ($f.File -eq $File -and $f.Client -eq $Client -and $f.Match -eq $Match) { return }
    }
    $findings.Add([PSCustomObject]@{ File=$File; Client=$Client; Severity=$Severity; Match=$Match })
    Write-Host "    [!] FOUND: $Client ($Severity) - $Match" -ForegroundColor Red
}

function Scan-JarContents {
    param([string]$JarPath)

    if ($scannedJars.ContainsKey($JarPath)) { return }
    $scannedJars[$JarPath] = $true

    $jarFileName = [System.IO.Path]::GetFileNameWithoutExtension($JarPath).ToLower()

    foreach ($sig in $db.cheatJarSignatures) {
        if ($jarFileName -like "*$($sig.ToLower())*") {
            Add-Finding -File $JarPath -Client $sig -Severity "high" -Match "JAR filename: $([System.IO.Path]::GetFileName($JarPath))"
            return
        }
    }

    $stream = $null
    $archive = $null
    try {
        $stream = [System.IO.File]::OpenRead($JarPath)
        $archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Read)

        $foundCheat = $false

        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            $nameLower = $name.ToLower()

            if ($nameLower -match "^net/minecraft/") { continue }
            if ($nameLower -match "^assets/minecraft/") { continue }
            if ($nameLower -match "^data/minecraft/") { continue }
            if ($nameLower -match "^org/apache/") { continue }
            if ($nameLower -match "^com/google/") { continue }
            if ($nameLower -match "^META-INF/") { continue }

            foreach ($client in $db.cheatClients) {
                foreach ($pattern in $client.patterns) {
                    $p = $pattern.ToLower()
                    if ($nameLower -match "/$([regex]::Escape($p))" -or $nameLower -match "^$([regex]::Escape($p))") {
                        Add-Finding -File $JarPath -Client $client.Name -Severity $client.Severity -Match "JAR entry: $name"
                        $foundCheat = $true
                        break
                    }
                }
                if ($foundCheat) { break }
            }
            if ($foundCheat) { break }

            if ($entry.Extension -eq ".class") {
                $className = [System.IO.Path]::GetFileNameWithoutExtension($name).ToLower()
                $dirPath = ($name -replace "/[^/]+$", "").ToLower()

                if ($dirPath -match "^net/minecraft") { continue }

                foreach ($cp in $db.cheatClassPatterns) {
                    $cl = $cp.ToLower()
                    if ($className -like "*$cl*") {
                        Add-Finding -File $JarPath -Client "Cheat module" -Severity "high" -Match "JAR class: $name"
                        $foundCheat = $true
                        break
                    }
                }
                if ($foundCheat) { break }
            }
        }
    } catch {}
    finally {
        try { if ($archive) { $archive.Dispose() } } catch {}
        try { if ($stream) { $stream.Close() } } catch {}
    }
}

function Scan-File {
    param([string]$FilePath)

    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath).ToLower()
    $fullLower = $FilePath.ToLower()
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()

    foreach ($client in $db.cheatClients) {
        foreach ($pattern in $client.patterns) {
            $p = $pattern.ToLower()
            if ($fileName -like "*$p*") {
                Add-Finding -File $FilePath -Client $client.Name -Severity $client.Severity -Match "Filename: $([System.IO.Path]::GetFileName($FilePath))"
                return
            }
        }
    }

    foreach ($sp in $db.suspiciousPaths) {
        if ($fullLower -match "[\\/]$([regex]::Escape($sp))[\\/]") {
            Add-Finding -File $FilePath -Client "Suspicious folder" -Severity "medium" -Match "Path: $FilePath"
            return
        }
    }

    if ($ext -in $db.cheatExtensions) {
        Add-Finding -File $FilePath -Client "Suspicious extension" -Severity "high" -Match "Extension: $ext"
        return
    }

    if ($ext -eq ".jar") {
        Scan-JarContents -JarPath $FilePath
    }
}

function Scan-Directory {
    param([string]$Path, [string]$Label, [switch]$JarOnly)

    if (-not (Test-Path $Path)) { return }

    Write-Host "[+] $Label : $Path" -ForegroundColor Green

    if ($JarOnly) {
        $files = Get-ChildItem -Path $Path -Recurse -File -Filter "*.jar" -ErrorAction SilentlyContinue
    } else {
        $files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue
    }
    $total = $files.Count
    $i = 0

    foreach ($file in $files) {
        $i++
        if ($i % 2000 -eq 0) {
            Write-Host "    [$i / $total]" -ForegroundColor DarkGray
        }
        Scan-File -FilePath $file.FullName
    }

    Write-Host "    Done: $total files" -ForegroundColor DarkGray
}

$startTime = Get-Date

$mcPaths = @(
    "$env:USERPROFILE\.minecraft",
    "$env:APPDATA\.minecraft",
    "$env:LOCALAPPDATA\Modrinth App",
    "$env:APPDATA\Modrinth",
    "$env:LOCALAPPDATA\CurseForge",
    "$env:LOCALAPPDATA\GDLauncher",
    "$env:LOCALAPPDATA\PolyMC",
    "$env:LOCALAPPDATA\PrismLauncher",
    "$env:LOCALAPPDATA\MultiMC",
    "$env:LOCALAPPDATA\ATLauncher",
    "$env:APPDATA\ATLauncher",
    "$env:LOCALAPPDATA\Babylon",
    "$env:LOCALAPPDATA\Badlion Client",
    "$env:LOCALAPPDATA\Lunar Client",
    "$env:LOCALAPPDATA\Feather",
    "$env:LOCALAPPDATA\Flarial",
    "$env:LOCALAPPDATA\SKlauncher",
    "$env:LOCALAPPDATA\SK-Genesis",
    "$env:LOCALAPPDATA\Astralith",
    "$env:LOCALAPPDATA\Legacy Launcher",
    "$env:LOCALAPPDATA\Crystal Launcher",
    "$env:LOCALAPPDATA\LabyMod",
    "$env:APPDATA\.babric",
    "$env:APPDATA\.versionmanager",
    "$env:USERPROFILE\SKlauncher",
    "$env:USERPROFILE\Astralith"
)

foreach ($p in $mcPaths) {
    Scan-Directory -Path $p -Label "Minecraft" -JarOnly
}

Scan-Directory -Path "$env:USERPROFILE\Downloads" -Label "Downloads" -JarOnly

if ($DeepScan) {
    Write-Host ""
    Write-Host "[*] Deep scan..." -ForegroundColor Yellow

    Scan-Directory -Path "$env:USERPROFILE\Downloads" -Label "Downloads"
    Scan-Directory -Path "$env:USERPROFILE\Desktop" -Label "Desktop"
    Scan-Directory -Path "$env:USERPROFILE\Documents" -Label "Documents"
}

$duration = (Get-Date) - $startTime

Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "            Scan  Finished" -ForegroundColor Green
    Write-Host "      Congrats you are clean gng w Guy" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
} else {
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "            Scan  Finished" -ForegroundColor Red
    Write-Host "          You Are  Cheating" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "    FOUND $($findings.Count) CHEAT(S):" -ForegroundColor Red
    Write-Host ""
    $grouped = $findings | Group-Object -Property Client
    foreach ($g in $grouped) {
        Write-Host "  [$($g.Count)x] $($g.Name)" -ForegroundColor Magenta
        foreach ($f in ($g.Group | Select-Object -First 5)) {
            Write-Host "       $($f.File)" -ForegroundColor Gray
            Write-Host "       -> $($f.Match)" -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
Write-Host "    Time: $($duration.TotalSeconds.ToString('F1'))s" -ForegroundColor White

if ($ExportReport -and $findings.Count -gt 0) {
    $reportFile = Join-Path $scriptPath ("scan-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".json")
    $findings | ConvertTo-Json -Depth 3 | Out-File $reportFile -Encoding UTF8
    Write-Host ""
    Write-Host "Report: $reportFile" -ForegroundColor Green
}

Write-Host ""
