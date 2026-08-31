<#
.SYNOPSIS
    Minecraft Cheat Detector
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
Write-Host "    Minecraft Cheat Detector v2.0" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$db = Get-Content $dbPath -Raw | ConvertFrom-Json
Write-Host "[*] Loaded $($db.cheatClients.Count) cheat signatures" -ForegroundColor Green

$findings = @()

function Write-Finding {
    param($File, $Client, $Severity, $Match)
    $script:findings += [PSCustomObject]@{
        File     = $File
        Client   = $Client
        Severity = $Severity
        Match    = $Match
    }
    Write-Host "    [!] FOUND: $Client ($Severity) - $Match" -ForegroundColor Red
}

function Scan-JarContents {
    param([string]$JarPath)

    try {
        $stream = [System.IO.File]::OpenRead($JarPath)
        $archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Read)

        $cheatPatterns = @(
            "hack", "cheat", "exploit", "killaura", "xray", "autoclicker",
            "velocity", "freecam", "jesus", "nuker", "aimassist", "fastplace",
            "noslow", "cheststealer", "nofall", "antiknockback", "fastbreak",
            "blink", "esp", "tracers", "fullbright", "bhop", "sprint",
            "flight", "fly", "noclip", "speed", "slow", "phase",
            "crash", "disabler", "timer", "reach", "hitboxes",
            "aura", "enderman", "antivoid", "target", "targetselector",
            "instantkill", "autotool", "autoeat", "totem", "elytrafly",
            "step", "scaffold", "bridge", "bowaim", "aimbot"
        )

        $skipPaths = @(
            "assets/minecraft/textures/",
            "assets/minecraft/models/",
            "assets/minecraft/sounds/",
            "assets/minecraft/lang/",
            "assets/minecraft/particles/",
            "assets/minecraft/shaders/",
            "data/minecraft/loot_table/",
            "data/minecraft/recipe/",
            "data/minecraft/advancement/",
            "META-INF/"
        )

        $clientNames = $db.cheatClients | ForEach-Object { $_.patterns[0] }

        foreach ($entry in $archive.Entries) {
            $entryName = $entry.FullName

            $skip = $false
            foreach ($sp in $skipPaths) {
                if ($entryName -like "$sp*") { $skip = $true; break }
            }
            if ($skip) { continue }

            if ($entry.Extension -eq ".class") {
                $classPath = $entryName -replace "\.class$", ""
                $classPathLower = $classPath.ToLower()

                foreach ($client in $db.cheatClients) {
                    foreach ($pattern in $client.patterns) {
                        $p = $pattern.ToLower()
                        if ($classPathLower -match "/$p/" -or $classPathLower -match "\.$p\." -or $classPathLower -match "/$p\.class$") {
                            Write-Finding -File $JarPath -Client $client.Name -Severity $client.Severity -Match "JAR class: $entryName"
                        }
                    }
                }

                foreach ($cp in $cheatPatterns) {
                    if ($classPathLower -match "/$cp/" -or $classPathLower -match "\.$cp\." -or $classPathLower -match "/$cp\.class$") {
                        $alreadyFound = $false
                        foreach ($f in $script:findings) {
                            if ($f.File -eq $JarPath -and $f.Match -eq "JAR class: $entryName") {
                                $alreadyFound = $true; break
                            }
                        }
                        if (-not $alreadyFound) {
                            Write-Finding -File $JarPath -Client "Suspicious class" -Severity "medium" -Match "JAR class: $entryName"
                        }
                    }
                }
            }

            if ($entry.Extension -in @(".json", ".cfg", ".properties") -and $entryName -notlike "data/minecraft/*" -and $entryName -notlike "assets/minecraft/*") {
                try {
                    $reader = New-Object System.IO.StreamReader($entry.Open())
                    $content = $reader.ReadToEnd()
                    $reader.Close()

                    foreach ($client in $db.cheatClients) {
                        foreach ($pattern in $client.patterns) {
                            if ($content -match "(?i)`"$([regex]::Escape($pattern))`"") {
                                $alreadyFound = $false
                                foreach ($f in $script:findings) {
                                    if ($f.File -eq $JarPath -and $f.Client -eq $client.Name) {
                                        $alreadyFound = $true; break
                                    }
                                }
                                if (-not $alreadyFound) {
                                    Write-Finding -File $JarPath -Client $client.Name -Severity $client.Severity -Match "JAR config: $entryName"
                                }
                            }
                        }
                    }
                } catch {}
            }
        }

        $archive.Dispose()
        $stream.Close()
    } catch {
        try { if ($archive) { $archive.Dispose() } } catch {}
        try { if ($stream) { $stream.Close() } } catch {}
    }
}

function Scan-File {
    param([string]$FilePath)

    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath).ToLower()
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()

    foreach ($client in $db.cheatClients) {
        foreach ($pattern in $client.patterns) {
            if ($fileName -match "(?i)$([regex]::Escape($pattern))") {
                Write-Finding -File $FilePath -Client $client.Name -Severity $client.Severity -Match "Filename match"
                return
            }
        }
    }

    if ($ext -in $db.cheatExtensions) {
        Write-Finding -File $FilePath -Client "Suspicious Extension" -Severity "medium" -Match "File extension: $ext"
    }

    if ($ext -eq ".jar") {
        Scan-JarContents -JarPath $FilePath
    }
}

function Scan-Directory {
    param([string]$Path, [string]$Label)

    if (-not (Test-Path $Path)) { return }

    Write-Host "[+] Scanning: $Label ($Path)" -ForegroundColor Green

    $files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue
    $total = $files.Count
    $i = 0

    foreach ($file in $files) {
        $i++
        if ($i % 500 -eq 0) {
            Write-Host "    [$i / $total] files..." -ForegroundColor DarkGray
        }
        Scan-File -FilePath $file.FullName
    }

    Write-Host "    Done: $total files" -ForegroundColor DarkGray
}

$startTime = Get-Date

$scanPaths = @(
    "$env:USERPROFILE\.minecraft",
    "$env:APPDATA\.minecraft"
)

foreach ($p in $scanPaths) {
    Scan-Directory -Path $p -Label "Minecraft"
}

if ($DeepScan) {
    Write-Host ""
    Write-Host "[*] Deep scan enabled - checking Downloads, Desktop, Documents..." -ForegroundColor Yellow

    Scan-Directory -Path "$env:USERPROFILE\Downloads" -Label "Downloads"
    Scan-Directory -Path "$env:USERPROFILE\Desktop" -Label "Desktop"
    Scan-Directory -Path "$env:USERPROFILE\Documents" -Label "Documents"
}

$duration = (Get-Date) - $startTime

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "    SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "    Time: $($duration.TotalSeconds.ToString('F1'))s" -ForegroundColor White
Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "    CLEAN - No cheats detected!" -ForegroundColor Green
} else {
    Write-Host "    FOUND $($findings.Count) CHEAT(S):" -ForegroundColor Red
    Write-Host ""

    $grouped = $findings | Group-Object -Property Client
    foreach ($g in $grouped) {
        Write-Host "  [$($g.Count)x] $($g.Name)" -ForegroundColor Magenta
        foreach ($f in ($g.Group | Select-Object -First 3)) {
            Write-Host "       $($f.File)" -ForegroundColor Gray
        }
    }
}

if ($ExportReport -and $findings.Count -gt 0) {
    $reportFile = Join-Path $scriptPath ("scan-report-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".json")
    $findings | ConvertTo-Json -Depth 3 | Out-File $reportFile -Encoding UTF8
    Write-Host ""
    Write-Host "Report saved: $reportFile" -ForegroundColor Green
}

Write-Host ""
