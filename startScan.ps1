<#
.SYNOPSIS
    Minecraft Cheat Detector v4.0
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
Write-Host "    Minecraft Cheat Detector v4.0" -ForegroundColor Cyan
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
    Write-Host "    [!] $Client ($Severity): $Match" -ForegroundColor Red
}

$skipPackages = @(
    "net/minecraft/",
    "org/apache/",
    "com/google/",
    "org/jetbrains/",
    "javax/",
    "java/",
    "org/spongepowered/",
    "org/eclipse/",
    "org/bukkit/",
    "com/mojang/",
    "org/slf4j/",
    "com/fasterxml/",
    "io/netty/",
    "org/yaml/",
    "org/json/",
    "com/velocitypowered/",
    "net/md_5/",
    "org/nightconfig/",
    "com/electronwill/",
    "com/typesafe/",
    "org/davidmoten/",
    "org/inarautomotive/",
    "com/sirsnaryo/",
    "com/earth2me/",
    "ac/grim/",
    "org/jd/",
    "com/github/retrooper/",
    "net/techboy/",
    "dev/sixseven/",
    "assets/dawn-loader/"
)

$cheatClasses = @(
    "killaura", "autoclicker", "velocity", "freecam", "jesus", "nuker",
    "aimassist", "fastplace", "noslow", "cheststealer", "nofall",
    "antiknockback", "fastbreak", "blink", "esp", "tracers", "fullbright",
    "bhop", "noclip", "phase", "crash", "disabler", "hitboxes", "aura",
    "enderman", "antivoid", "instantkill", "autotool", "autoeat",
    "elytrafly", "scaffold", "bridge", "bowaim", "aimbot", "xray",
    "killAura", "autoClicker", "noFall", "noSlow", "chestStealer",
    "autoSprint", "autoJump", "step", "speed", "fly", "flight",
    "reach", "hitBox", "autoArmor", "autoTotem", "autoEat"
)

function Scan-JarContents {
    param([string]$JarPath)

    if ($scannedJars.ContainsKey($JarPath)) { return }
    $scannedJars[$JarPath] = $true

    $stream = $null
    $archive = $null
    try {
        $stream = [System.IO.File]::OpenRead($JarPath)
        $archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Read)

        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            $nameLower = $name.ToLower()

            $skip = $false
            foreach ($sp in $skipPackages) {
                if ($nameLower -match "^$([regex]::Escape($sp))") { $skip = $true; break }
            }
            if ($skip) { continue }

            if ($entry.Extension -eq ".class") {
                $className = [System.IO.Path]::GetFileNameWithoutExtension($name).ToLower()
                $dirPath = $name.ToLower() -replace "/[^/]+$", ""

                foreach ($cp in $cheatClasses) {
                    $cl = $cp.ToLower()
                    if ($className -eq $cl -or $className -like "*$cl*" ) {
                        if ($dirPath -notmatch "^net/minecraft" -and $dirPath -notmatch "^org/apache" -and $dirPath -notmatch "^com/google") {
                            Add-Finding -File $JarPath -Client "Cheat class" -Severity "high" -Match "JAR class: $name"
                        }
                    }
                }
            }

            foreach ($client in $db.cheatClients) {
                foreach ($pattern in $client.patterns) {
                    $p = $pattern.ToLower()
                    if ($nameLower -match "/$([regex]::Escape($p))" -or $nameLower -match "^$([regex]::Escape($p))") {
                        $skipClient = $false
                        foreach ($sp in $skipPackages) {
                            if ($nameLower -match "^$([regex]::Escape($sp))") { $skipClient = $true; break }
                        }
                        if (-not $skipClient) {
                            Add-Finding -File $JarPath -Client $client.Name -Severity $client.Severity -Match "JAR: $name"
                        }
                    }
                }
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
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()

    foreach ($client in $db.cheatClients) {
        foreach ($pattern in $client.patterns) {
            $p = $pattern.ToLower()
            if ($fileName -eq $p -or $fileName -eq "$p-mod" -or $fileName -eq "$p-client") {
                Add-Finding -File $FilePath -Client $client.Name -Severity $client.Severity -Match "Filename: $([System.IO.Path]::GetFileName($FilePath))"
                return
            }
        }
    }

    if ($ext -in $db.cheatExtensions) {
        Add-Finding -File $FilePath -Client "Suspicious extension" -Severity "medium" -Match "Extension: $ext"
    }

    if ($ext -eq ".jar") {
        Scan-JarContents -JarPath $FilePath
    }
}

function Scan-Directory {
    param([string]$Path, [string]$Label)

    if (-not (Test-Path $Path)) { return }

    Write-Host "[+] $Label : $Path" -ForegroundColor Green

    $files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue
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

Scan-Directory -Path "$env:USERPROFILE\.minecraft" -Label "Minecraft"
Scan-Directory -Path "$env:APPDATA\.minecraft" -Label "Minecraft (Roaming)"

if ($DeepScan) {
    Write-Host ""
    Write-Host "[*] Deep scan..." -ForegroundColor Yellow
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
            Write-Host "       -> $($f.Match)" -ForegroundColor DarkGray
        }
    }
}

if ($ExportReport -and $findings.Count -gt 0) {
    $reportFile = Join-Path $scriptPath ("scan-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".json")
    $findings | ConvertTo-Json -Depth 3 | Out-File $reportFile -Encoding UTF8
    Write-Host ""
    Write-Host "Report: $reportFile" -ForegroundColor Green
}

Write-Host ""
