<#
.SYNOPSIS
    Minecraft Cheat Detector - Scans for known cheat clients and suspicious files.
.DESCRIPTION
    Scans local Minecraft directories for known cheat clients, suspicious mods,
    and potentially harmful modifications.
.EXAMPLE
    .\startScan.ps1
#>

param(
    [string]$ScanPath = "$env:USERPROFILE",
    [switch]$DeepScan,
    [switch]$ExportReport
)

$ErrorActionPreference = "SilentlyContinue"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$dbPath = Join-Path $scriptPath "cheats-db.json"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "    Minecraft Cheat Detector v1.0" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Load cheat database
if (Test-Path $dbPath) {
    $db = Get-Content $dbPath -Raw | ConvertFrom-Json
    Write-Host "[*] Loaded cheat database: $($db.cheatClients.Count) known clients" -ForegroundColor Green
} else {
    Write-Host "[!] Database not found at $dbPath" -ForegroundColor Red
    exit 1
}

# Define scan locations
$minecraftPaths = @(
    "$env:USERPROFILE\.minecraft",
    "$env:APPDATA\.minecraft",
    "$env:USERPROFILE\AppData\Roaming\.minecraft",
    "$env:USERPROFILE\mods",
    "$env:USERPROFILE\.versions"
)

Write-Host "[*] Starting scan..." -ForegroundColor Yellow
Write-Host "[*] Scan scope: $ScanPath" -ForegroundColor Yellow
Write-Host ""

$findings = @()
$filesScanned = 0
$startTime = Get-Date

# Function to check file content
function Test-FileForCheats {
    param([string]$FilePath)
    
    $results = @()
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath).ToLower()
    
    # Check filename against patterns
    foreach ($client in $db.cheatClients) {
        foreach ($pattern in $client.patterns) {
            if ($fileName -like "*$($pattern.ToLower())*") {
                $results += [PSCustomObject]@{
                    File = $FilePath
                    Client = $client.Name
                    Severity = $client.Severity
                    Match = "Filename"
                }
            }
        }
    }
    
    # Check file extensions
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    if ($ext -in $db.cheatExtensions) {
        $results += [PSCustomObject]@{
            File = $FilePath
            Client = "Unknown (Suspicious Extension)"
            Severity = "medium"
            Match = "Extension"
        }
    }
    
    # Check path for suspicious folders
    $dirName = Split-Path $FilePath -Leaf
    if ($dirName -in $db.suspiciousPaths) {
        $results += [PSCustomObject]@{
            File = $FilePath
            Client = "Suspicious Directory"
            Severity = "low"
            Match = "Path"
        }
    }
    
    return $results
}

# Scan each minecraft location
foreach ($mcPath in $minecraftPaths) {
    if (Test-Path $mcPath) {
        Write-Host "[+] Found Minecraft directory: $mcPath" -ForegroundColor Green
        
        $files = Get-ChildItem -Path $mcPath -Recurse -File -ErrorAction SilentlyContinue
        $totalFiles = $files.Count
        $current = 0
        
        foreach ($file in $files) {
            $current++
            $filesScanned++
            
            if ($current % 100 -eq 0) {
                Write-Host "    Scanning: $current / $totalFiles" -ForegroundColor DarkGray
            }
            
            $result = Test-FileForCheats -FilePath $file.FullName
            if ($result) {
                $findings += $result
            }
        }
        
        Write-Host "    Completed: $totalFiles files" -ForegroundColor DarkGray
    }
}

# Deep scan additional locations if requested
if ($DeepScan) {
    Write-Host ""
    Write-Host "[*] Running deep scan on additional directories..." -ForegroundColor Yellow
    
    $additionalPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        "$env:APPDATA",
        "$env:LOCALAPPDATA"
    )
    
    foreach ($path in $additionalPaths) {
        if (Test-Path $path) {
            Write-Host "[+] Scanning: $path" -ForegroundColor Green
            
            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
            $totalFiles = $files.Count
            $current = 0
            
            foreach ($file in $files) {
                $current++
                $filesScanned++
                
                if ($current % 100 -eq 0) {
                    Write-Host "    Scanning: $current / $totalFiles" -ForegroundColor DarkGray
                }
                
                $result = Test-FileForCheats -FilePath $file.FullName
                if ($result) {
                    $findings += $result
                }
            }
        }
    }
}

$endTime = Get-Date
$duration = $endTime - $startTime

# Display results
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "    SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files scanned: $filesScanned" -ForegroundColor White
Write-Host "Time taken: $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor White
Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "[OK] No cheats detected!" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "[!] Found $($findings.Count) potential cheats:" -ForegroundColor Red
    Write-Host ""
    
    $highSeverity = ($findings | Where-Object { $_.Severity -eq "high" }).Count
    $mediumSeverity = ($findings | Where-Object { $_.Severity -eq "medium" }).Count
    $lowSeverity = ($findings | Where-Object { $_.Severity -eq "low" }).Count
    
    if ($highSeverity -gt 0) { Write-Host "    HIGH:   $highSeverity" -ForegroundColor Red }
    if ($mediumSeverity -gt 0) { Write-Host "    MEDIUM: $mediumSeverity" -ForegroundColor Yellow }
    if ($lowSeverity -gt 0) { Write-Host "    LOW:    $lowSeverity" -ForegroundColor DarkYellow }
    Write-Host ""
    
    # Group by client
    $grouped = $findings | Group-Object -Property Client
    foreach ($group in $grouped) {
        Write-Host "--- $($group.Name) ---" -ForegroundColor Magenta
        foreach ($finding in $group.Group | Select-Object -First 3) {
            Write-Host "    File: $($finding.File)" -ForegroundColor Gray
            Write-Host "    Match: $($finding.Match) | Severity: $($finding.Severity)" -ForegroundColor Gray
            Write-Host ""
        }
        if ($group.Count -gt 3) {
            Write-Host "    ... and $($group.Count - 3) more" -ForegroundColor DarkGray
            Write-Host ""
        }
    }
}

# Export report if requested
if ($ExportReport -and $findings.Count -gt 0) {
    $reportPath = Join-Path $scriptPath "cheat-scan-report-$(Get-Date -Format 'yyyyMMdd-HHmmss).json"
    $findings | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "[*] Report saved to: $reportPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "    Scan completed successfully!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
