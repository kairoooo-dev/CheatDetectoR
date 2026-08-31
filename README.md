# Minecraft Cheat Detector

A PowerShell-based tool to scan for known Minecraft cheat clients and suspicious modifications on your PC.

## Features

- Scans standard Minecraft directories
- Detects 50+ known cheat clients
- Detects suspicious file extensions
- Identifies cheats in mod folders
- Deep scan option for additional directories
- Export reports to JSON

## Supported Cheat Clients

Wurst, Impact, Future, Inertia, Rise, Moon, Sigma, Vape, Raven, Phobos, Aristotle, Konas, Tenacity, Onyx, Aristois, Mercenaries, Zed, Dawn, Yum, Flareon, Gambler, LiquidBounce, FH-API, BleachHack, NightX, Exhibition, Element, Jigsaw, HNS, Xulu, Dortware, AutoAim, AutoClicker, KillAura, Scaffold, Jesus, Nuker, Timer, Velocity, Freecam, Xray, AntiKnockback, Reach, AimAssist, FastPlace, NoSlow, Sprint, ChestStealer, AutoArmor, NoFall

## Usage

### Quick Scan
```powershell
.\startScan.ps1
```

### Deep Scan (includes Downloads, Documents, Desktop)
```powershell
.\startScan.ps1 -DeepScan
```

### Export Report
```powershell
.\startScan.ps1 -ExportReport
```

### Custom Scan Path
```powershell
.\startScan.ps1 -ScanPath "C:\path\to\scan"
```

## Installation

1. Clone the repository:
```powershell
git clone https://github.com/kairoooo-dev/CheatDetectoR.git
```

2. Navigate to the directory:
```powershell
cd CheatDetectoR
```

3. Run the scan:
```powershell
.\startScan.ps1
```

## Requirements

- Windows 10/11
- PowerShell 5.1+

## Detection Methods

- Filename pattern matching
- Suspicious file extension detection
- Path-based detection
- Known cheat database matching

## Report

Reports are saved as JSON files in the tool directory with timestamps.

## License

MIT License
