# .NET 6.x Application Detection for Microsoft Intune
## Detection Script Documentation

---

## Executive Summary

This solution provides a detection script for identifying applications that depend on the .NET 6.x runtime on Windows devices managed through Microsoft Intune Remediations. .NET 6 reached end-of-life on November 12, 2024, and applications targeting this runtime should be upgraded to a supported LTS version (.NET 8 or later).

**Key Benefits:**
- **Multi-Method Detection**: Combines five independent detection approaches to maximize coverage
- **Intune-Compliant**: Fully adheres to Microsoft Intune Remediation requirements (2,048 character output limit, proper exit codes, silent execution)
- **Timeout-Safe**: Built-in timeout protection to stay within Intune's 3-minute execution limit
- **Deduplication**: Avoids double-counting applications found by multiple methods
- **Actionable Output**: Reports specific application names and locations for remediation planning

**Deployment Model**: Microsoft Intune Remediations (Detection only -- reporting mode)

**Target Audience**: IT Administrators, Security Teams, Desktop Engineering

**Compatibility**: Windows 10/11, PowerShell 5.1+

---

## Table of Contents

1. [Overview](#overview)
2. [Detection Script](#detection-script)
3. [Deployment Guide](#deployment-guide)
4. [Usage Examples](#usage-examples)
5. [Post-Processing Tools](#post-processing-tools)
6. [Troubleshooting](#troubleshooting)
7. [FAQ](#faq)

---

## Overview

### Solution Architecture

```
+----------------------------------------------------------+
|                    Microsoft Intune                       |
|                      Remediations                        |
+----------------------------------------------------------+
                           |
                    +------v------+
                    |  Detection  |
                    |   Script    |
                    |             |
                    | Exit 0 = OK |--- No .NET 6.x apps found
                    | Exit 1 = Fix|--- .NET 6.x apps detected
                    +-------------+
                           |
                    +------v------+
                    |   Report    |
                    | Non-Compliant|
                    |   Devices   |
                    +-------------+
```

### Detection Methods

The script uses five layered detection methods to ensure comprehensive coverage:

```
+------------------+     +------------------+     +------------------+     +------------------+     +------------------+
| 1. RuntimeConfig |     | 2. Deps.json     |     | 3. Self-Contained|     | 4. Single-File   |     | 5. Registry Scan |
|    Scan          |     |    Scan          |     |    Binary Scan   |     |    Binary Scan   |     |                  |
| *.runtimeconfig  |     | *.deps.json      |     | coreclr.dll with |     | .NET bundle sig  |     | Uninstall keys   |
|    .json files   |     |    files         |     | version 6.x      |     | + framework ref  |     | + InstallLocation|
+------------------+     +------------------+     +------------------+     +------------------+     +------------------+
        |                        |                        |                        |                        |
        v                        v                        v                        v                        v
   Identifies apps          Catches apps           Detects apps that       Detects single-file      Links registered
   via framework            via target             bundle the .NET 6.x    published apps with      apps to .NET 6.x
   version reference        framework ref          runtime in-binary       embedded runtime         dependencies
```

### Files Included

| File | Purpose | Required |
|------|---------|----------|
| `Detect-DotNet6Apps.ps1` | Detection script for Intune | Yes |
| `Parse-DotNet6Report.ps1` | Parses Intune CSV export into structured app list | No (post-processing) |
| `Analyze-DotNet6Report.ps1` | Produces vendor/impact analysis from parsed results | No (post-processing) |
| `DotNet6Detection-Documentation.md` | This documentation | No |

---

## Detection Script

### File: `Detect-DotNet6Apps.ps1`

#### Purpose
Non-destructive detection script that identifies applications depending on .NET 6.x runtime on Windows devices. Designed specifically for Microsoft Intune Remediations.

#### What It Detects

##### 1. RuntimeConfig.json Scan
- Scans `C:\Program Files` and `C:\Program Files (x86)` recursively
- Excludes `\dotnet\shared\` and `\dotnet\sdk\` directories (the .NET runtime itself)
- Parses `*.runtimeconfig.json` files for:
  - `runtimeOptions.framework.version` matching `6.*`
  - `runtimeOptions.frameworks[].version` matching `6.*` (multi-framework apps)
  - `runtimeOptions.tfm` matching `net6.0` or `net6.0-*` (target framework moniker)
- Reports application name and directory path

##### 2. Deps.json Scan
- Scans `C:\Program Files` and `C:\Program Files (x86)` recursively
- Excludes `\dotnet\shared\` and `\dotnet\sdk\` directories (the .NET runtime itself)
- Uses string matching on `*.deps.json` files (avoids parsing very large JSON):
  - `.NETCoreApp,Version=v6.x` target framework references
  - `runtimeTarget` entries referencing `net6.0`
- Deduplicates against applications already found via runtimeconfig.json

##### 3. Self-Contained Binary Scan
- Scans `C:\Program Files` and `C:\Program Files (x86)` recursively for `coreclr.dll`
- Skips the shared dotnet runtime directory (`\dotnet\shared\`) to avoid false positives
- Reads the file version of `coreclr.dll` using `System.Diagnostics.FileVersionInfo`
- Flags directories where the file version starts with `6.` (indicating .NET 6.x bundled runtime)
- Identifies the app name from the primary `.exe` in the same directory
- Detects self-contained applications that embed the .NET 6.x runtime

##### 4. Single-File Binary Scan
- Scans `.exe` files in Program Files (depth-limited to 4 levels, minimum 500 KB)
- Skips `\dotnet\` and `\Windows Kits\` directories
- Skips executables already detected by other methods or with companion `runtimeconfig.json`/`coreclr.dll`
- Validates the .NET single-file bundle signature (32-byte SHA-256 hash at end of file) before scanning
- Only confirmed bundles are scanned for `.NETCoreApp,Version=v6.` framework strings
- Detects single-file published applications with embedded .NET 6.x framework

##### 5. Registry-Based Application Scan
- Scans `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- Scans `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
- For applications with a valid `InstallLocation`:
  - Searches the install directory (depth-limited to 2 levels) for `*.runtimeconfig.json`
  - Parses found configs for .NET 6.x framework references
- Reports application display name and version from registry
- Deduplicates against previously detected applications

#### Exit Codes

| Exit Code | Meaning | Action |
|-----------|---------|--------|
| 0 | Compliant - No applications depending on .NET 6.x detected | Remediation script NOT executed |
| 1 | Non-compliant - Applications depending on .NET 6.x found | Remediation script EXECUTED (or reported) |

#### Compliance Logic

The script determines compliance based on application findings across all five detection methods. Any application found via runtimeconfig.json, deps.json, self-contained binary inspection, single-file binary scan, or registry scan contributes to the compliance decision.

#### Output Validation

**Intune Requirement**: Maximum 2,048 characters

**Implementation**:
- All output collected in memory during execution
- Detected applications limited to first 10 entries in output
- Size validation performed before output emission
- Automatic truncation to summary-only if limit exceeded

#### Example Output (Compliant)

```
=== .NET 6.x Application Detection Started === | | === Detection Summary === | Apps (runtimeconfig.json): 0 | Apps (deps.json): 0 | Apps (self-contained): 0 | Apps (single-file): 0 | Apps (Registry): 0 | Total App Findings: 0 | Detection completed in 3.2 second(s) | Status: COMPLIANT - No applications depending on .NET 6.x detected
```

#### Example Output (Non-Compliant)

```
=== .NET 6.x Application Detection Started === | RuntimeConfig: 2 app(s) targeting .NET 6.x | Self-contained: 1 app(s) with bundled .NET 6.x runtime | Registry app: Contoso Agent v2.1.0 | | === Detection Summary === | Apps (runtimeconfig.json): 2 | Apps (deps.json): 0 | Apps (self-contained): 1 | Apps (single-file): 0 | Apps (Registry): 1 | Total App Findings: 4 | | === Detected Applications === | [runtimeconfig.json] ContosoAgent @ C:\Program Files\Contoso\Agent | [runtimeconfig.json] WidgetService @ C:\Program Files\Widgets\Service | [Self-contained binary] LegacyTool @ C:\Program Files\LegacyTool | [Registry] Contoso Agent @ C:\Program Files\Contoso\Agent | Detection completed in 5.1 second(s) | Status: NON-COMPLIANT - 4 application(s) depending on .NET 6.x detected
```

#### Technical Specifications

| Property | Value |
|----------|-------|
| Language | PowerShell 5.1+ |
| Typical Execution Time | 5-30 seconds (depends on disk content) |
| Execution Context | SYSTEM or User |
| Privileges Required | Read-only (no admin required for detection) |
| Timeout Protection | Automatically stops scans at 170 seconds |
| Output Limit | Respects Intune 2,048 character limit |
| Destructive | No -- read-only operations only |

---

## Deployment Guide

### Prerequisites

- Windows 10 or Windows 11
- PowerShell 5.1 or higher
- Microsoft Intune license with Remediations capability

### Intune Configuration

1. Navigate to **Devices** > **Remediations** in the Microsoft Intune admin center
2. Click **+ Create script package**
3. Configure:
   - **Name**: `MWPW_PRD_DotNetDetect`
   - **Description**: Detects applications depending on end-of-life .NET 6.x runtime
   - **Publisher**: DW Client Solutions
4. Upload scripts:
   - **Detection script**: `Detect-DotNet6Apps.ps1`
   - **Remediation script**: None (detection/reporting only) or custom remediation
5. Script settings:
   - **Run this script using the logged-on credentials**: No (run as SYSTEM)
   - **Enforce script signature check**: Per organization policy
   - **Run script in 64-bit PowerShell**: Yes
6. Assignments:
   - Assign to target device groups
   - Set schedule (recommended: once daily or weekly)

### Recommended Schedule

| Environment | Frequency | Purpose |
|-------------|-----------|---------|
| Pilot | Daily | Rapid feedback during initial rollout |
| Production | Weekly | Ongoing compliance monitoring |
| Post-migration | Daily (temporary) | Verify .NET 6.x app upgrades completed |

---

## Usage Examples

### Local Testing

> **Note:** The detection script accepts no parameters. Intune Remediations do not support passing arguments to scripts. Local testing is useful for validating behaviour on a single device.

```powershell
# Run detection locally (as admin for full coverage)
.\Detect-DotNet6Apps.ps1

# Check exit code
$LASTEXITCODE
# 0 = compliant, 1 = non-compliant
```

### Interpreting Results

**Exit Code 0**: The device has no applications depending on .NET 6.x. The device is compliant.

**Exit Code 1**: One or more applications depending on .NET 6.x were found. Review the output to identify which applications need to be upgraded or removed.

---

## Post-Processing Tools

After collecting detection results from the fleet via Intune, use these companion scripts to extract and analyse the data.

### Parse-DotNet6Report.ps1

Parses the raw Intune Remediation CSV export (DeviceRunStatesByProactiveRemediation) and extracts all detected .NET 6.x applications into a structured format.

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-CsvPath` | Yes | -- | Path to the Intune CSV export file |
| `-OutputPath` | No | None (screen only) | Path for the output CSV. If omitted, results are printed to screen only |
| `-PostFilter` | No | Off | Excludes `dotnet\sdk` and `dotnet\shared` paths from results (useful for reports collected before those exclusions were added to the detection script) |
| `-Detailed` | No | Off | Includes per-device breakdown in console output |

#### Usage

```powershell
# Screen-only output
.\Parse-DotNet6Report.ps1 -CsvPath ".\DeviceRunStatesByProactiveRemediation.csv"

# Export to CSV with post-filtering
.\Parse-DotNet6Report.ps1 -CsvPath ".\report.csv" -OutputPath ".\DotNet6Apps.csv" -PostFilter

# Full per-device breakdown
.\Parse-DotNet6Report.ps1 -CsvPath ".\report.csv" -Detailed
```

#### Output Columns (CSV)

| Column | Description |
|--------|-------------|
| `AppName` | Application name extracted from detection output |
| `AppPath` | Installation path on the device |
| `DetectionMethod` | Which detection method(s) found the application |
| `DeviceCount` | Number of unique devices where the application was detected |
| `Devices` | Semicolon-separated list of device names |

---

### Analyze-DotNet6Report.ps1

Produces a prioritised vendor/impact analysis report from the CSV output of `Parse-DotNet6Report.ps1`. Dynamically extracts vendor names from install paths (first subfolder under Program Files).

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-CsvPath` | Yes | -- | Path to the parsed CSV file (output from Parse-DotNet6Report.ps1) |
| `-Threshold` | No | 500 | Minimum device count for the high-impact report section |
| `-Top` | No | 20 | Number of top applications to display |
| `-OutputPath` | No | None (screen only) | Path for an enriched analysis CSV export (adds Vendor and HighImpact columns) |

#### Usage

```powershell
# Screen-only analysis with defaults
.\Analyze-DotNet6Report.ps1 -CsvPath ".\DotNet6Apps.csv"

# Lower threshold, more results
.\Analyze-DotNet6Report.ps1 -CsvPath ".\DotNet6Apps.csv" -Threshold 100 -Top 30

# Export with vendor tagging for further processing
.\Analyze-DotNet6Report.ps1 -CsvPath ".\DotNet6Apps.csv" -OutputPath ".\Analysis.csv"
```

#### Report Sections

1. **Detection Method Breakdown** -- Count of apps found by each method
2. **Vendor Impact Analysis** -- Dynamic vendor grouping with unique app count, max device count, and total device-hits
3. **Top N Applications** -- Highest-impact apps by device count
4. **High-Impact Applications** -- All apps above the threshold
5. **Summary Statistics** -- Totals and key metrics

---

### End-to-End Workflow

```
1. Deploy Detect-DotNet6Apps.ps1 via Intune Remediations
2. Wait for reporting cycle to complete (daily/weekly)
3. Export CSV: Intune > Devices > Remediations > [Package] > Device status > Export
4. Parse:   .\Parse-DotNet6Report.ps1 -CsvPath ".\export.csv" -OutputPath ".\parsed.csv" -PostFilter
5. Analyse: .\Analyze-DotNet6Report.ps1 -CsvPath ".\parsed.csv" -Threshold 100
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Script reports 0 runtimes but finds apps | dotnet.exe not in standard paths | Normal -- apps may bundle runtime or use self-contained deployment |
| Scan times out | Large Program Files with many subdirectories | Expected on content-heavy devices; partial results still reported |
| False positive | App ships with net6.0 config but is self-contained and works without runtime | Review the specific app; may need exclusion logic |
| No apps found but runtime installed | Runtime installed but no framework-dependent apps exist | Compliant -- runtime alone is not a finding |

### Verbose Logging

> **Note:** The detection script does not accept parameters -- Intune Remediations cannot pass arguments to scripts. The `-Verbose` preference variable must be set manually before execution, making this useful only for local troubleshooting with limited scope.

```powershell
$VerbosePreference = 'Continue'
.\Detect-DotNet6Apps.ps1 2>&1 | Out-File .\detection-verbose.log
```

---

## FAQ

**Q: Why does the script not flag devices that only have .NET 6.x runtime installed?**
A: The runtime alone is not a security risk if no applications use it. The script focuses on detecting applications that actively depend on the end-of-life runtime, which is the actionable finding.

**Q: Does this detect self-contained .NET 6.x applications?**
A: Yes. Self-contained applications are detected in two ways: (1) their `runtimeconfig.json` and `deps.json` files still reference .NET 6.x, and (2) the self-contained binary scan identifies `coreclr.dll` with file version 6.x bundled directly in the application directory.

**Q: How does the self-contained binary scan avoid false positives?**
A: The scan explicitly skips the shared dotnet runtime directory (`\dotnet\shared\`). It only flags `coreclr.dll` found in application-specific directories, which indicates the runtime was bundled with the app via self-contained or single-file publish.

**Q: What about .NET 6.x applications installed per-user (AppData)?**
A: The current version scans only Program Files and registry. Per-user AppData scanning can be added if needed, following the same per-user enumeration pattern used in other remediation scripts.

**Q: How does it handle large directories?**
A: The script includes timeout protection. If scanning takes too long, it stops gracefully and reports partial results. The timeout threshold is 170 seconds (within Intune's 3-minute limit).

**Q: Will this script cause any changes to the device?**
A: No. The script is entirely read-only. It does not modify files, registry keys, or installed software.

---

## References

- [.NET Support Policy](https://dotnet.microsoft.com/platform/support/policy/dotnet-core)
- [.NET 6 End of Support](https://devblogs.microsoft.com/dotnet/dotnet-6-end-of-support/)
- [Microsoft Intune Remediations](https://learn.microsoft.com/intune/intune-service/fundamentals/remediations)
- [runtimeconfig.json Reference](https://learn.microsoft.com/dotnet/core/runtime-config/)
