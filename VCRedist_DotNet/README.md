# Using the Detect, Parse & Analyze Scripts for Runtime Dependency Discovery

This guide covers the practical use of the detection script suites for unsupported runtime dependencies. Two suites exist with identical operational patterns:

- **DotNetDetect** -- finds applications depending on end-of-life .NET 6.x
- **VCRedistDetect** -- finds applications depending on unsupported Visual C++ runtimes (2005-2013) and outdated VC++ 14.x packages

Each suite consists of three scripts that form a pipeline: Detect (runs on devices), Parse (extracts structured data from Intune export), and Analyze (produces prioritised remediation intelligence).

---

## Prerequisites

- PowerShell 5.1 or higher (all scripts)
- Microsoft Intune with Remediations (for detection deployment)
- Access to export "Device run states" CSV from the Intune portal

---

## Step 1: Deploy the Detection Script

The detection scripts run on endpoints via Intune Remediations. They require no parameters (Intune does not support passing arguments to remediation scripts).

### Intune Configuration

1. Navigate to **Devices > Remediations** (or Endpoint analytics > Remediations)
2. Create a new script package
3. Upload the detection script:
   - For .NET 6: `Detect-DotNet6Apps.ps1`
   - For VC++: `Detect-LegacyVCRedist.ps1`
4. Leave the remediation script blank (detection-only)
5. Settings:
   - Run this script using the logged-on credentials: **No** (run as SYSTEM)
   - Enforce script signature check: per your policy
   - Run script in 64-bit PowerShell: **Yes**
6. Assign to a device group (start with a pilot group)
7. Set a schedule (or Once for initial data collection)

### What Happens on the Device

The script runs silently, scans the local file system and registry, then exits:

- **Exit 0** = Compliant (no findings)
- **Exit 1** = Non-compliant (findings detected)

Output is written as a single pipe-delimited string within the 2048-character Intune limit. No files are written to disk, no network calls are made, and no changes are made to the system.

---

## Step 2: Export Results from Intune

Once reporting data has populated (allow 24-48 hours for fleet coverage):

1. Navigate to the remediation in Intune
2. Go to **Device status**
3. Filter to "With issues" (exit code 1) if desired
4. Click **Export** to download the CSV

The exported file is typically named `DeviceRunStatesByProactiveRemediation.csv` and contains one row per device with the detection output in a `PreRemediationDetectionScriptOutput` column (column name varies by Intune export version -- the Parse scripts auto-detect it).

---

## Step 3: Parse the Export

The Parse scripts extract structured application data from the raw Intune CSV.

### .NET 6

```powershell
# Basic parse -- results to screen
.\Parse-DotNet6Report.ps1 -CsvPath ".\DeviceRunStates.csv"

# Parse with CSV export and SDK/runtime path filtering
.\Parse-DotNet6Report.ps1 -CsvPath ".\DeviceRunStates.csv" -OutputPath ".\DotNet6Apps.csv" -PostFilter

# Parse with per-device detail
.\Parse-DotNet6Report.ps1 -CsvPath ".\DeviceRunStates.csv" -OutputPath ".\DotNet6Apps.csv" -Detailed
```

### VC++ Redistributable

```powershell
# Basic parse -- results to screen
.\Parse-VCRedistReport.ps1 -CsvPath ".\DeviceRunStates.csv"

# Parse with CSV export
.\Parse-VCRedistReport.ps1 -CsvPath ".\DeviceRunStates.csv" -OutputPath ".\VCRedistApps.csv"

# Parse with per-device detail
.\Parse-VCRedistReport.ps1 -CsvPath ".\DeviceRunStates.csv" -OutputPath ".\VCRedistApps.csv" -Detailed
```

Note: The VC++ detection script already excludes System32, SysWOW64, WinSxS, and Office C2R paths at detection time. The `-PostFilter` switch exists in the Parse script for backward compatibility with older detection script exports (pre-v1.2.0) but is not needed with current versions.

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-CsvPath` | Yes | Path to the Intune CSV export |
| `-OutputPath` | No | Export results to CSV (screen-only if omitted) |
| `-PostFilter` | No | Exclude noise paths. Required for .NET 6 (SDK/runtime filtering). Not needed for VC++ (detection script already filters at source) |
| `-Detailed` | No | Show per-device breakdown in console output |

### What You Get

The output CSV contains one row per unique application with:

- **AppName** -- application identifier (exe name or display name)
- **AppPath** -- file system location where it was found
- **DetectionMethod** -- which detection technique found it
- **DeviceCount** -- number of devices where this app was detected
- **Devices** -- semicolon-separated list of device names

### Tips

- Always use `-PostFilter` for the .NET 6 suite unless you specifically want to see SDK/runtime paths
- For the VC++ suite, `-PostFilter` is not needed -- the detection script already excludes system and Office C2R paths before output
- The `-Detailed` switch is useful for validating results on small pilot groups but produces verbose output on large fleets
- The Parse scripts only process rows where the device was non-compliant (exit 1)
- Column auto-detection handles various Intune export formats -- you do not need to rename columns

---

## Step 4: Analyze for Prioritisation

The Analyze scripts take the parsed CSV and produce actionable intelligence for remediation planning.

### .NET 6

```powershell
# Standard analysis (top 20 apps, high-impact threshold 500 devices)
.\Analyze-DotNet6Report.ps1 -CsvPath ".\DotNet6Apps.csv"

# Lower threshold for smaller fleet, show more apps
.\Analyze-DotNet6Report.ps1 -CsvPath ".\DotNet6Apps.csv" -Threshold 100 -Top 30

# Export enriched analysis CSV (adds Vendor and HighImpact columns)
.\Analyze-DotNet6Report.ps1 -CsvPath ".\DotNet6Apps.csv" -OutputPath ".\DotNet6Analysis.csv"
```

### VC++ Redistributable

```powershell
# Standard analysis
.\Analyze-VCRedistReport.ps1 -CsvPath ".\VCRedistApps.csv"

# Lower threshold, more results
.\Analyze-VCRedistReport.ps1 -CsvPath ".\VCRedistApps.csv" -Threshold 100 -Top 30

# Export enriched analysis CSV
.\Analyze-VCRedistReport.ps1 -CsvPath ".\VCRedistApps.csv" -OutputPath ".\VCRedistAnalysis.csv"
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-CsvPath` | Yes | -- | Path to the Parse script's output CSV |
| `-Threshold` | No | 500 | Minimum device count for the high-impact list |
| `-Top` | No | 20 | Number of top applications to display |
| `-OutputPath` | No | -- | Export enriched analysis CSV |

### Report Sections

The analysis produces several sections in the console output:

1. **Detection Method Breakdown** -- which methods found the most apps (helps understand where dependencies live)
2. **Version Distribution** (VC++ only) -- shows which legacy VC++ versions are most prevalent
3. **Vendor Impact Analysis** -- dynamically groups apps by vendor (extracted from file paths, no hardcoded list)
4. **Top N Applications** -- ranked by device count (your highest-impact remediation targets)
5. **High-Impact Applications** -- filtered to only those above your threshold
6. **Summary Statistics** -- totals and averages

### Tips

- Start with the default `-Threshold 500` to focus on the biggest impact items
- Lower it progressively as you work through the backlog
- The `-OutputPath` CSV adds `Vendor` and `HighImpact` columns to the parsed data, making it easy to pivot in Excel
- Vendor extraction uses the first subfolder under Program Files -- it handles most commercial software correctly without any configuration

---

## End-to-End Example

Here is a complete workflow from deployment to remediation planning:

```powershell
# After exporting the Intune CSV to your working directory...

# --- .NET 6 ---
.\Parse-DotNet6Report.ps1 -CsvPath ".\IntuneExport_DotNet6.csv" -OutputPath ".\DotNet6Apps.csv" -PostFilter
.\Analyze-DotNet6Report.ps1 -CsvPath ".\DotNet6Apps.csv" -Threshold 200 -OutputPath ".\DotNet6Analysis.csv"

# --- VC++ Redist ---
.\Parse-VCRedistReport.ps1 -CsvPath ".\IntuneExport_VCRedist.csv" -OutputPath ".\VCRedistApps.csv"
.\Analyze-VCRedistReport.ps1 -CsvPath ".\VCRedistApps.csv" -Threshold 200 -OutputPath ".\VCRedistAnalysis.csv"
```

Open the analysis CSVs in Excel for filtering, pivot tables, and sharing with application owners.

---

## Understanding the Detection Output

When viewing raw Intune output (before parsing), the detection scripts produce pipe-delimited strings. Here is what the fields mean:

### Normal output (fits within 2048 characters)

```
=== Legacy VC++ Redistributable Detection v1.4.0 === | Installed: AppName v1.0 | ...
| === Detection Summary === | Installed Redist packages: 14 | Apps (PE Import): 8 | ...
| === Detected Applications === | [PE Import (VC++ 2010 (10.0))] keytool @ C:\Program Files\Java\...
| Status: NON-COMPLIANT - 25 finding(s)...
```

### Truncated output (exceeds 2048 characters)

```
=== VC++ Detection v1.4.0 (Truncated) === | Installed: 14 | PE: 8 | Local: 3 | SxS: 0 | V14: 0
| Total: 25 | [PE Import (VC++ 2010 (10.0))] keytool | [App-local DLL (VC++ 2013 (12.0))] appvcleaner
| (+12 more) | Status: NON-COMPLIANT - 25 finding(s)...
```

In truncated mode:
- Paths are omitted to save space
- Applications are deduplicated by name
- Actionable findings (PE Import, App-local, SxS, Outdated V14) are listed first
- Installed Redist packages are shown last (already visible in Intune software inventory)
- A "(+N more)" counter shows how many entries did not fit

The Parse scripts handle both formats transparently.

---

## Detection Methods at a Glance

### VC++ Redistributable Suite

| Tag in Output | What It Means | Remediation |
|---------------|---------------|-------------|
| `[Installed Redist]` | Legacy redist package registered in Add/Remove Programs | Remove after confirming no apps depend on it |
| `[PE Import (VC++ XXXX)]` | Executable directly imports a legacy VC runtime DLL | Contact vendor for updated build |
| `[App-local DLL (VC++ XXXX)]` | Legacy DLL bundled in the app directory | Contact vendor -- private copy, cannot be patched centrally |
| `[SxS Manifest (VC++ XXXX)]` | App manifest declares SxS dependency on VC++ 2005/2008 | Contact vendor or plan replacement |
| `[Outdated V14 Redist]` | VC++ 14.x package installed but below minimum version | Deploy latest VC++ 14.x Redistributable (no app changes needed) |

### .NET 6 Suite

| Tag in Output | What It Means | Remediation |
|---------------|---------------|-------------|
| `[RuntimeConfig]` | App has runtimeconfig.json targeting .NET 6 | Vendor must rebuild for .NET 8+ |
| `[Deps.json]` | App deps.json references .NET 6 | Vendor must rebuild for .NET 8+ |
| `[Self-contained]` | App bundles coreclr.dll version 6.x | Vendor must rebuild and redistribute |
| `[Single-file]` | Monolithic .NET 6 single-file publish | Vendor must rebuild and redistribute |
| `[Registry]` | Registered app with .NET 6 config in install directory | Vendor must rebuild for .NET 8+ |

---

## Frequently Asked Questions

### Can the detection scripts modify anything on the device?

No. They are strictly read-only. They scan the file system and registry but write nothing, create no files, and make no network calls.

### How long do they take to run?

Typically 30-90 seconds depending on how many executables are installed. A 170-second timeout prevents exceeding Intune's 3-minute limit. If timeout is reached, remaining checks are skipped and a notice is included in the output.

### Why does my Java installation show up as a VC++ finding?

The JVM and all JRE/JDK command-line utilities (`java.exe`, `keytool.exe`, `jjs.exe`, etc.) are native C++ executables. They are compiled against whatever VC++ toolchain was current when that JRE version was built. An old JRE 8 can generate 15+ PE Import findings for `msvcr100.dll`. The fix is to upgrade the JRE/JDK to a current version.

### What if the output is truncated?

The Parse scripts handle truncated output correctly. However, truncated output may not contain all detected apps (only as many as fit in 2048 characters). The counts in the header (`PE: 23`, `Local: 3`, etc.) always reflect the true totals even when individual entries are cut off.

### Should I use -PostFilter?

For the **.NET 6 suite**, yes -- without it you will see noise from .NET SDK and shared runtime directories (the runtime itself, not an app depending on it).

For the **VC++ suite**, it is not needed. The detection script (v1.2.0+) already excludes:
- System32/SysWOW64/WinSxS (system-installed VC++ copies)
- Microsoft Office C2R paths (managed by Office update channel)

The `-PostFilter` switch still exists in the VC++ Parse script for backward compatibility if you are processing CSVs exported from an older detection script version.

### Can I run the Parse/Analyze scripts without Intune?

The Parse scripts expect the specific CSV format exported from Intune Remediations. They cannot process arbitrary data. However, if you run the detection script locally on a device, you can read its console output directly -- the Parse scripts are only needed for fleet-scale analysis.

### How often should I re-run the analysis?

- **Initial deployment**: daily schedule until you have full fleet coverage (1-2 weeks)
- **Ongoing monitoring**: weekly or bi-weekly to catch new app deployments
- **Post-remediation**: re-run after deploying VC++ 14.x updates or retiring legacy apps to confirm findings decrease

---

## Quick Reference

```powershell
# VC++ Redist: full pipeline
.\Parse-VCRedistReport.ps1 -CsvPath ".\export.csv" -OutputPath ".\parsed.csv"
.\Analyze-VCRedistReport.ps1 -CsvPath ".\parsed.csv" -OutputPath ".\analysis.csv"

# .NET 6: full pipeline
.\Parse-DotNet6Report.ps1 -CsvPath ".\export.csv" -OutputPath ".\parsed.csv" -PostFilter
.\Analyze-DotNet6Report.ps1 -CsvPath ".\parsed.csv" -OutputPath ".\analysis.csv"
```
