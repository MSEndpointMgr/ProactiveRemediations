# MWPW_PRD_VCRedistDetect - Legacy VC++ Redistributable Detection Suite

## Overview

This suite detects devices running applications that depend on unsupported or outdated Visual C++ Redistributable runtimes. It consists of three scripts:

| Script | Purpose |
|--------|---------|
| `Detect-LegacyVCRedist.ps1` | Intune Remediation detection script (runs on endpoints) |
| `Parse-VCRedistReport.ps1` | Post-processing: extracts per-app data from Intune CSV export |
| `Analyze-VCRedistReport.ps1` | Fleet analysis: vendor grouping, version distribution, priority ranking |

---

## Targeted VC++ Versions

### Unsupported (End-of-Life) -- Requires App Update or Replacement

| Version | Visual Studio | EOL Date | Runtime DLLs |
|---------|---------------|----------|--------------|
| 8.0 | VS 2005 | April 12, 2016 | msvcr80.dll, msvcp80.dll |
| 9.0 | VS 2008 | April 10, 2018 | msvcr90.dll, msvcp90.dll |
| 10.0 | VS 2010 | July 14, 2020 | msvcr100.dll, msvcp100.dll |
| 11.0 | VS 2012 | January 10, 2023 | msvcr110.dll, msvcp110.dll, vccorlib110.dll |
| 12.0 | VS 2013 | April 9, 2024 | msvcr120.dll, msvcp120.dll, vccorlib120.dll |

### Outdated (Updateable) -- Requires Package Update Only

| Version | Visual Studio | Status | Runtime DLLs |
|---------|---------------|--------|--------------|
| 14.x | VS 2015/2017/2019/2022/2026 | Supported but outdated package | vcruntime140.dll, msvcp140.dll, vcruntime140_1.dll |

The v14 runtime is binary-compatible across all VS 2015-2026 releases. Applications using `vcruntime140.dll` do **not** need recompilation -- only the redistributable package needs updating to the latest security-patched release. The detection script flags outdated v14 packages that may contain known CVEs.

---

## Detection Methods

### Check 1: Installed Legacy Redistributable Packages (Registry)

Scans the Windows Uninstall registry keys for installed VC++ 2005-2013 Redistributable packages:
- `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`

Matches display names containing "Visual C++ 2005/2008/2010/2012/2013" or version patterns "8.0" through "12.0".

**Impact**: Confirms the legacy runtime is present on the device (even if no app actively uses it).

### Check 2: PE Import Table Analysis

Parses the Portable Executable (PE) header of `.exe` files in Program Files directories (depth 4) to read the Import Directory Table. Identifies executables that directly import legacy VC runtime DLLs.

**How it works**:
1. Reads DOS Header (verifies MZ signature)
2. Navigates to PE Signature via `e_lfanew`
3. Reads COFF Header + Optional Header to locate Import Directory RVA
4. Reads Section Table to convert RVA to file offset
5. Iterates Import Directory entries and reads DLL name strings
6. Matches names against `msvcr{80-120}.dll`, `msvcp{80-120}.dll`, `vccorlib{110-120}.dll`

**Constraints**: Files 10KB-500MB, max depth 4, max 256 import entries per file.

### Check 3: App-Local Legacy DLL Copies

Scans Program Files for copies of legacy VC runtime DLLs deployed alongside applications (app-local deployment). These are DLLs bundled in the application directory rather than using the system-installed redistributable.

Excludes system directories (System32, SysWOW64, WinSxS) which contain the centrally-installed copies.

### Check 4: Side-by-Side (WinSxS) Manifest References

VC++ 2005 and 2008 use the Windows Side-by-Side (SxS) mechanism. Applications declare runtime dependencies via manifest files referencing assembly identities such as:
- `microsoft.vc80.crt` / `microsoft.vc80.mfc` / `microsoft.vc80.atl`
- `microsoft.vc90.crt` / `microsoft.vc90.mfc` / `microsoft.vc90.atl`

This check scans `.manifest` files in Program Files (depth 4, max 100KB) for these assembly references.

### Check 5: Outdated VC++ 14.x Redistributable Package

Checks if the installed VC++ 14.x (2015-2026) Redistributable package version is below a minimum acceptable threshold. This does NOT mean the apps are broken -- it means the runtime package has known security vulnerabilities and should be updated.

**Registry locations checked**:
- `HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\{x64|x86}` (Version/Major/Minor/Bld)
- Fallback: Uninstall keys matching "Visual C++ 2015/2017/2019/2022/2026 Redistributable"

**Current minimum version**: `14.51.36231.0` (VS 2026 18.x servicing update, May 2026)

**Key difference from Checks 1-4**: The remediation here is simply installing the latest v14 redistributable package. No application changes are needed.

---

## Output Format

The detection script produces pipe-delimited (`|`) output within the Intune 2048-character limit. Detected applications are listed as:

```
[Method] AppName @ Path
```

Examples:
```
[Installed Redist] Microsoft Visual C++ 2012 Redistributable (x64) @ C:\Program Files\...
[PE Import (VC++ 2010 (10.0))] SomeApp @ C:\Program Files\Vendor\SomeApp
[App-local DLL (VC++ 2008 (9.0))] LegacyTool @ C:\Program Files (x86)\OldVendor\Tool
[SxS Manifest (VC++ 2005 (8.0))] AncientApp @ C:\Program Files\Archive\App
[Outdated V14 Redist] VC++ 14.x Redist (x64) @ Installed: v14.36.32532.0 (minimum: v14.40.33816.0)
```

---

## Post-Processing Tools

### Parse-VCRedistReport.ps1

Processes the Intune "DeviceRunStatesByProactiveRemediation" CSV export and extracts detection data into a structured format.

**Parameters**:
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-CsvPath` | Yes | Path to Intune CSV export |
| `-OutputPath` | No | Export results to CSV (screen-only if omitted) |
| `-PostFilter` | No | Exclude System32/SysWOW64/WinSxS paths |
| `-Detailed` | No | Show per-device breakdown |

**Output**: Unique application list with detection method, path, and device count. Uses HashSet-based summarisation for performance on large datasets.

**Auto-detection**: Automatically identifies the correct output column from various Intune export formats.

### Analyze-VCRedistReport.ps1

Produces actionable intelligence from the Parse script's CSV output for remediation planning.

**Parameters**:
| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-CsvPath` | Yes | -- | Path to Parse output CSV |
| `-Threshold` | No | 500 | Minimum device count for high-impact list |
| `-Top` | No | 20 | Number of top apps to display |
| `-OutputPath` | No | -- | Export enriched analysis CSV |

**Analysis sections**:
- Detection method breakdown (which methods found the most apps)
- VC++ version distribution (which legacy versions are most prevalent)
- Vendor impact analysis (dynamic extraction from file paths -- no hardcoded vendor list)
- Top N applications by device count
- High-impact applications above threshold
- Summary statistics

---

## End-to-End Workflow

### Step 1: Deploy Detection Script

1. Upload `Detect-LegacyVCRedist.ps1` as an Intune Proactive Remediation detection script
2. Assign to target device groups
3. Wait for reporting data to populate (24-48h for full fleet coverage)

### Step 2: Export Results

1. Navigate to Intune > Reports > Endpoint analytics > Proactive remediations
2. Select the MWPW_PRD_VCRedistDetect remediation
3. Export "Device run states" to CSV

### Step 3: Parse Fleet Data

```powershell
# Basic parse (screen output)
.\Parse-VCRedistReport.ps1 -CsvPath ".\DeviceRunStates.csv"

# Parse with export and system-path filtering
.\Parse-VCRedistReport.ps1 -CsvPath ".\DeviceRunStates.csv" -OutputPath ".\VCRedistApps.csv" -PostFilter

# Parse with per-device detail
.\Parse-VCRedistReport.ps1 -CsvPath ".\DeviceRunStates.csv" -Detailed
```

### Step 4: Analyse for Prioritisation

```powershell
# Standard analysis
.\Analyze-VCRedistReport.ps1 -CsvPath ".\VCRedistApps.csv"

# Lower threshold for smaller fleet, export report
.\Analyze-VCRedistReport.ps1 -CsvPath ".\VCRedistApps.csv" -Threshold 100 -Top 30 -OutputPath ".\Analysis.csv"
```

### Step 5: Remediation Actions

Based on the analysis output:

| Finding Type | Remediation Action |
|---|---|
| Outdated V14 Redist | Deploy latest VC++ 14.x Redistributable via Intune (no app changes needed) |
| Installed legacy redist (2005-2013) | Remove package if no dependent apps remain; update apps that require it |
| PE Import / App-local / SxS apps | Contact vendor for updated version or plan app replacement |

---

## Technical Notes

- **Timeout handling**: Detection script has a 170-second safety threshold (Intune allows 180s). Each major check is skipped if timeout is reached.
- **Output truncation**: If output exceeds 2048 characters, a summary-only version is emitted.
- **No parameters**: The detection script accepts no parameters (Intune Remediation limitation). All configuration is internal.
- **Performance**: PE Import scanning is the most expensive check. Files are filtered by size (10KB-500MB) and depth (4 levels) to stay within timeout.
- **V14 threshold updates**: When a new security-patched v14 redist is released, update the `$MINIMUM_V14_VERSION` variable in the detection script.

---

## References

- [Latest supported Visual C++ Redistributable downloads](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist)
- [Redistributable version auditing](https://learn.microsoft.com/cpp/windows/redist-version-auditing)
- [Visual C++ Runtime lifecycle](https://learn.microsoft.com/lifecycle/products/?terms=visual+c%2B%2B)
- [PE Format specification](https://learn.microsoft.com/windows/win32/debug/pe-format)
