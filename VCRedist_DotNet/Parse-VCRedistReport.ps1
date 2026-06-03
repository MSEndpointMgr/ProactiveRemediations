<#
.SYNOPSIS
    Parses Intune Remediation CSV export and extracts all detected legacy VC++ runtime dependencies.

.DESCRIPTION
    This script processes the "DeviceRunStatesByProactiveRemediation" CSV export from
    Microsoft Intune and extracts the detection output from MWPW_PRD_VCRedistDetect.
    It parses the pipe-delimited detection strings and produces a consolidated list
    of all applications found to depend on unsupported VC++ runtimes across all reported devices.

    Output includes:
    - Unique application list with detection method, name, path, and device count
    - Per-device breakdown (optional with -Detailed switch)
    - CSV export of results (optional with -OutputPath)

.PARAMETER CsvPath
    Path to the Intune Remediation CSV export file.

.PARAMETER OutputPath
    Path for the output CSV file. If omitted, results are printed to screen only.

.PARAMETER PostFilter
    Exclude system-level VC runtime paths (System32, SysWOW64, WinSxS) from results.

.PARAMETER Detailed
    Include per-device breakdown in console output.

.EXAMPLE
    .\Parse-VCRedistReport.ps1 -CsvPath "C:\Users\user\Downloads\DeviceRunStatesByProactiveRemediation.csv"

.EXAMPLE
    .\Parse-VCRedistReport.ps1 -CsvPath ".\report.csv" -OutputPath ".\VCRedistApps.csv" -PostFilter

.EXAMPLE
    .\Parse-VCRedistReport.ps1 -CsvPath ".\report.csv" -Detailed

.NOTES
    FileName: Parse-VCRedistReport.ps1
    Author: Anders Ahl
    Created: 2026-06-02
    Updated: 2026-06-02
    Version: 1.0.0
    Requires: PowerShell 5.1 or higher
    Use Case: Post-processing of MWPW_PRD_VCRedistDetect Intune Remediation output

    Version history:
    1.0.0 - Initial release
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the Intune Remediation CSV export file.")]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath,

    [Parameter(Mandatory = $false, HelpMessage = "Path for the output CSV file.")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, HelpMessage = "Exclude system-level VC runtime paths from results.")]
    [switch]$PostFilter,

    [Parameter(Mandatory = $false, HelpMessage = "Include per-device breakdown in console output.")]
    [switch]$Detailed
)

Begin {
    $Timer = [System.Diagnostics.Stopwatch]::StartNew()
    $ParsedApps = New-Object -TypeName "System.Collections.Generic.List[System.Object]"
    $DeviceCount = 0
    $NonCompliantCount = 0
    $ErrorCount = 0

    # Validate input file
    if (-not (Test-Path -Path $CsvPath -ErrorAction SilentlyContinue)) {
        Write-Warning "CSV file not found: $($CsvPath)"
        return
    }
}

Process {
    try {
        # Import the CSV
        Write-Host "Importing CSV from: $($CsvPath)"
        $csvData = Import-Csv -Path $CsvPath -ErrorAction Stop
        $DeviceCount = $csvData.Count
        Write-Host "Loaded $($DeviceCount) device record(s)"

        # Identify the detection output column
        $columnNames = $csvData[0].PSObject.Properties.Name
        $outputColumn = $null

        # Try common column name patterns from Intune export
        $candidateColumns = @(
            'PreRemediationDetectionScriptOutput',
            'DetectionScriptOutput',
            'Pre-remediationDetectionScriptOutput',
            'preRemediationDetectionScriptOutput'
        )

        foreach ($candidate in $candidateColumns) {
            if ($columnNames -contains $candidate) {
                $outputColumn = $candidate
                break
            }
        }

        # Fallback: find column containing detection output markers
        if (-not $outputColumn) {
            foreach ($col in $columnNames) {
                $sampleValue = ($csvData | Where-Object { $_.$col -match 'VC\+\+' } | Select-Object -First 1).$col
                if ($sampleValue) {
                    $outputColumn = $col
                    break
                }
            }
        }

        if (-not $outputColumn) {
            Write-Warning "Could not identify the detection output column. Available columns:"
            Write-Warning ($columnNames -join ', ')
            return
        }

        Write-Host "Using output column: $($outputColumn)"

        # Identify device name column
        $deviceColumn = $null
        $deviceCandidates = @('DeviceName', 'Device name', 'deviceName', 'ManagedDeviceName', 'Device')
        foreach ($candidate in $deviceCandidates) {
            if ($columnNames -contains $candidate) {
                $deviceColumn = $candidate
                break
            }
        }

        Write-Host ""

        # Parse each device record
        $currentRecord = 0
        $totalRecords = $csvData.Count
        foreach ($row in $csvData) {
            $currentRecord++
            if ($currentRecord % 500 -eq 0 -or $currentRecord -eq $totalRecords) {
                Write-Progress -Activity "Parsing detection output" -Status "Record $($currentRecord) of $($totalRecords)" -PercentComplete (($currentRecord / $totalRecords) * 100)
            }

            $detectionOutput = $row.$outputColumn
            if (-not $detectionOutput) { continue }

            # Only parse non-compliant records (those with "NON-COMPLIANT" status)
            if ($detectionOutput -notmatch 'NON-COMPLIANT') { continue }
            $NonCompliantCount++

            $deviceName = if ($deviceColumn) { $row.$deviceColumn } else { "Unknown-$($currentRecord)" }

            # Split pipe-delimited output and parse detected applications
            $segments = $detectionOutput -split '\s*\|\s*'

            foreach ($segment in $segments) {
                # Match pattern: [Method] AppName @ Path
                if ($segment -match '^\[(.+?)\]\s+(.+?)\s+@\s+(.+)$') {
                    $method = $Matches[1].Trim()
                    $appName = $Matches[2].Trim()
                    $appPath = $Matches[3].Trim()

                    [void]$ParsedApps.Add([PSCustomObject]@{
                        DeviceName = $deviceName
                        Method = $method
                        AppName = $appName
                        AppPath = $appPath
                    })
                }
            }
        }

        Write-Progress -Activity "Parsing detection output" -Completed

        # Apply post-filter to remove system-level and managed runtime paths
        if ($PostFilter) {
            $preFilterCount = $ParsedApps.Count
            $filteredApps = New-Object -TypeName "System.Collections.Generic.List[System.Object]"
            foreach ($app in $ParsedApps) {
                if ($app.AppPath -notlike '*\System32\*' -and
                    $app.AppPath -notlike '*\SysWOW64\*' -and
                    $app.AppPath -notlike '*\WinSxS\*' -and
                    $app.AppPath -notlike '*\Microsoft Office\root\*' -and
                    $app.AppPath -ne 'N/A') {
                    [void]$filteredApps.Add($app)
                }
            }
            $ParsedApps = $filteredApps
            $removedCount = $preFilterCount - $ParsedApps.Count
            Write-Host "Post-filter removed $($removedCount) system/managed entries (System32, SysWOW64, WinSxS, Office C2R)"
        }

        if ($ParsedApps.Count -eq 0) {
            Write-Host "No legacy VC++ dependent applications found in the report."
            return
        }

        # Build unique application summary using hashtable for performance
        Write-Host "Summarising applications..."
        $appIndex = @{}
        $currentRecord = 0
        $totalRecords = $ParsedApps.Count
        foreach ($entry in $ParsedApps) {
            $currentRecord++
            if ($currentRecord % 2000 -eq 0) {
                Write-Progress -Activity "Building application summary" -Status "Entry $($currentRecord) of $($totalRecords)" -PercentComplete (($currentRecord / $totalRecords) * 100)
            }

            $key = "$($entry.AppName)|$($entry.AppPath)"
            if (-not $appIndex.ContainsKey($key)) {
                $appIndex[$key] = @{
                    AppName = $entry.AppName
                    AppPath = $entry.AppPath
                    Devices = New-Object -TypeName "System.Collections.Generic.HashSet[string]"
                    Methods = New-Object -TypeName "System.Collections.Generic.HashSet[string]"
                }
            }
            [void]$appIndex[$key].Devices.Add($entry.DeviceName)
            [void]$appIndex[$key].Methods.Add($entry.Method)
        }
        Write-Progress -Activity "Building application summary" -Completed

        $uniqueApps = New-Object -TypeName "System.Collections.Generic.List[System.Object]"
        foreach ($app in $appIndex.Values) {
            [void]$uniqueApps.Add([PSCustomObject]@{
                AppName = $app.AppName
                AppPath = $app.AppPath
                DetectionMethod = ($app.Methods -join ', ')
                DeviceCount = $app.Devices.Count
                Devices = ($app.Devices -join '; ')
            })
        }
        $uniqueApps = $uniqueApps | Sort-Object -Property DeviceCount -Descending

        # Display summary
        Write-Host "=== Legacy VC++ Dependent Applications ===" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Total non-compliant devices: $($NonCompliantCount) / $($DeviceCount)"
        Write-Host "Unique applications found: $($uniqueApps.Count)"
        Write-Host ""

        # Display application table
        $uniqueApps | Format-Table -Property @(
            @{ Label = 'Application'; Expression = { $_.AppName }; Width = 35 }
            @{ Label = 'Path'; Expression = { $_.AppPath }; Width = 55 }
            @{ Label = 'Method'; Expression = { $_.DetectionMethod }; Width = 30 }
            @{ Label = 'Devices'; Expression = { $_.DeviceCount }; Width = 7 }
        ) -Wrap

        # Per-device breakdown
        if ($Detailed) {
            Write-Host ""
            Write-Host "=== Per-Device Breakdown ===" -ForegroundColor Cyan
            Write-Host ""

            $perDevice = $ParsedApps | Group-Object -Property DeviceName
            foreach ($device in $perDevice) {
                Write-Host "  $($device.Name):" -ForegroundColor Yellow
                foreach ($app in $device.Group) {
                    Write-Host "    [$($app.Method)] $($app.AppName) @ $($app.AppPath)"
                }
                Write-Host ""
            }
        }

        # Export to CSV if output path specified
        if ($OutputPath) {
            $uniqueApps | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "Results exported to: $($OutputPath)"
        }
    }
    catch [System.Exception] {
        $ErrorCount++
        Write-Warning "Error processing CSV: $($_.Exception.Message)"
    }
}

End {
    $Timer.Stop()
    Write-Host ""
    Write-Host "Parsing completed in $($Timer.Elapsed.TotalSeconds.ToString('F2')) seconds. Errors: $($ErrorCount)" -ForegroundColor Green
}
