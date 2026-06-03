<#
.SYNOPSIS
    Analyses a DotNet6 dependencies CSV and produces a prioritised vendor/app impact report.

.DESCRIPTION
    This script processes the CSV output from Parse-DotNet6Report.ps1 and produces
    actionable conclusions for .NET 6.x remediation planning:
    - Top applications by device count
    - Detection method breakdown
    - Vendor grouping with impact ranking
    - High-impact applications above a configurable threshold

.PARAMETER CsvPath
    Path to the DotNet6 dependencies CSV file (output from Parse-DotNet6Report.ps1).

.PARAMETER Threshold
    Minimum device count to include in the high-impact report. Defaults to 500.

.PARAMETER Top
    Number of top applications to display in the summary. Defaults to 20.

.PARAMETER OutputPath
    Optional path for an analysis report CSV export.

.EXAMPLE
    .\Analyze-DotNet6Report.ps1 -CsvPath "C:\Users\user\Downloads\DotNet6-dependencies.csv"

.EXAMPLE
    .\Analyze-DotNet6Report.ps1 -CsvPath ".\DotNet6Apps.csv" -Threshold 100 -Top 30

.EXAMPLE
    .\Analyze-DotNet6Report.ps1 -CsvPath ".\DotNet6Apps.csv" -OutputPath ".\Analysis.csv"

.NOTES
    FileName: Analyze-DotNet6Report.ps1
    Author: Anders Ahl
    Created: 2026-06-02
    Updated: 2026-06-02
    Version: 1.0.0
    Requires: PowerShell 5.1 or higher
    Use Case: Post-processing analysis of Parse-DotNet6Report.ps1 output

    Version history:
    1.0.0 - Initial release
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the DotNet6 dependencies CSV file.")]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath,

    [Parameter(Mandatory = $false, HelpMessage = "Minimum device count for high-impact report.")]
    [ValidateRange(1, 100000)]
    [int]$Threshold = 500,

    [Parameter(Mandatory = $false, HelpMessage = "Number of top applications to display.")]
    [ValidateRange(1, 500)]
    [int]$Top = 20,

    [Parameter(Mandatory = $false, HelpMessage = "Optional path for analysis report CSV export.")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Begin {
    $Timer = [System.Diagnostics.Stopwatch]::StartNew()
    $ErrorCount = 0

    function Get-VendorFromPath {
        param([string]$AppPath)

        # Extract vendor from the first subfolder under Program Files / Program Files (x86)
        if ($AppPath -match '^[A-Z]:\\Program Files(?: \(x86\))?\\([^\\]+)') {
            return $Matches[1]
        }

        # Fallback: try ProgramData or Users\*\AppData\Local
        if ($AppPath -match '^[A-Z]:\\ProgramData\\([^\\]+)') {
            return $Matches[1]
        }
        if ($AppPath -match '\\AppData\\(?:Local|Roaming)\\([^\\]+)') {
            return $Matches[1]
        }

        return "Other"
    }

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
        $csv = Import-Csv -Path $CsvPath -ErrorAction Stop
        Write-Host "Loaded $($csv.Count) unique application entries"
        Write-Host ""

        # === Detection Method Breakdown ===
        Write-Host "=== Detection Method Breakdown ===" -ForegroundColor Cyan
        Write-Host ""
        $methodGroups = $csv | Group-Object -Property DetectionMethod | Sort-Object Count -Descending
        foreach ($group in $methodGroups) {
            Write-Host "  $($group.Name): $($group.Count) apps"
        }
        Write-Host ""

        # === Vendor Grouping ===
        Write-Host "=== Vendor Impact Analysis ===" -ForegroundColor Cyan
        Write-Host ""

        $vendorMap = @{}
        foreach ($app in $csv) {
            $vendor = Get-VendorFromPath -AppPath $app.AppPath

            if (-not $vendorMap.ContainsKey($vendor)) {
                $vendorMap[$vendor] = New-Object -TypeName "System.Collections.Generic.List[System.Object]"
            }
            [void]$vendorMap[$vendor].Add($app)
        }

        $vendorSummary = New-Object -TypeName "System.Collections.Generic.List[System.Object]"
        foreach ($entry in $vendorMap.GetEnumerator()) {
            $maxDevices = 0
            $totalDeviceHits = 0
            foreach ($app in $entry.Value) {
                $dc = [int]$app.DeviceCount
                $totalDeviceHits += $dc
                if ($dc -gt $maxDevices) { $maxDevices = $dc }
            }
            [void]$vendorSummary.Add([PSCustomObject]@{
                Vendor = $entry.Key
                UniqueApps = $entry.Value.Count
                MaxDeviceCount = $maxDevices
                TotalDeviceHits = $totalDeviceHits
            })
        }
        $vendorSummary = $vendorSummary | Sort-Object -Property TotalDeviceHits -Descending

        $vendorSummary | Format-Table -Property @(
            @{ Label = 'Vendor'; Expression = { $_.Vendor }; Width = 16 }
            @{ Label = 'Unique Apps'; Expression = { $_.UniqueApps }; Width = 11 }
            @{ Label = 'Max Devices'; Expression = { $_.MaxDeviceCount }; Width = 11 }
            @{ Label = 'Total Hits'; Expression = { $_.TotalDeviceHits }; Width = 12 }
        )

        # === Top N Applications ===
        Write-Host "=== Top $($Top) Applications by Device Count ===" -ForegroundColor Cyan
        Write-Host ""

        $topApps = $csv | Sort-Object { [int]$_.DeviceCount } -Descending | Select-Object -First $Top
        $topApps | Format-Table -Property @(
            @{ Label = 'Application'; Expression = { $_.AppName }; Width = 40 }
            @{ Label = 'Devices'; Expression = { $_.DeviceCount }; Width = 8 }
            @{ Label = 'Method'; Expression = { $_.DetectionMethod }; Width = 22 }
            @{ Label = 'Path'; Expression = { $_.AppPath }; Width = 60 }
        ) -Wrap

        # === High-Impact Applications ===
        $highImpact = $csv | Where-Object { [int]$_.DeviceCount -ge $Threshold } | Sort-Object { [int]$_.DeviceCount } -Descending
        Write-Host "=== High-Impact Applications ($($Threshold)+ devices): $($highImpact.Count) apps ===" -ForegroundColor Cyan
        Write-Host ""

        if ($highImpact.Count -gt 0) {
            $highImpact | Format-Table -Property @(
                @{ Label = 'Application'; Expression = { $_.AppName }; Width = 40 }
                @{ Label = 'Devices'; Expression = { $_.DeviceCount }; Width = 8 }
                @{ Label = 'Method'; Expression = { $_.DetectionMethod }; Width = 22 }
                @{ Label = 'Path'; Expression = { $_.AppPath }; Width = 70 }
            ) -Wrap
        }
        else {
            Write-Host "  No applications found on $($Threshold)+ devices."
        }

        # === Summary Statistics ===
        Write-Host ""
        Write-Host "=== Summary ===" -ForegroundColor Cyan
        Write-Host ""
        $totalDevices = ($csv | Measure-Object -Property DeviceCount -Maximum).Maximum
        $totalApps = $csv.Count
        Write-Host "  Total unique app/path combinations: $($totalApps)"
        Write-Host "  Highest single-app device count: $($totalDevices)"
        Write-Host "  Apps on $($Threshold)+ devices: $($highImpact.Count)"
        Write-Host "  Vendors identified: $($vendorSummary.Count)"
        Write-Host ""

        # Export if output path specified
        if ($OutputPath) {
            $exportData = New-Object -TypeName "System.Collections.Generic.List[System.Object]"
            foreach ($app in ($csv | Sort-Object { [int]$_.DeviceCount } -Descending)) {
                $vendor = Get-VendorFromPath -AppPath $app.AppPath
                [void]$exportData.Add([PSCustomObject]@{
                    Vendor = $vendor
                    AppName = $app.AppName
                    AppPath = $app.AppPath
                    DetectionMethod = $app.DetectionMethod
                    DeviceCount = [int]$app.DeviceCount
                    HighImpact = if ([int]$app.DeviceCount -ge $Threshold) { "Yes" } else { "No" }
                })
            }
            $exportData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "Analysis exported to: $($OutputPath)"
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
    Write-Host "Analysis completed in $($Timer.Elapsed.TotalSeconds.ToString('F2')) seconds. Errors: $($ErrorCount)" -ForegroundColor Green
}
