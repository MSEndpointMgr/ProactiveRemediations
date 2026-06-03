<#
.SYNOPSIS
    Detection script for applications that rely on .NET 6.x runtime.

.DESCRIPTION
    This script detects applications that depend on .NET 6.x (any 6.x.x version) on Windows
    devices for use with Microsoft Intune Remediations. It checks for:
    - Applications with runtimeconfig.json files targeting .NET 6.x
    - NuGet package references to .NET 6.x in deps.json files
    - Self-contained applications with .NET 6.x runtime bundled in the binary (coreclr.dll)
    - Single-file published applications with embedded .NET 6.x framework references
    - Registered .NET 6.x dependent applications in Uninstall registry keys

    .NET 6 reached end-of-life on November 12, 2024. Applications targeting this
    runtime should be upgraded to a supported LTS version (.NET 8 or later).

    Exit Codes:
    - 0: No applications depending on .NET 6.x detected (compliant/no remediation needed)
    - 1: Applications depending on .NET 6.x detected (remediation needed)

.NOTES
    FileName: Detect-DotNet6Apps.ps1
    Author: Anders Ahl
    Created: 2026-06-01
    Updated: 2026-06-02
    Version: 1.3.0
    Requires: PowerShell 5.1 or higher
    Use Case: Microsoft Intune Remediations - Detection Script

    Version history:
    1.3.0 - Excluded dotnet shared/sdk directories from runtimeconfig and deps.json scans;
            added bundle signature pre-filter for single-file detection
    1.2.0 - Added single-file binary detection via embedded framework string scanning
    1.1.0 - Removed standalone runtime detection; added self-contained binary detection
    1.0.0 - Initial release

    Microsoft Documentation:
    https://learn.microsoft.com/intune/intune-service/fundamentals/remediations
    https://dotnet.microsoft.com/platform/support/policy/dotnet-core
#>

[CmdletBinding()]
param()

# Microsoft Intune timeout limits
$SCRIPT_TIMEOUT_SECONDS = 170  # 3-minute limit with 10-second buffer for cleanup
$scriptStartTime = Get-Date

# Initialize detection results
$detectionResults = @{
    RuntimeConfigApps    = 0
    DepsJsonApps         = 0
    SelfContainedApps    = 0
    SingleFileApps       = 0
    RegistryApps         = 0
}

# Maximum output size allowed by Intune
$MAX_OUTPUT_SIZE = 2048

# Collection for all output messages (to be emitted at the end)
$outputMessages = [System.Collections.ArrayList]@()

# Collection for detected application details
$detectedApps = [System.Collections.ArrayList]@()

#region Detection Functions

function Test-ScriptTimeout {
    <#
    .SYNOPSIS
        Checks if script has reached timeout limit.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $elapsedSeconds = ((Get-Date) - $scriptStartTime).TotalSeconds
    return ($elapsedSeconds -ge $SCRIPT_TIMEOUT_SECONDS)
}

function Invoke-MajorDetectionCheck {
    <#
    .SYNOPSIS
        Runs one major detection check if timeout has not been reached.
    #>
    [CmdletBinding()]
    [OutputType([int], [hashtable], [object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckName,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DefaultValue = 0
    )

    if (Test-ScriptTimeout) {
        [void]$outputMessages.Add("NOTICE: Skipped $($CheckName) due to timeout")
        return $DefaultValue
    }

    return (& $Action)
}

function Find-DotNet6RuntimeConfigApps {
    <#
    .SYNOPSIS
        Scans Program Files for runtimeconfig.json files that target .NET 6.x.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $foundCount = 0
    $searchPaths = @(
        "$($env:ProgramFiles)",
        "${env:ProgramFiles(x86)}"
    )

    foreach ($searchPath in $searchPaths) {
        if (Test-ScriptTimeout) {
            [void]$outputMessages.Add("NOTICE: RuntimeConfig scan stopped due to timeout")
            break
        }

        if (-not (Test-Path -Path $searchPath -ErrorAction SilentlyContinue)) {
            continue
        }

        try {
            $configFiles = Get-ChildItem -Path $searchPath -Recurse -Filter '*.runtimeconfig.json' -ErrorAction SilentlyContinue | Where-Object {
                $_.FullName -notlike '*\dotnet\shared\*' -and
                $_.FullName -notlike '*\dotnet\sdk\*'
            }

            foreach ($file in $configFiles) {
                if (Test-ScriptTimeout) {
                    [void]$outputMessages.Add("NOTICE: RuntimeConfig file scan stopped due to timeout")
                    break
                }

                try {
                    $jsonContent = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                    if (-not $jsonContent) { continue }

                    $config = $jsonContent | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if (-not $config) { continue }

                    $targetsDotNet6 = $false

                    # Check runtimeOptions.framework (single framework reference)
                    if ($config.runtimeOptions -and $config.runtimeOptions.framework) {
                        if ($config.runtimeOptions.framework.version -like '6.*') {
                            $targetsDotNet6 = $true
                        }
                    }

                    # Check runtimeOptions.frameworks (multiple framework references)
                    if (-not $targetsDotNet6 -and $config.runtimeOptions -and $config.runtimeOptions.frameworks) {
                        foreach ($fw in $config.runtimeOptions.frameworks) {
                            if ($fw.version -like '6.*') {
                                $targetsDotNet6 = $true
                                break
                            }
                        }
                    }

                    # Check runtimeOptions.tfm (target framework moniker)
                    if (-not $targetsDotNet6 -and $config.runtimeOptions -and $config.runtimeOptions.tfm) {
                        if ($config.runtimeOptions.tfm -eq 'net6.0' -or $config.runtimeOptions.tfm -like 'net6.0-*') {
                            $targetsDotNet6 = $true
                        }
                    }

                    if ($targetsDotNet6) {
                        $appName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name) -replace '\.runtimeconfig$', ''
                        $appDir = $file.DirectoryName
                        [void]$detectedApps.Add([PSCustomObject]@{
                            Name   = $appName
                            Path   = $appDir
                            Method = 'runtimeconfig.json'
                        })
                        $foundCount++
                    }
                }
                catch {
                    Write-Verbose "Error parsing $($file.FullName): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Verbose "Error scanning $($searchPath): $($_.Exception.Message)"
        }
    }

    if ($foundCount -gt 0) {
        [void]$outputMessages.Add("RuntimeConfig: $($foundCount) app(s) targeting .NET 6.x")
    }

    return $foundCount
}

function Find-DotNet6DepsJsonApps {
    <#
    .SYNOPSIS
        Scans Program Files for .deps.json files referencing .NET 6.x runtime libraries.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $foundCount = 0
    $searchPaths = @(
        "$($env:ProgramFiles)",
        "${env:ProgramFiles(x86)}"
    )

    foreach ($searchPath in $searchPaths) {
        if (Test-ScriptTimeout) {
            [void]$outputMessages.Add("NOTICE: DepsJson scan stopped due to timeout")
            break
        }

        if (-not (Test-Path -Path $searchPath -ErrorAction SilentlyContinue)) {
            continue
        }

        try {
            $depsFiles = Get-ChildItem -Path $searchPath -Recurse -Filter '*.deps.json' -ErrorAction SilentlyContinue | Where-Object {
                $_.FullName -notlike '*\dotnet\shared\*' -and
                $_.FullName -notlike '*\dotnet\sdk\*'
            }

            foreach ($file in $depsFiles) {
                if (Test-ScriptTimeout) {
                    [void]$outputMessages.Add("NOTICE: DepsJson file scan stopped due to timeout")
                    break
                }

                try {
                    $jsonContent = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                    if (-not $jsonContent) { continue }

                    # Use string matching for .deps.json as these files can be very large
                    # Look for .NETCoreApp,Version=v6.0 target framework reference
                    $targetsDotNet6 = $false

                    if ($jsonContent -match '\.NETCoreApp,Version=v6\.\d+') {
                        $targetsDotNet6 = $true
                    }
                    elseif ($jsonContent -match '"runtimeTarget"[^}]*"net6\.0') {
                        $targetsDotNet6 = $true
                    }

                    if ($targetsDotNet6) {
                        $appName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name) -replace '\.deps$', ''

                        # Avoid duplicate detection if runtimeconfig.json already found this app
                        $alreadyDetected = $false
                        foreach ($existing in $detectedApps) {
                            if ($existing.Name -eq $appName -and $existing.Path -eq $file.DirectoryName) {
                                $alreadyDetected = $true
                                break
                            }
                        }

                        if (-not $alreadyDetected) {
                            [void]$detectedApps.Add([PSCustomObject]@{
                                Name   = $appName
                                Path   = $file.DirectoryName
                                Method = 'deps.json'
                            })
                            $foundCount++
                        }
                    }
                }
                catch {
                    Write-Verbose "Error parsing $($file.FullName): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Verbose "Error scanning $($searchPath): $($_.Exception.Message)"
        }
    }

    if ($foundCount -gt 0) {
        [void]$outputMessages.Add("DepsJson: $($foundCount) additional app(s) targeting .NET 6.x")
    }

    return $foundCount
}

function Find-DotNet6SelfContainedApps {
    <#
    .SYNOPSIS
        Scans Program Files for self-contained .NET 6.x applications by detecting
        bundled runtime binaries (coreclr.dll, hostfxr.dll) with file version 6.x.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $foundCount = 0
    $searchPaths = @(
        "$($env:ProgramFiles)",
        "${env:ProgramFiles(x86)}"
    )

    foreach ($searchPath in $searchPaths) {
        if (Test-ScriptTimeout) {
            [void]$outputMessages.Add("NOTICE: Self-contained binary scan stopped due to timeout")
            break
        }

        if (-not (Test-Path -Path $searchPath -ErrorAction SilentlyContinue)) {
            continue
        }

        try {
            # Search for coreclr.dll -- the primary runtime binary present in self-contained apps
            $coreclrFiles = Get-ChildItem -Path $searchPath -Recurse -Filter 'coreclr.dll' -ErrorAction SilentlyContinue

            foreach ($file in $coreclrFiles) {
                if (Test-ScriptTimeout) {
                    [void]$outputMessages.Add("NOTICE: Self-contained binary file scan stopped due to timeout")
                    break
                }

                try {
                    # Skip the shared dotnet runtime directory (framework-dependent installs live there)
                    if ($file.FullName -like '*\dotnet\shared\*') { continue }

                    $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
                    if (-not $fileVersion.FileVersion) { continue }

                    # Check if file version is 6.x
                    if ($fileVersion.FileVersion -match '^6\.\d+') {
                        $appDir = $file.DirectoryName

                        # Avoid duplicates with previously detected apps
                        $alreadyDetected = $false
                        foreach ($existing in $detectedApps) {
                            if ($existing.Path -eq $appDir) {
                                $alreadyDetected = $true
                                break
                            }
                        }

                        if (-not $alreadyDetected) {
                            # Try to determine app name from exe in same directory
                            $appExe = Get-ChildItem -Path $appDir -Filter '*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'createdump.exe' } | Select-Object -First 1
                            $appName = if ($appExe) {
                                [System.IO.Path]::GetFileNameWithoutExtension($appExe.Name)
                            } else {
                                Split-Path -Path $appDir -Leaf
                            }

                            [void]$detectedApps.Add([PSCustomObject]@{
                                Name   = $appName
                                Path   = $appDir
                                Method = 'Self-contained binary'
                            })
                            $foundCount++
                        }
                    }
                }
                catch {
                    Write-Verbose "Error inspecting $($file.FullName): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Verbose "Error scanning $($searchPath) for self-contained binaries: $($_.Exception.Message)"
        }
    }

    if ($foundCount -gt 0) {
        [void]$outputMessages.Add("Self-contained: $($foundCount) app(s) with bundled .NET 6.x runtime")
    }

    return $foundCount
}

function Test-DotNetSingleFileBundle {
    <#
    .SYNOPSIS
        Checks whether an exe file is a .NET single-file bundle by reading the bundle
        signature from the end of the file.
    .DESCRIPTION
        .NET single-file bundles store a 32-byte signature (SHA-256 of ".net core bundle\0")
        near the end of the file. The layout from EOF is:
        - Last 12 bytes: [Int64 headerOffset][Int32 unused/reserved]
        - Preceding 32 bytes: bundle signature hash
        Total: last 44 bytes contain the bundle marker.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    # .NET single-file bundle signature: SHA-256 of ".net core bundle\0"
    # This is a fixed constant in the .NET runtime source (Microsoft.NET.HostModel)
    $bundleSignature = [byte[]]@(
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
        0x72, 0x7b, 0x03, 0xd3, 0x9c, 0x11, 0x97, 0xa4,
        0x40, 0x8c, 0x0f, 0xe6, 0xe5, 0x77, 0x4d, 0x0c,
        0x02, 0x32, 0x1a, 0x14, 0x88, 0x04, 0x00, 0x00
    )

    $trailerSize = 44  # 32 bytes signature + 8 bytes headerOffset + 4 bytes reserved
    $fileStream = $null

    try {
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        if ($fileStream.Length -lt $trailerSize) { return $false }

        # Seek to the signature position (44 bytes from end)
        $fileStream.Seek(-$trailerSize, [System.IO.SeekOrigin]::End) | Out-Null

        # Read the 32-byte signature
        $sigBuffer = New-Object byte[] 32
        $read = $fileStream.Read($sigBuffer, 0, 32)
        if ($read -ne 32) { return $false }

        # Compare with expected bundle signature
        for ($i = 0; $i -lt 32; $i++) {
            if ($sigBuffer[$i] -ne $bundleSignature[$i]) {
                return $false
            }
        }

        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($fileStream) { $fileStream.Close() }
    }
}

function Find-DotNet6SingleFileApps {
    <#
    .SYNOPSIS
        Detects single-file published .NET 6.x applications by verifying the bundle
        signature and scanning for embedded framework version strings.
    .DESCRIPTION
        Single-file .NET apps bundle runtimeconfig.json and deps.json inside the exe.
        This function first validates the exe is a genuine .NET single-file bundle by
        checking the 32-byte bundle signature at the end of the file, then scans the
        binary for the framework version string (.NETCoreApp,Version=v6.x).
        Only scans exe files that were not already detected by other methods.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $foundCount = 0
    $searchPaths = @(
        "$($env:ProgramFiles)",
        "${env:ProgramFiles(x86)}"
    )

    # Target string embedded in deps.json content within single-file bundles
    $searchBytes = [System.Text.Encoding]::UTF8.GetBytes('.NETCoreApp,Version=v6.')
    $chunkSize = 65536  # 64 KB read chunks

    foreach ($searchPath in $searchPaths) {
        if (Test-ScriptTimeout) {
            [void]$outputMessages.Add("NOTICE: Single-file binary scan stopped due to timeout")
            break
        }

        if (-not (Test-Path -Path $searchPath -ErrorAction SilentlyContinue)) {
            continue
        }

        try {
            # Get exe files; skip dotnet SDK/runtime directories and small files
            $exeFiles = Get-ChildItem -Path $searchPath -Recurse -Filter '*.exe' -Depth 4 -ErrorAction SilentlyContinue | Where-Object {
                $_.Length -gt 500KB -and
                $_.FullName -notlike '*\dotnet\*' -and
                $_.FullName -notlike '*\Windows Kits\*'
            }

            foreach ($file in $exeFiles) {
                if (Test-ScriptTimeout) {
                    [void]$outputMessages.Add("NOTICE: Single-file exe scan stopped due to timeout")
                    break
                }

                try {
                    $appDir = $file.DirectoryName

                    # Skip if this directory was already detected by other methods
                    $alreadyDetected = $false
                    foreach ($existing in $detectedApps) {
                        if ($existing.Path -eq $appDir) {
                            $alreadyDetected = $true
                            break
                        }
                    }
                    if ($alreadyDetected) { continue }

                    # Skip if runtimeconfig.json or coreclr.dll exists (already caught)
                    $appBaseName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                    $runtimeConfigPath = [System.IO.Path]::Combine($appDir, "$($appBaseName).runtimeconfig.json")
                    if (Test-Path -Path $runtimeConfigPath -ErrorAction SilentlyContinue) { continue }
                    if (Test-Path -Path ([System.IO.Path]::Combine($appDir, 'coreclr.dll')) -ErrorAction SilentlyContinue) { continue }

                    # Quick check: verify this is a .NET single-file bundle before full scan
                    if (-not (Test-DotNetSingleFileBundle -FilePath $file.FullName)) { continue }

                    # Confirmed single-file bundle -- scan for .NET 6.x framework string
                    $fileStream = $null
                    $containsDotNet6 = $false
                    try {
                        $fileStream = [System.IO.File]::OpenRead($file.FullName)
                        $buffer = New-Object byte[] ($chunkSize + $searchBytes.Length)
                        $overlap = $searchBytes.Length - 1

                        while (($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                            # Search buffer for target bytes
                            $limit = $bytesRead - $searchBytes.Length
                            for ($i = 0; $i -le $limit; $i++) {
                                if ($buffer[$i] -eq $searchBytes[0]) {
                                    $match = $true
                                    for ($j = 1; $j -lt $searchBytes.Length; $j++) {
                                        if ($buffer[$i + $j] -ne $searchBytes[$j]) {
                                            $match = $false
                                            break
                                        }
                                    }
                                    if ($match) {
                                        $containsDotNet6 = $true
                                        break
                                    }
                                }
                            }

                            if ($containsDotNet6) { break }

                            # Seek back by overlap to avoid missing matches at chunk boundaries
                            if ($bytesRead -eq $buffer.Length) {
                                $fileStream.Seek(-$overlap, [System.IO.SeekOrigin]::Current) | Out-Null
                            }
                        }
                    }
                    finally {
                        if ($fileStream) { $fileStream.Close() }
                    }

                    if ($containsDotNet6) {
                        [void]$detectedApps.Add([PSCustomObject]@{
                            Name   = $appBaseName
                            Path   = $appDir
                            Method = 'Single-file binary'
                        })
                        $foundCount++
                    }
                }
                catch {
                    Write-Verbose "Error inspecting single-file exe $($file.FullName): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Verbose "Error scanning $($searchPath) for single-file binaries: $($_.Exception.Message)"
        }
    }

    if ($foundCount -gt 0) {
        [void]$outputMessages.Add("Single-file: $($foundCount) app(s) with embedded .NET 6.x framework")
    }

    return $foundCount
}

function Find-DotNet6RegistryApps {
    <#
    .SYNOPSIS
        Scans Uninstall registry keys for applications that reference .NET 6.x in their
        install location and contain .NET 6.x runtime artifacts.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $foundCount = 0
    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $uninstallPaths) {
        if (Test-ScriptTimeout) {
            [void]$outputMessages.Add("NOTICE: Registry scan stopped due to timeout")
            break
        }

        try {
            $keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue

            foreach ($key in $keys) {
                try {
                    $properties = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue

                    if (-not $properties.DisplayName) { continue }
                    if (-not $properties.InstallLocation) { continue }

                    $installLocation = $properties.InstallLocation
                    if (-not (Test-Path -Path $installLocation -ErrorAction SilentlyContinue)) { continue }

                    # Check if install location contains runtimeconfig.json targeting .NET 6
                    $runtimeConfigs = Get-ChildItem -Path $installLocation -Filter '*.runtimeconfig.json' -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 3

                    foreach ($configFile in $runtimeConfigs) {
                        try {
                            $jsonContent = Get-Content -Path $configFile.FullName -Raw -ErrorAction SilentlyContinue
                            if (-not $jsonContent) { continue }

                            $config = $jsonContent | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if (-not $config) { continue }

                            $targetsDotNet6 = $false

                            if ($config.runtimeOptions -and $config.runtimeOptions.framework) {
                                if ($config.runtimeOptions.framework.version -like '6.*') {
                                    $targetsDotNet6 = $true
                                }
                            }

                            if (-not $targetsDotNet6 -and $config.runtimeOptions -and $config.runtimeOptions.frameworks) {
                                foreach ($fw in $config.runtimeOptions.frameworks) {
                                    if ($fw.version -like '6.*') {
                                        $targetsDotNet6 = $true
                                        break
                                    }
                                }
                            }

                            if ($targetsDotNet6) {
                                $appName = $properties.DisplayName
                                $appVersion = $properties.DisplayVersion

                                # Avoid duplicates
                                $alreadyDetected = $false
                                foreach ($existing in $detectedApps) {
                                    if ($existing.Path -eq $installLocation) {
                                        $alreadyDetected = $true
                                        break
                                    }
                                }

                                if (-not $alreadyDetected) {
                                    [void]$detectedApps.Add([PSCustomObject]@{
                                        Name   = $appName
                                        Path   = $installLocation
                                        Method = 'Registry'
                                    })
                                    [void]$outputMessages.Add("Registry app: $($appName) v$($appVersion)")
                                    $foundCount++
                                }
                                break  # No need to check more configs for this app
                            }
                        }
                        catch {
                            Write-Verbose "Error parsing registry app config: $($_.Exception.Message)"
                        }
                    }
                }
                catch {
                    Write-Verbose "Skipped registry key due to error: $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Verbose "Error reading registry path $($path): $($_.Exception.Message)"
        }
    }

    return $foundCount
}

#endregion

#region Main Detection Logic

[void]$outputMessages.Add("=== .NET 6.x Application Detection Started ===")

# Check 1: RuntimeConfig.json scan
$detectionResults.RuntimeConfigApps = Invoke-MajorDetectionCheck -CheckName "RuntimeConfig Apps" -Action { Find-DotNet6RuntimeConfigApps }

# Check 2: Deps.json scan
$detectionResults.DepsJsonApps = Invoke-MajorDetectionCheck -CheckName "DepsJson Apps" -Action { Find-DotNet6DepsJsonApps }

# Check 3: Self-contained binary scan
$detectionResults.SelfContainedApps = Invoke-MajorDetectionCheck -CheckName "Self-contained Apps" -Action { Find-DotNet6SelfContainedApps }

# Check 4: Single-file binary scan
$detectionResults.SingleFileApps = Invoke-MajorDetectionCheck -CheckName "Single-file Apps" -Action { Find-DotNet6SingleFileApps }

# Check 5: Registry-based application scan
$detectionResults.RegistryApps = Invoke-MajorDetectionCheck -CheckName "Registry Apps" -Action { Find-DotNet6RegistryApps }

# Calculate total findings
$totalAppFindings = $detectionResults.RuntimeConfigApps +
                    $detectionResults.DepsJsonApps +
                    $detectionResults.SelfContainedApps +
                    $detectionResults.SingleFileApps +
                    $detectionResults.RegistryApps

# Build summary output
[void]$outputMessages.Add("")
[void]$outputMessages.Add("=== Detection Summary ===")
[void]$outputMessages.Add("Apps (runtimeconfig.json): $($detectionResults.RuntimeConfigApps)")
[void]$outputMessages.Add("Apps (deps.json): $($detectionResults.DepsJsonApps)")
[void]$outputMessages.Add("Apps (self-contained): $($detectionResults.SelfContainedApps)")
[void]$outputMessages.Add("Apps (single-file): $($detectionResults.SingleFileApps)")
[void]$outputMessages.Add("Apps (Registry): $($detectionResults.RegistryApps)")
[void]$outputMessages.Add("Total App Findings: $($totalAppFindings)")

# List detected apps (limited to first 10 to conserve output space)
if ($detectedApps.Count -gt 0) {
    [void]$outputMessages.Add("")
    [void]$outputMessages.Add("=== Detected Applications ===")
    $appLimit = [Math]::Min($detectedApps.Count, 10)
    for ($i = 0; $i -lt $appLimit; $i++) {
        $app = $detectedApps[$i]
        [void]$outputMessages.Add("[$($app.Method)] $($app.Name) @ $($app.Path)")
    }
    if ($detectedApps.Count -gt 10) {
        [void]$outputMessages.Add("... and $($detectedApps.Count - 10) more")
    }
}

$duration = (Get-Date) - $scriptStartTime
[void]$outputMessages.Add(("Detection completed in {0:N1} second(s)" -f $duration.TotalSeconds))

$complianceStatus = if ($totalAppFindings -eq 0) {
    "COMPLIANT - No applications depending on .NET 6.x detected"
} else {
    "NON-COMPLIANT - $($totalAppFindings) application(s) depending on .NET 6.x detected"
}
[void]$outputMessages.Add("Status: $($complianceStatus)")

# Combine messages using pipe separator to reduce character count
$finalOutput = $outputMessages -join " | "

# Validate output size and truncate if necessary
if ($finalOutput.Length -gt $MAX_OUTPUT_SIZE) {
    $truncatedOutput = @(
        "=== .NET 6.x Application Detection (Output Truncated) ==="
        "=== Detection Summary ==="
        "Apps (runtimeconfig.json): $($detectionResults.RuntimeConfigApps)"
        "Apps (deps.json): $($detectionResults.DepsJsonApps)"
        "Apps (self-contained): $($detectionResults.SelfContainedApps)"
        "Apps (single-file): $($detectionResults.SingleFileApps)"
        "Apps (Registry): $($detectionResults.RegistryApps)"
        "Total App Findings: $($totalAppFindings)"
        "Status: $($complianceStatus)"
        "NOTE: Full details truncated due to Intune 2048 character limit."
    )

    $truncatedOutput = $truncatedOutput -join " | "

    if ($truncatedOutput.Length -gt $MAX_OUTPUT_SIZE) {
        $truncatedOutput = "[TRUNCATED] Detection: $($totalAppFindings) app(s), Status: $($complianceStatus)"
    }

    Write-Output $truncatedOutput
}
else {
    Write-Output $finalOutput
}

if ($totalAppFindings -eq 0) {
    exit 0  # Compliant - no remediation needed
}
else {
    exit 1  # Non-compliant - remediation needed
}

#endregion
