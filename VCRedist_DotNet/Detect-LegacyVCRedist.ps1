<#
.SYNOPSIS
    Detection script for applications that rely on unsupported legacy Visual C++ Redistributable runtimes.

.DESCRIPTION
    This script detects applications that depend on end-of-life Visual C++ Runtime
    libraries on Windows devices for use with Microsoft Intune Remediations. It checks for:
    - Installed legacy VC++ Redistributable packages via registry (VC++ 2005-2013)
    - Applications importing legacy VC runtime DLLs via PE Import Table analysis
    - App-local copies of legacy VC runtime DLLs deployed alongside applications
    - Side-by-Side (WinSxS) manifest references for VC++ 2005/2008 assemblies
    - Outdated VC++ 14.x (2015-2026) Redistributable packages that need updating

    Unsupported legacy versions targeted:
    - Visual Studio 2005 (VC++ 8.0)  - EOL April 12, 2016
    - Visual Studio 2008 (VC++ 9.0)  - EOL April 10, 2018
    - Visual Studio 2010 (VC++ 10.0) - EOL July 14, 2020
    - Visual Studio 2012 (VC++ 11.0) - EOL January 10, 2023
    - Visual Studio 2013 (VC++ 12.0) - EOL April 9, 2024

    Additionally detected (updatable, not EOL):
    - Visual Studio 2015-2026 (VC++ 14.x) - outdated redist package installed
      (Apps using vcruntime140.dll are binary-compatible; only the package needs updating)

    Exit Codes:
    - 0: No applications depending on unsupported VC++ runtimes detected (compliant)
    - 1: Applications depending on unsupported VC++ runtimes detected (non-compliant)

.NOTES
    FileName: Detect-LegacyVCRedist.ps1
    Author: Anders Ahl
    Created: 2026-06-02
    Updated: 2026-06-03
    Version: 1.4.0
    Requires: PowerShell 5.1 or higher
    Use Case: Microsoft Intune Remediations - Detection Script

    Version history:
    1.5.0 - Updated minimum V14 version to 14.51.36231.0 (VS 2026), added 2026 to regex match
    1.4.0 - Truncation deduplicates by app name (avoids wasting space on multi-exe apps)
    1.3.0 - Truncation now prioritises actionable app findings over installed redist entries
    1.2.0 - Added Office C2R path exclusion, improved truncated output with app names
    1.1.0 - Added Check 5: Outdated VC++ 14.x Redistributable detection
    1.0.0 - Initial release

    Microsoft Documentation:
    https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist
    https://learn.microsoft.com/cpp/windows/redist-version-auditing
#>

[CmdletBinding()]
param()

# Script version (keep in sync with .NOTES Version above)
$scriptVersion = '1.5.0'

# Microsoft Intune timeout limits
$SCRIPT_TIMEOUT_SECONDS = 170  # 3-minute limit with 10-second buffer for cleanup
$scriptStartTime = Get-Date

# Initialize detection results
$detectionResults = @{
    InstalledRedists  = 0
    PEImportApps      = 0
    AppLocalDlls      = 0
    SxSManifestApps   = 0
    OutdatedV14Redist = 0
}

# Minimum acceptable VC++ 14.x Redistributable version (build number)
# 14.51.36231.0 = VS 2026 18.x servicing update (May 2026)
# Update this value when a newer security-patched release is available.
$MINIMUM_V14_VERSION = [Version]'14.51.36231.0'

# Maximum output size allowed by Intune
$MAX_OUTPUT_SIZE = 2048

# Collection for all output messages (to be emitted at the end)
$outputMessages = [System.Collections.ArrayList]@()

# Collection for detected application details
$detectedApps = [System.Collections.ArrayList]@()

# Legacy VC runtime DLL patterns (unsupported versions only)
# VC++ 8.0 (2005): msvcr80, msvcp80
# VC++ 9.0 (2008): msvcr90, msvcp90
# VC++ 10.0 (2010): msvcr100, msvcp100
# VC++ 11.0 (2012): msvcr110, msvcp110, vccorlib110
# VC++ 12.0 (2013): msvcr120, msvcp120, vccorlib120
$legacyDllNames = @(
    'msvcr80.dll', 'msvcp80.dll',
    'msvcr90.dll', 'msvcp90.dll',
    'msvcr100.dll', 'msvcp100.dll',
    'msvcr110.dll', 'msvcp110.dll', 'vccorlib110.dll',
    'msvcr120.dll', 'msvcp120.dll', 'vccorlib120.dll'
)

# Regex for PE import table matching (version numbers 80-120)
$legacyDllRegex = '^(msvc[rp]|vccorlib)(80|90|100|110|120)\.dll$'


# Map DLL version number to VC++ version string
$versionMap = @{
    '80'  = 'VC++ 2005 (8.0)'
    '90'  = 'VC++ 2008 (9.0)'
    '100' = 'VC++ 2010 (10.0)'
    '110' = 'VC++ 2012 (11.0)'
    '120' = 'VC++ 2013 (12.0)'
}

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

function Get-VCVersionFromDll {
    <#
    .SYNOPSIS
        Extracts the VC++ version label from a legacy runtime DLL name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DllName
    )

    if ($DllName -match '(80|90|100|110|120)') {
        $verNum = $Matches[1]
        if ($versionMap.ContainsKey($verNum)) {
            return $versionMap[$verNum]
        }
    }
    return "Unknown"
}

function Find-InstalledLegacyRedists {
    <#
    .SYNOPSIS
        Scans registry for installed legacy Visual C++ Redistributable packages.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $foundCount = 0
    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    # Match patterns for legacy VC++ Redist display names
    $legacyPatterns = @(
        '*Visual C++ 2005*',
        '*Visual C++ 2008*',
        '*Visual C++ 2010*',
        '*Visual C++ 2012*',
        '*Visual C++ 2013*',
        '*Visual C++*Redistributable*8.0*',
        '*Visual C++*Redistributable*9.0*',
        '*Visual C++*Redistributable*10.0*',
        '*Visual C++*Redistributable*11.0*',
        '*Visual C++*Redistributable*12.0*'
    )

    foreach ($path in $uninstallPaths) {
        if (Test-ScriptTimeout) {
            [void]$outputMessages.Add("NOTICE: Registry redist scan stopped due to timeout")
            break
        }

        try {
            $keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue

            foreach ($key in $keys) {
                try {
                    $properties = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                    if (-not $properties.DisplayName) { continue }

                    $displayName = $properties.DisplayName
                    $isLegacy = $false

                    foreach ($pattern in $legacyPatterns) {
                        if ($displayName -like $pattern) {
                            $isLegacy = $true
                            break
                        }
                    }

                    if ($isLegacy) {
                        # Avoid duplicates (x64 and x86 entries may exist)
                        $alreadyDetected = $false
                        foreach ($existing in $detectedApps) {
                            if ($existing.Name -eq $displayName -and $existing.Method -eq 'Installed Redist') {
                                $alreadyDetected = $true
                                break
                            }
                        }

                        if (-not $alreadyDetected) {
                            $appVersion = $properties.DisplayVersion
                            [void]$detectedApps.Add([PSCustomObject]@{
                                Name   = $displayName
                                Path   = if ($properties.InstallLocation) { $properties.InstallLocation } else { "N/A" }
                                Method = 'Installed Redist'
                            })
                            [void]$outputMessages.Add("Installed: $($displayName) v$($appVersion)")
                            $foundCount++
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

function Get-PEImportedDlls {
    <#
    .SYNOPSIS
        Reads the PE Import Directory Table from an executable and returns imported DLL names.
    .DESCRIPTION
        Parses the PE header structure:
        1. DOS Header (e_lfanew at offset 0x3C)
        2. PE Signature + COFF Header
        3. Optional Header (to get Import Directory RVA and Section Table)
        4. Section Table (to convert RVA to file offset)
        5. Import Directory Table (to read DLL name strings)
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $importedDlls = @()
    $fileStream = $null
    $reader = $null

    try {
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $reader = New-Object System.IO.BinaryReader($fileStream)

        # DOS Header: check MZ signature
        $mzSig = $reader.ReadUInt16()
        if ($mzSig -ne 0x5A4D) { return $importedDlls }  # Not a valid PE

        # e_lfanew: offset to PE header (at DOS header offset 0x3C)
        $fileStream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $reader.ReadInt32()

        if ($peOffset -lt 0 -or $peOffset -gt ($fileStream.Length - 4)) { return $importedDlls }

        # PE Signature
        $fileStream.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peSig = $reader.ReadUInt32()
        if ($peSig -ne 0x00004550) { return $importedDlls }  # "PE\0\0"

        # COFF Header
        $reader.ReadUInt16() | Out-Null  # Machine
        $numberOfSections = $reader.ReadUInt16()
        $reader.ReadBytes(12) | Out-Null  # TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
        $sizeOfOptionalHeader = $reader.ReadUInt16()
        $reader.ReadUInt16() | Out-Null  # Characteristics

        if ($sizeOfOptionalHeader -eq 0) { return $importedDlls }

        # Optional Header
        $optionalHeaderStart = $fileStream.Position
        $magic = $reader.ReadUInt16()
        $is64Bit = ($magic -eq 0x20B)  # PE32+ = 64-bit

        # Navigate to Data Directories
        # For PE32: offset 96 from optional header start
        # For PE32+: offset 112 from optional header start
        if ($is64Bit) {
            $fileStream.Seek($optionalHeaderStart + 112, [System.IO.SeekOrigin]::Begin) | Out-Null
        }
        else {
            $fileStream.Seek($optionalHeaderStart + 96, [System.IO.SeekOrigin]::Begin) | Out-Null
        }

        # First data directory is Export Table (skip it)
        $reader.ReadBytes(8) | Out-Null

        # Second data directory is Import Table
        $importRva = $reader.ReadUInt32()
        $importSize = $reader.ReadUInt32()

        if ($importRva -eq 0 -or $importSize -eq 0) { return $importedDlls }

        # Read Section Table to convert RVA to file offset
        $sectionTableOffset = $optionalHeaderStart + $sizeOfOptionalHeader
        $fileStream.Seek($sectionTableOffset, [System.IO.SeekOrigin]::Begin) | Out-Null

        $sections = @()
        for ($s = 0; $s -lt $numberOfSections; $s++) {
            $sectionName = [System.Text.Encoding]::ASCII.GetString($reader.ReadBytes(8)).TrimEnd([char]0)
            $virtualSize = $reader.ReadUInt32()
            $virtualAddress = $reader.ReadUInt32()
            $sizeOfRawData = $reader.ReadUInt32()
            $pointerToRawData = $reader.ReadUInt32()
            $reader.ReadBytes(16) | Out-Null  # Rest of section header

            $sections += [PSCustomObject]@{
                Name             = $sectionName
                VirtualSize      = $virtualSize
                VirtualAddress   = $virtualAddress
                SizeOfRawData    = $sizeOfRawData
                PointerToRawData = $pointerToRawData
            }
        }

        # Convert RVA to file offset
        $importFileOffset = -1
        foreach ($section in $sections) {
            if ($importRva -ge $section.VirtualAddress -and $importRva -lt ($section.VirtualAddress + $section.SizeOfRawData)) {
                $importFileOffset = $importRva - $section.VirtualAddress + $section.PointerToRawData
                break
            }
        }

        if ($importFileOffset -lt 0) { return $importedDlls }

        # Read Import Directory Table entries (20 bytes each, terminated by null entry)
        $fileStream.Seek($importFileOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $maxEntries = 256  # Safety limit

        for ($e = 0; $e -lt $maxEntries; $e++) {
            $importLookupTableRva = $reader.ReadUInt32()
            $reader.ReadUInt32() | Out-Null  # TimeDateStamp
            $reader.ReadUInt32() | Out-Null  # ForwarderChain
            $nameRva = $reader.ReadUInt32()
            $reader.ReadUInt32() | Out-Null  # ImportAddressTableRva

            # Null entry terminates the table
            if ($importLookupTableRva -eq 0 -and $nameRva -eq 0) { break }
            if ($nameRva -eq 0) { continue }

            # Convert name RVA to file offset
            $nameFileOffset = -1
            foreach ($section in $sections) {
                if ($nameRva -ge $section.VirtualAddress -and $nameRva -lt ($section.VirtualAddress + $section.SizeOfRawData)) {
                    $nameFileOffset = $nameRva - $section.VirtualAddress + $section.PointerToRawData
                    break
                }
            }

            if ($nameFileOffset -lt 0) { continue }

            # Save current position, read DLL name, restore position
            $savedPosition = $fileStream.Position
            $fileStream.Seek($nameFileOffset, [System.IO.SeekOrigin]::Begin) | Out-Null

            # Read null-terminated ASCII string
            $nameBytes = New-Object System.Collections.Generic.List[byte]
            $maxNameLen = 128
            for ($n = 0; $n -lt $maxNameLen; $n++) {
                $b = $reader.ReadByte()
                if ($b -eq 0) { break }
                [void]$nameBytes.Add($b)
            }

            if ($nameBytes.Count -gt 0) {
                $dllName = [System.Text.Encoding]::ASCII.GetString($nameBytes.ToArray())
                $importedDlls += $dllName.ToLower()
            }

            $fileStream.Seek($savedPosition, [System.IO.SeekOrigin]::Begin) | Out-Null
        }
    }
    catch {
        Write-Verbose "Error reading PE imports from $($FilePath): $($_.Exception.Message)"
    }
    finally {
        if ($reader) { $reader.Close() }
        if ($fileStream) { $fileStream.Close() }
    }

    return $importedDlls
}

function Find-PEImportLegacyApps {
    <#
    .SYNOPSIS
        Scans Program Files for executables that import legacy VC runtime DLLs via PE Import Table.
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
            [void]$outputMessages.Add("NOTICE: PE Import scan stopped due to timeout")
            break
        }

        if (-not (Test-Path -Path $searchPath -ErrorAction SilentlyContinue)) {
            continue
        }

        try {
            $exeFiles = Get-ChildItem -Path $searchPath -Recurse -Filter '*.exe' -Depth 4 -ErrorAction SilentlyContinue | Where-Object {
                $_.Length -gt 10KB -and
                $_.Length -lt 500MB -and
                $_.FullName -notlike '*\Microsoft Office\root\*'
            }

            foreach ($file in $exeFiles) {
                if (Test-ScriptTimeout) {
                    [void]$outputMessages.Add("NOTICE: PE Import exe scan stopped due to timeout")
                    break
                }

                try {
                    $importedDlls = Get-PEImportedDlls -FilePath $file.FullName
                    $legacyImports = $importedDlls | Where-Object { $_ -match $legacyDllRegex }

                    if ($legacyImports) {
                        $appName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                        $appDir = $file.DirectoryName

                        # Avoid duplicates
                        $alreadyDetected = $false
                        foreach ($existing in $detectedApps) {
                            if ($existing.Path -eq $appDir -and $existing.Name -eq $appName) {
                                $alreadyDetected = $true
                                break
                            }
                        }

                        if (-not $alreadyDetected) {
                            # Determine highest VC version referenced
                            $vcVersion = "Unknown"
                            foreach ($dll in $legacyImports) {
                                $thisVersion = Get-VCVersionFromDll -DllName $dll
                                $vcVersion = $thisVersion  # Take the last match (usually one version per app)
                            }

                            [void]$detectedApps.Add([PSCustomObject]@{
                                Name   = $appName
                                Path   = $appDir
                                Method = "PE Import ($($vcVersion))"
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
            Write-Verbose "Error scanning $($searchPath): $($_.Exception.Message)"
        }
    }

    if ($foundCount -gt 0) {
        [void]$outputMessages.Add("PE Import: $($foundCount) app(s) importing legacy VC runtime DLLs")
    }

    return $foundCount
}

function Find-AppLocalLegacyDlls {
    <#
    .SYNOPSIS
        Scans Program Files for app-local copies of legacy VC runtime DLLs deployed
        alongside applications.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $foundCount = 0
    $searchPaths = @(
        "$($env:ProgramFiles)",
        "${env:ProgramFiles(x86)}"
    )

    # Track directories already found to avoid duplicates per directory
    $foundDirectories = @{}

    foreach ($searchPath in $searchPaths) {
        if (Test-ScriptTimeout) {
            [void]$outputMessages.Add("NOTICE: App-local DLL scan stopped due to timeout")
            break
        }

        if (-not (Test-Path -Path $searchPath -ErrorAction SilentlyContinue)) {
            continue
        }

        try {
            foreach ($dllName in $legacyDllNames) {
                if (Test-ScriptTimeout) { break }

                $foundFiles = Get-ChildItem -Path $searchPath -Recurse -Filter $dllName -Depth 4 -ErrorAction SilentlyContinue | Where-Object {
                    # Exclude System32/SysWOW64/WinSxS -- those are the system-installed copies
                    $_.FullName -notlike "*$($env:SystemRoot)*" -and
                    # Exclude Office C2R paths (managed by Office update channel)
                    $_.FullName -notlike '*\Microsoft Office\root\*'
                }

                foreach ($file in $foundFiles) {
                    $appDir = $file.DirectoryName

                    if ($foundDirectories.ContainsKey($appDir)) { continue }
                    $foundDirectories[$appDir] = $true

                    # Identify the application from the exe in the same directory
                    $appExe = Get-ChildItem -Path $appDir -Filter '*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
                    $appName = if ($appExe) {
                        [System.IO.Path]::GetFileNameWithoutExtension($appExe.Name)
                    }
                    else {
                        Split-Path -Path $appDir -Leaf
                    }

                    # Check if already detected via PE Import
                    $alreadyDetected = $false
                    foreach ($existing in $detectedApps) {
                        if ($existing.Path -eq $appDir) {
                            $alreadyDetected = $true
                            break
                        }
                    }

                    if (-not $alreadyDetected) {
                        $vcVersion = Get-VCVersionFromDll -DllName $file.Name
                        [void]$detectedApps.Add([PSCustomObject]@{
                            Name   = $appName
                            Path   = $appDir
                            Method = "App-local DLL ($($vcVersion))"
                        })
                        $foundCount++
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error scanning $($searchPath) for app-local DLLs: $($_.Exception.Message)"
        }
    }

    if ($foundCount -gt 0) {
        [void]$outputMessages.Add("App-local: $($foundCount) app(s) with bundled legacy VC runtime DLLs")
    }

    return $foundCount
}

function Find-SxSManifestLegacyApps {
    <#
    .SYNOPSIS
        Scans Program Files for application manifests referencing VC++ 2005/2008
        Side-by-Side (WinSxS) assemblies.
    .DESCRIPTION
        VC++ 2005 and 2008 use the Windows SxS mechanism. Applications declare their
        dependency via an embedded or external manifest (.manifest file or embedded RT_MANIFEST)
        containing references to microsoft.vc80.crt or microsoft.vc90.crt assemblies.
        This function checks external .manifest files for these references.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $foundCount = 0
    $searchPaths = @(
        "$($env:ProgramFiles)",
        "${env:ProgramFiles(x86)}"
    )

    # SxS assembly identity patterns for legacy VC runtimes
    $sxsPatterns = @(
        'microsoft.vc80.crt',
        'microsoft.vc80.mfc',
        'microsoft.vc80.atl',
        'microsoft.vc90.crt',
        'microsoft.vc90.mfc',
        'microsoft.vc90.atl'
    )

    foreach ($searchPath in $searchPaths) {
        if (Test-ScriptTimeout) {
            [void]$outputMessages.Add("NOTICE: SxS manifest scan stopped due to timeout")
            break
        }

        if (-not (Test-Path -Path $searchPath -ErrorAction SilentlyContinue)) {
            continue
        }

        try {
            $manifestFiles = Get-ChildItem -Path $searchPath -Recurse -Filter '*.manifest' -Depth 4 -ErrorAction SilentlyContinue | Where-Object {
                $_.Length -lt 100KB
            }

            foreach ($file in $manifestFiles) {
                if (Test-ScriptTimeout) {
                    [void]$outputMessages.Add("NOTICE: SxS manifest file scan stopped due to timeout")
                    break
                }

                try {
                    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                    if (-not $content) { continue }

                    $hasLegacyRef = $false
                    $vcVersion = "Unknown"
                    foreach ($pattern in $sxsPatterns) {
                        if ($content -match $pattern) {
                            $hasLegacyRef = $true
                            if ($pattern -match 'vc80') {
                                $vcVersion = 'VC++ 2005 (8.0)'
                            }
                            elseif ($pattern -match 'vc90') {
                                $vcVersion = 'VC++ 2008 (9.0)'
                            }
                            break
                        }
                    }

                    if ($hasLegacyRef) {
                        $appDir = $file.DirectoryName
                        $appExe = Get-ChildItem -Path $appDir -Filter '*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
                        $appName = if ($appExe) {
                            [System.IO.Path]::GetFileNameWithoutExtension($appExe.Name)
                        }
                        else {
                            Split-Path -Path $appDir -Leaf
                        }

                        # Avoid duplicates
                        $alreadyDetected = $false
                        foreach ($existing in $detectedApps) {
                            if ($existing.Path -eq $appDir) {
                                $alreadyDetected = $true
                                break
                            }
                        }

                        if (-not $alreadyDetected) {
                            [void]$detectedApps.Add([PSCustomObject]@{
                                Name   = $appName
                                Path   = $appDir
                                Method = "SxS Manifest ($($vcVersion))"
                            })
                            $foundCount++
                        }
                    }
                }
                catch {
                    Write-Verbose "Error reading manifest $($file.FullName): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Verbose "Error scanning $($searchPath) for manifests: $($_.Exception.Message)"
        }
    }

    if ($foundCount -gt 0) {
        [void]$outputMessages.Add("SxS Manifest: $($foundCount) app(s) with legacy VC++ assembly references")
    }

    return $foundCount
}

function Find-OutdatedV14Redist {
    <#
    .SYNOPSIS
        Checks if the installed VC++ 14.x (2015-2026) Redistributable is outdated.
    .DESCRIPTION
        The v14 runtime (vcruntime140.dll) is binary-compatible across VS 2015/2017/2019/2022/2026.
        Applications do not need recompilation -- they just need the latest redistributable
        package installed. This check flags outdated v14 packages that may contain known CVEs.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $foundCount = 0

    # Registry paths for VC++ 14.x runtime metadata
    $v14RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x86"
    )

    $checkedArchitectures = @{}

    foreach ($regPath in $v14RegPaths) {
        if (Test-ScriptTimeout) {
            [void]$outputMessages.Add("NOTICE: V14 redist check stopped due to timeout")
            break
        }

        try {
            if (-not (Test-Path -Path $regPath -ErrorAction SilentlyContinue)) { continue }

            $regProps = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if (-not $regProps) { continue }

            # Determine architecture from path
            $arch = if ($regPath -match 'x64') { 'x64' } else { 'x86' }
            if ($checkedArchitectures.ContainsKey($arch)) { continue }
            $checkedArchitectures[$arch] = $true

            # Get installed version -- try Version property first, then build from Major.Minor.Bld
            $installedVersion = $null
            if ($regProps.Version) {
                # Version string is typically "v14.xx.xxxxx.xx" -- strip leading 'v'
                $versionString = $regProps.Version -replace '^v', ''
                try {
                    $installedVersion = [Version]$versionString
                }
                catch {
                    Write-Verbose "Could not parse version string: $($regProps.Version)"
                }
            }

            if (-not $installedVersion -and $regProps.Major -and $regProps.Minor -and $regProps.Bld) {
                try {
                    $installedVersion = [Version]"$($regProps.Major).$($regProps.Minor).$($regProps.Bld).0"
                }
                catch {
                    Write-Verbose "Could not construct version from Major/Minor/Bld"
                }
            }

            if (-not $installedVersion) { continue }

            # Compare against minimum acceptable version
            if ($installedVersion -lt $MINIMUM_V14_VERSION) {
                [void]$detectedApps.Add([PSCustomObject]@{
                    Name   = "VC++ 14.x Redist ($($arch))"
                    Path   = "Installed: v$($installedVersion) (minimum: v$($MINIMUM_V14_VERSION))"
                    Method = 'Outdated V14 Redist'
                })
                [void]$outputMessages.Add("Outdated V14 ($($arch)): v$($installedVersion) < v$($MINIMUM_V14_VERSION)")
                $foundCount++
            }
        }
        catch {
            Write-Verbose "Error checking v14 redist at $($regPath): $($_.Exception.Message)"
        }
    }

    # Also check via Uninstall registry for display name confirmation
    if ($foundCount -eq 0) {
        $uninstallPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        foreach ($path in $uninstallPaths) {
            if (Test-ScriptTimeout) { break }

            try {
                $keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                foreach ($key in $keys) {
                    $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                    if (-not $props.DisplayName) { continue }

                    # Match VC++ 2015-2026 Redistributable entries
                    if ($props.DisplayName -match 'Visual C\+\+.*(2015|2017|2019|2022|2026).*Redistributable') {
                        if ($props.DisplayVersion) {
                            try {
                                $pkgVersion = [Version]$props.DisplayVersion
                                if ($pkgVersion -lt $MINIMUM_V14_VERSION) {
                                    $arch = if ($props.DisplayName -match 'x64') { 'x64' }
                                            elseif ($props.DisplayName -match 'x86') { 'x86' }
                                            else { 'unknown' }

                                    if (-not $checkedArchitectures.ContainsKey("pkg_$($arch)")) {
                                        $checkedArchitectures["pkg_$($arch)"] = $true
                                        [void]$detectedApps.Add([PSCustomObject]@{
                                            Name   = "$($props.DisplayName)"
                                            Path   = "Installed: v$($pkgVersion) (minimum: v$($MINIMUM_V14_VERSION))"
                                            Method = 'Outdated V14 Redist'
                                        })
                                        [void]$outputMessages.Add("Outdated V14 pkg: $($props.DisplayName) v$($pkgVersion)")
                                        $foundCount++
                                    }
                                }
                            }
                            catch {
                                Write-Verbose "Could not parse package version: $($props.DisplayVersion)"
                            }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Error scanning uninstall keys at $($path): $($_.Exception.Message)"
            }
        }
    }

    if ($foundCount -gt 0) {
        [void]$outputMessages.Add("Outdated V14: $($foundCount) outdated VC++ 14.x Redistributable package(s)")
    }

    return $foundCount
}

#endregion

#region Main Detection Logic

[void]$outputMessages.Add("=== Legacy VC++ Redistributable Detection v$($scriptVersion) ===")

# Check 1: Installed legacy VC++ Redistributable packages
$detectionResults.InstalledRedists = Invoke-MajorDetectionCheck -CheckName "Installed Redists" -Action { Find-InstalledLegacyRedists }

# Check 2: PE Import Table scan for legacy VC runtime imports
$detectionResults.PEImportApps = Invoke-MajorDetectionCheck -CheckName "PE Import Apps" -Action { Find-PEImportLegacyApps }

# Check 3: App-local legacy VC runtime DLLs
$detectionResults.AppLocalDlls = Invoke-MajorDetectionCheck -CheckName "App-local DLLs" -Action { Find-AppLocalLegacyDlls }

# Check 4: SxS Manifest references (VC++ 2005/2008)
$detectionResults.SxSManifestApps = Invoke-MajorDetectionCheck -CheckName "SxS Manifest Apps" -Action { Find-SxSManifestLegacyApps }

# Check 5: Outdated VC++ 14.x Redistributable (2015-2026 binary-compatible; just needs package update)
$detectionResults.OutdatedV14Redist = Invoke-MajorDetectionCheck -CheckName "Outdated V14 Redist" -Action { Find-OutdatedV14Redist }

# Calculate total findings
$totalAppFindings = $detectionResults.InstalledRedists +
                    $detectionResults.PEImportApps +
                    $detectionResults.AppLocalDlls +
                    $detectionResults.SxSManifestApps +
                    $detectionResults.OutdatedV14Redist

# Build summary output
[void]$outputMessages.Add("")
[void]$outputMessages.Add("=== Detection Summary ===")
[void]$outputMessages.Add("Installed Redist packages: $($detectionResults.InstalledRedists)")
[void]$outputMessages.Add("Apps (PE Import): $($detectionResults.PEImportApps)")
[void]$outputMessages.Add("Apps (App-local DLL): $($detectionResults.AppLocalDlls)")
[void]$outputMessages.Add("Apps (SxS Manifest): $($detectionResults.SxSManifestApps)")
[void]$outputMessages.Add("Outdated V14 Redist: $($detectionResults.OutdatedV14Redist)")
[void]$outputMessages.Add("Total Findings: $($totalAppFindings)")

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
    "COMPLIANT - No applications depending on unsupported VC++ runtimes detected"
}
else {
    "NON-COMPLIANT - $($totalAppFindings) finding(s) for unsupported VC++ runtime dependencies"
}
[void]$outputMessages.Add("Status: $($complianceStatus)")

# Combine messages using pipe separator to reduce character count
$finalOutput = $outputMessages -join " | "

# Validate output size and truncate if necessary
if ($finalOutput.Length -gt $MAX_OUTPUT_SIZE) {
    # Prioritize actionable findings over installed redist packages in truncated output.
    # Installed redists are already visible in Intune software inventory -- apps are the real value.
    # Deduplicate by app name within each priority tier to avoid wasting space on
    # multiple exes from the same application (e.g. JRE tools, Backupper subdirs).
    $priorityNames = [ordered]@{}
    $lowPriorityNames = [ordered]@{}

    foreach ($app in $detectedApps) {
        if ($app.Method -eq 'Installed Redist') {
            if (-not $lowPriorityNames.Contains($app.Name)) {
                $lowPriorityNames[$app.Name] = $app.Method
            }
        }
        else {
            if (-not $priorityNames.Contains($app.Name)) {
                $priorityNames[$app.Name] = $app.Method
            }
        }
    }

    $truncatedParts = @(
        "=== VC++ Detection v$($scriptVersion) (Truncated) ==="
        "Installed: $($detectionResults.InstalledRedists)"
        "PE: $($detectionResults.PEImportApps)"
        "Local: $($detectionResults.AppLocalDlls)"
        "SxS: $($detectionResults.SxSManifestApps)"
        "V14: $($detectionResults.OutdatedV14Redist)"
        "Total: $($totalAppFindings)"
    )

    # Calculate available space for app entries
    $headerLength = ($truncatedParts -join ' | ').Length
    $statusLine = "Status: $($complianceStatus)"
    $reservedLength = $headerLength + 3 + $statusLine.Length + 3  # 3 for " | " separators
    $remainingSpace = $MAX_OUTPUT_SIZE - $reservedLength
    $appLines = @()
    $totalUniqueEntries = $priorityNames.Count + $lowPriorityNames.Count
    $addedCount = 0

    # Add priority apps first (PE Import, App-local, SxS, Outdated V14) -- unique names only
    foreach ($entry in $priorityNames.GetEnumerator()) {
        $line = "[$($entry.Value)] $($entry.Key)"
        $lineLength = $line.Length + 3
        if (($remainingSpace - $lineLength) -lt 50) { break }
        $appLines += $line
        $remainingSpace -= $lineLength
        $addedCount++
    }

    # Fill remaining space with installed redist entries (low priority)
    foreach ($entry in $lowPriorityNames.GetEnumerator()) {
        $line = "[$($entry.Value)] $($entry.Key)"
        $lineLength = $line.Length + 3
        if (($remainingSpace - $lineLength) -lt 50) { break }
        $appLines += $line
        $remainingSpace -= $lineLength
        $addedCount++
    }

    if ($addedCount -lt $totalUniqueEntries) {
        $appLines += "(+$($totalUniqueEntries - $addedCount) more)"
    }

    $truncatedParts += $appLines
    $truncatedParts += $statusLine
    $truncatedOutput = $truncatedParts -join ' | '

    if ($truncatedOutput.Length -gt $MAX_OUTPUT_SIZE) {
        # Final fallback: just summary + status
        $truncatedOutput = "[TRUNCATED] Installed:$($detectionResults.InstalledRedists) PE:$($detectionResults.PEImportApps) Local:$($detectionResults.AppLocalDlls) SxS:$($detectionResults.SxSManifestApps) V14:$($detectionResults.OutdatedV14Redist) Total:$($totalAppFindings) | $($complianceStatus)"
    }

    Write-Output $truncatedOutput
}
else {
    Write-Output $finalOutput
}

if ($totalAppFindings -eq 0) {
    exit 0  # Compliant
}
else {
    exit 1  # Non-compliant
}
