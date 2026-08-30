# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
Runs the terminal candidate profile as a disposable local Windows user.

.DESCRIPTION
The caller has already prepared and verified read-only policy, tools, and
candidate source. This script gives a fresh local user read-only access to
those inputs and write access only to dedicated build directories. It denies
that user access to the runner command directory, supplies a new minimal
environment, and kills every process owned by the user before removing it.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('controller', 'protected-ci', 'candidate-ci')] [string] $CandidateProfile,
    [Parameter(Mandatory)] [ValidateSet('spec', 'traits', 'rs')] [string] $Kind,
    [Parameter(Mandatory)] [string] $Sandbox,
    [Parameter(Mandatory)] [string] $PolicyRoot,
    [Parameter(Mandatory)] [string] $CandidateRoot,
    [Parameter(Mandatory)] [string] $Driver,
    [Parameter(Mandatory)] [string] $Python,
    [Parameter(Mandatory)] [string] $Cargo,
    [Parameter(Mandatory)] [string] $ProtectedValidator,
    [Parameter(Mandatory)] [string] $CommandFile,
    [Parameter(Mandatory)] [string] $CandidateHome,
    [Parameter(Mandatory)] [string] $CandidateCache,
    [Parameter(Mandatory)] [string] $CandidateCargoHome,
    [Parameter(Mandatory)] [string] $CandidateTarget,
    [Parameter(Mandatory)] [string] $CandidateTemp,
    [Parameter(Mandatory)] [string] $CandidateBufCache,
    [Parameter(Mandatory)] [string] $CandidatePycache,
    [Parameter(Mandatory)] [string] $TrustedRustupHome,
    [Parameter(Mandatory)] [string] $TrustedPath,
    [Parameter(Mandatory)] [string] $DetachedPidFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$candidateUser = 'yscandidate'
$candidateExit = 1
$createdUser = $false
$process = $null

function Invoke-Icacls {
    param([Parameter(Mandatory)] [string[]] $Arguments)

    & icacls.exe @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with status $LASTEXITCODE"
    }
}

function Set-ReadOnlyReparsePointAccess {
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [string] $RunnerSid,
        [Parameter(Mandatory)] [string] $SystemSid,
        [Parameter(Mandatory)] [string] $AdministratorsSid,
        [Parameter(Mandatory)] [string] $CandidateSid
    )

    # icacls follows a symbolic link unless /L is explicit. Harden the link
    # entry itself so the disposable identity can inspect but not replace it.
    $reparsePoints = @(
        Get-ChildItem -LiteralPath $Root -Force -Recurse `
            -Attributes ReparsePoint -ErrorAction Stop
    )
    foreach ($item in $reparsePoints) {
        Invoke-Icacls -Arguments @(
            $item.FullName,
            '/grant:r',
            "${RunnerSid}:F",
            "${SystemSid}:F",
            "${AdministratorsSid}:F",
            "${CandidateSid}:RX",
            '/L'
        )
        Invoke-Icacls -Arguments @($item.FullName, '/inheritance:r', '/L')
    }
}

function Get-CandidateProcesses {
    Get-CimInstance Win32_Process | ForEach-Object {
        $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($null -ne $owner -and $owner.ReturnValue -eq 0 -and $owner.User -eq $candidateUser) {
            $_
        }
    }
}

function Stop-CandidateProcesses {
    foreach ($candidateProcess in @(Get-CandidateProcesses)) {
        Stop-Process -Id $candidateProcess.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function Test-PathUnderRoots {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string[]] $Roots
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    foreach ($root in $Roots) {
        $fullRoot = [IO.Path]::GetFullPath($root)
        if ($fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
        if (-not $fullRoot.EndsWith([IO.Path]::DirectorySeparatorChar)) {
            $fullRoot += [IO.Path]::DirectorySeparatorChar
        }
        if ($fullPath.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function ConvertTo-TrustedDirectoryList {
    param(
        [Parameter(Mandatory)] [string] $Value,
        [Parameter(Mandatory)] [string] $Label,
        [Parameter(Mandatory)] [string[]] $Roots
    )

    if ($Value.Length -gt 32768) {
        throw "Visual Studio provided an oversized ${Label} path"
    }
    $directories = @($Value.Split([IO.Path]::PathSeparator))
    if (
        $directories.Count -eq 0 -or
        $directories.Count -gt 64 -or
        @($directories | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0
    ) {
        throw "Visual Studio provided a noncanonical ${Label} path"
    }
    $normalized = @(
        foreach ($directory in $directories) {
            $trimmed = $directory.Trim()
            if (-not [IO.Path]::IsPathFullyQualified($trimmed)) {
                throw "Visual Studio provided a relative ${Label} directory"
            }
            $fullPath = [IO.Path]::GetFullPath($trimmed)
            if (
                -not (Test-Path -LiteralPath $fullPath -PathType Container) -or
                -not (Test-PathUnderRoots -Path $fullPath -Roots $Roots)
            ) {
                throw "Visual Studio provided an untrusted ${Label} directory"
            }
            $fullPath
        }
    )
    return $normalized -join [IO.Path]::PathSeparator
}

function Get-TrustedMsvcEnvironment {
    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles
    )
    $programFilesX86 = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFilesX86
    )
    if (
        [string]::IsNullOrWhiteSpace($programFiles) -or
        [string]::IsNullOrWhiteSpace($programFilesX86)
    ) {
        throw 'Windows Program Files roots are unavailable'
    }

    $vswherePath = Join-Path $programFilesX86 (
        'Microsoft Visual Studio\Installer\vswhere.exe'
    )
    $vswhere = Get-Item -LiteralPath $vswherePath -Force
    if (
        -not $vswhere.Exists -or
        $vswhere.VersionInfo.CompanyName -ne 'Microsoft Corporation'
    ) {
        throw 'the trusted Microsoft Visual Studio locator is unavailable'
    }

    $installationOutput = & $vswhere.FullName `
        -latest -products '*' `
        -requires 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' `
        -property installationPath
    if ($LASTEXITCODE -ne 0) {
        throw "Visual Studio locator failed with status $LASTEXITCODE"
    }
    $installations = @(
        $installationOutput |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($installations.Count -ne 1) {
        throw "expected one current Visual Studio installation, found $($installations.Count)"
    }
    $installation = [IO.Path]::GetFullPath($installations[0].Trim())
    $programFilesRoots = @($programFiles, $programFilesX86)
    if (-not (Test-PathUnderRoots -Path $installation -Roots $programFilesRoots)) {
        throw 'Visual Studio installation is outside Program Files'
    }

    $versionFile = Join-Path $installation (
        'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt'
    )
    $toolVersion = [IO.File]::ReadAllText($versionFile).Trim()
    if ($toolVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw 'Visual Studio declared a noncanonical default VC tool version'
    }
    $linkerPath = Join-Path $installation (
        "VC\Tools\MSVC\${toolVersion}\bin\Hostx64\x64\link.exe"
    )
    $linker = Get-Item -LiteralPath $linkerPath -Force
    if (
        -not $linker.Exists -or
        $linker.VersionInfo.CompanyName -ne 'Microsoft Corporation' -or
        $linker.VersionInfo.FileDescription -notlike '*Incremental Linker*'
    ) {
        throw 'the declared default Microsoft x64 linker is unavailable'
    }
    $developerCommandPath = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $developerCommandPath -PathType Leaf)) {
        throw 'the trusted Visual Studio developer environment is unavailable'
    }
    if ([string]::IsNullOrWhiteSpace($env:COMSPEC)) {
        throw 'the Windows command interpreter is unavailable'
    }
    $developerCommand = (
        "call `"${developerCommandPath}`" -no_logo -arch=x64 " +
        '-host_arch=x64 && set'
    )
    $environmentOutput = & $env:COMSPEC /d /s /c $developerCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Visual Studio developer environment failed with status $LASTEXITCODE"
    }
    $developerEnvironment = @{}
    foreach ($line in $environmentOutput) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            $developerEnvironment[$line.Substring(0, $separator)] = (
                $line.Substring($separator + 1)
            )
        }
    }
    foreach ($name in @('VCToolsInstallDir', 'WindowsSdkDir', 'LIB', 'INCLUDE')) {
        if (
            -not $developerEnvironment.ContainsKey($name) -or
            [string]::IsNullOrWhiteSpace($developerEnvironment[$name])
        ) {
            throw "Visual Studio developer environment omitted ${name}"
        }
    }

    $expectedTools = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath(
            (Join-Path $installation "VC\Tools\MSVC\${toolVersion}")
        )
    )
    $declaredTools = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($developerEnvironment['VCToolsInstallDir'])
    )
    if (-not $declaredTools.Equals(
        $expectedTools,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Visual Studio developer environment selected a different VC toolset'
    }
    $windowsSdk = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($developerEnvironment['WindowsSdkDir'])
    )
    if (-not (Test-PathUnderRoots -Path $windowsSdk -Roots $programFilesRoots)) {
        throw 'Visual Studio developer environment selected an untrusted Windows SDK'
    }
    $windowsKitsRoot = [IO.Directory]::GetParent($windowsSdk).FullName
    if (-not (Test-PathUnderRoots -Path $windowsKitsRoot -Roots $programFilesRoots)) {
        throw 'Visual Studio developer environment selected an untrusted SDK root'
    }
    $environmentRoots = @($installation, $windowsKitsRoot)
    return [PSCustomObject]@{
        Linker = $linker.FullName
        Lib = ConvertTo-TrustedDirectoryList `
            -Value $developerEnvironment['LIB'] `
            -Label 'library' `
            -Roots $environmentRoots
        Include = ConvertTo-TrustedDirectoryList `
            -Value $developerEnvironment['INCLUDE'] `
            -Label 'include' `
            -Roots $environmentRoots
    }
}

try {
    if (Get-LocalUser -Name $candidateUser -ErrorAction SilentlyContinue) {
        throw 'disposable candidate user already exists'
    }
    if (@(Get-CandidateProcesses).Count -ne 0) {
        throw 'disposable candidate identity already owns a process'
    }

    $randomBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($randomBytes)
    $passwordText = [Convert]::ToBase64String($randomBytes) + 'aA1!'
    $securePassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
    New-LocalUser -Name $candidateUser -Password $securePassword `
        -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword `
        -Description 'Disposable YamlSigil candidate' | Out-Null
    $createdUser = $true

    $candidateSid = '*' + (Get-LocalUser -Name $candidateUser).SID.Value
    $runnerSid = '*' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $systemSid = '*S-1-5-18'
    $administratorsSid = '*S-1-5-32-544'
    $commandDirectory = Split-Path -Parent $CommandFile
    $candidatePath = $TrustedPath
    $trustedMsvcEnvironment = $null
    if ($CandidateProfile -ne 'controller') {
        $trustedMsvcEnvironment = Get-TrustedMsvcEnvironment
        $trustedMsvcBin = Split-Path -Parent $trustedMsvcEnvironment.Linker
        $candidatePath = $trustedMsvcBin + [IO.Path]::PathSeparator + $TrustedPath
    }

    # Candidate source, protected policy, and installed tools stay read-only;
    # only task-specific build and temporary directories are writable. Give
    # every existing object direct access entries before removing inheritance,
    # so no recursive operation can strand a child with an incomplete ACL.
    Invoke-Icacls -Arguments @(
        $Sandbox,
        '/grant:r',
        "${runnerSid}:F",
        "${systemSid}:F",
        "${administratorsSid}:F",
        "${candidateSid}:RX",
        '/T'
    )
    Invoke-Icacls -Arguments @($Sandbox, '/inheritance:r', '/T')
    Invoke-Icacls -Arguments @($PolicyRoot, '/grant:r', "${candidateSid}:(OI)(CI)RX", '/T')
    Invoke-Icacls -Arguments @(
        $PolicyRoot,
        '/deny',
        "${candidateSid}:(OI)(CI)(WD,AD,WEA,WA,DE,DC,WDAC,WO)",
        '/T'
    )
    foreach ($readOnlyRoot in @($CandidateRoot, $PolicyRoot)) {
        Set-ReadOnlyReparsePointAccess `
            -Root $readOnlyRoot `
            -RunnerSid $runnerSid `
            -SystemSid $systemSid `
            -AdministratorsSid $administratorsSid `
            -CandidateSid $candidateSid
    }
    foreach ($writable in @(
        $CandidateHome,
        $CandidateCache,
        $CandidateCargoHome,
        $CandidateTarget,
        $CandidateTemp,
        $CandidateBufCache,
        $CandidatePycache
    )) {
        Invoke-Icacls -Arguments @(
            $writable,
            '/grant:r',
            "${runnerSid}:(OI)(CI)F",
            "${systemSid}:(OI)(CI)F",
            "${administratorsSid}:(OI)(CI)F",
            "${candidateSid}:(OI)(CI)M",
            '/T'
        )
    }
    Invoke-Icacls -Arguments @($commandDirectory, '/deny', "${candidateSid}:(OI)(CI)F")

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Python
    $startInfo.WorkingDirectory = $Sandbox
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UserName = $candidateUser
    $startInfo.Domain = $env:COMPUTERNAME
    $startInfo.Password = $securePassword
    $startInfo.LoadUserProfile = $false
    $startInfo.Environment.Clear()
    $startInfo.Environment['PATH'] = $candidatePath
    $startInfo.Environment['HOME'] = $CandidateHome
    $startInfo.Environment['USERPROFILE'] = $CandidateHome
    $startInfo.Environment['LOCALAPPDATA'] = $CandidateCache
    $startInfo.Environment['XDG_CACHE_HOME'] = $CandidateCache
    $startInfo.Environment['TEMP'] = $CandidateTemp
    $startInfo.Environment['TMP'] = $CandidateTemp
    $startInfo.Environment['SYSTEMROOT'] = $env:SYSTEMROOT
    $startInfo.Environment['COMSPEC'] = $env:COMSPEC
    $startInfo.Environment['CARGO_HOME'] = $CandidateCargoHome
    $startInfo.Environment['CARGO_TARGET_DIR'] = $CandidateTarget
    if ($null -ne $trustedMsvcEnvironment) {
        $startInfo.Environment['CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER'] = (
            $trustedMsvcEnvironment.Linker
        )
        $startInfo.Environment['LIB'] = $trustedMsvcEnvironment.Lib
        $startInfo.Environment['INCLUDE'] = $trustedMsvcEnvironment.Include
    }
    if ($CandidateProfile -ne 'controller' -and $Kind -ne 'spec') {
        # Current Cargo writes the generated root lock beside the disposable
        # home while the verified candidate source remains read-only.
        $startInfo.Environment['CARGO_RESOLVER_LOCKFILE_PATH'] = (
            Join-Path $CandidateHome 'Cargo.lock'
        )
    }
    $startInfo.Environment['RUSTUP_HOME'] = $TrustedRustupHome
    $startInfo.Environment['RUSTUP_TOOLCHAIN'] = 'stable'
    $startInfo.Environment['RUSTFLAGS'] = '-D warnings'
    $startInfo.Environment['BUF_CACHE_DIR'] = $CandidateBufCache
    $startInfo.Environment['BUF_RS_CACHE_DIR'] = $CandidateBufCache
    $startInfo.Environment['PYTHONPYCACHEPREFIX'] = $CandidatePycache
    $startInfo.Environment['YAML_SIGIL_PROFILE'] = $CandidateProfile
    $startInfo.Environment['YAML_SIGIL_TERMINAL_CANDIDATE'] = '1'

    foreach ($argument in @(
        $Driver,
        'run',
        '--profile', $CandidateProfile,
        '--kind', $Kind,
        '--policy-root', $PolicyRoot,
        '--candidate-root', $CandidateRoot,
        '--trusted-cargo', $Cargo,
        '--trusted-python', $Python,
        '--trusted-rustup-home', $TrustedRustupHome,
        '--protected-validator', $ProtectedValidator,
        '--command-file', $CommandFile,
        '--detached-pid-file', $DetachedPidFile
    )) {
        [void] $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'could not start the disposable candidate process'
    }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $deadline = [DateTime]::UtcNow.AddMinutes(85)
    while (-not $process.WaitForExit(250)) {
        if ([DateTime]::UtcNow -ge $deadline) {
            throw 'terminal candidate exceeded its 85-minute parent deadline'
        }
    }
    $candidateExit = $process.ExitCode
    $standardOutput = $stdout.GetAwaiter().GetResult()
    $standardError = $stderr.GetAwaiter().GetResult()
    [Console]::Out.Write($standardOutput)
    [Console]::Error.Write($standardError)
}
finally {
    Stop-CandidateProcesses
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if (@(Get-CandidateProcesses).Count -eq 0) {
            break
        }
        Start-Sleep -Milliseconds 100
        Stop-CandidateProcesses
    }
    if (@(Get-CandidateProcesses).Count -ne 0) {
        $candidateExit = 1
        [Console]::Error.WriteLine('terminal candidate identity retained a process after cleanup')
    }
    else {
        Write-Host 'Terminal candidate identity is quiescent.'
    }

    if ($createdUser) {
        try {
            Remove-LocalUser -Name $candidateUser -ErrorAction Stop
        }
        catch {
            $candidateExit = 1
            [Console]::Error.WriteLine('disposable candidate identity could not be removed')
        }
        if (Get-LocalUser -Name $candidateUser -ErrorAction SilentlyContinue) {
            $candidateExit = 1
            [Console]::Error.WriteLine('disposable candidate identity remains after removal')
        }
    }
    if ($null -ne $process) {
        $process.Dispose()
    }
}

exit $candidateExit
