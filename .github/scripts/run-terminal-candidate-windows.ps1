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
    foreach ($writable in @(
        $CandidateHome,
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
    $startInfo.Environment['PATH'] = $TrustedPath
    $startInfo.Environment['HOME'] = $CandidateHome
    $startInfo.Environment['USERPROFILE'] = $CandidateHome
    $startInfo.Environment['TEMP'] = $CandidateTemp
    $startInfo.Environment['TMP'] = $CandidateTemp
    $startInfo.Environment['SYSTEMROOT'] = $env:SYSTEMROOT
    $startInfo.Environment['COMSPEC'] = $env:COMSPEC
    $startInfo.Environment['CARGO_HOME'] = $CandidateCargoHome
    $startInfo.Environment['CARGO_TARGET_DIR'] = $CandidateTarget
    $startInfo.Environment['RUSTUP_HOME'] = $TrustedRustupHome
    $startInfo.Environment['RUSTUP_TOOLCHAIN'] = 'stable'
    $startInfo.Environment['RUSTFLAGS'] = '-D warnings'
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
