# The one thing the tool can change: a user environment variable from a fixed
# list, pointing at a new empty folder below <drive>:\FromC. These tests set a
# real user variable on the test machine and remove it again.

BeforeDiscovery {
    $script:OtherDrive = [System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady -and $_.Name -notlike 'C*' } |
        Select-Object -First 1 | ForEach-Object { $_.Name.Substring(0, 1) }
    $script:NoOtherDrive = [string]::IsNullOrEmpty($script:OtherDrive)
}

BeforeAll {
    . (Join-Path $PSScriptRoot '..\DiskSpaceTriage.ps1') -ImportOnly

    $script:Dest = [System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady -and $_.Name -notlike 'C*' } |
        Select-Object -First 1 | ForEach-Object { $_.Name.Substring(0, 1) }
    $script:Var     = 'TRITON_CACHE_DIR'
    $script:Saved   = [Environment]::GetEnvironmentVariable($script:Var, 'User')
    $script:SavedHf = [Environment]::GetEnvironmentVariable('HF_HOME', 'User')
    [Environment]::SetEnvironmentVariable($script:Var, $null, 'User')
    [Environment]::SetEnvironmentVariable('HF_HOME', $null, 'User')

    $base = $env:RUNNER_TEMP
    if ([string]::IsNullOrWhiteSpace($base)) { $base = $env:PUBLIC }
    $script:LogDir = Join-Path $base ('triage-actions-' + [guid]::NewGuid().ToString('N'))
    $script:Target = $script:TriageRedirectTargets | Where-Object Variable -eq $script:Var
    $script:Value  = ''
    $script:Store  = ''
    $script:MadeStore = $false
    if ($script:Dest) {
        # The only folder the tool will accept for this store on this drive.
        $script:Value = Get-TriageRedirectFolder -Letter $script:Dest -Target $script:Target
        $script:Store = Split-Path -Parent $script:Value          # ...\.triton
        $script:MadeStore = -not (Test-Path -LiteralPath $script:Store)
    }
    # The plan only offers a store that exists in its usual place.
    $script:HfSource = Join-Path $env:USERPROFILE '.cache\huggingface'
    $script:MadeHf   = -not (Test-Path -LiteralPath $script:HfSource)
    if ($script:MadeHf) { New-Item -ItemType Directory -Path $script:HfSource -Force | Out-Null }
}

AfterAll {
    [Environment]::SetEnvironmentVariable($script:Var, $script:Saved, 'User')
    [Environment]::SetEnvironmentVariable('HF_HOME', $script:SavedHf, 'User')
    # Remove only what this test run created.
    if ($script:MadeStore -and $script:Store -and (Test-Path -LiteralPath $script:Store)) { Remove-Item -LiteralPath $script:Store -Recurse -Force }
    if ($script:MadeHf -and (Test-Path -LiteralPath $script:HfSource)) { Remove-Item -LiteralPath $script:HfSource -Recurse -Force }
    if ($script:LogDir -and (Test-Path -LiteralPath $script:LogDir)) { Remove-Item -LiteralPath $script:LogDir -Recurse -Force }
}

Describe 'Test environment' {
    It 'has a second fixed drive on CI, so the action tests below really run' {
        if ($env:CI) { $script:Dest | Should -Not -BeNullOrEmpty }
    }
}

Describe 'Get-TriageRedirectPlan' -Skip:$script:NoOtherDrive {
    BeforeAll { $script:Plan = @(Get-TriageRedirectPlan -Result (Get-SampleTriageResult) -DestinationDrive $script:Dest) }

    It 'offers only stores the scan found' {
        ($script:Plan | ForEach-Object Variable) | Should -Contain 'HF_HOME'
        ($script:Plan | ForEach-Object Variable) | Should -Contain 'PIP_CACHE_DIR'
        ($script:Plan | ForEach-Object Variable) | Should -Not -Contain 'GOMODCACHE'
    }
    It 'keeps the same folder name and structure below FromC' {
        $hf = $script:Plan | Where-Object Variable -eq 'HF_HOME'
        $hf.State         | Should -Be 'Ready'
        $hf.ProposedValue | Should -BeLike "$($script:Dest):\FromC\Users\*\.cache\huggingface"
    }
    It 'changes nothing by planning' {
        [Environment]::GetEnvironmentVariable('HF_HOME', 'User') | Should -BeNullOrEmpty
        Test-Path -LiteralPath "$($script:Dest):\FromC\Users\$([System.IO.Path]::GetFileName($env:USERPROFILE))\.cache\huggingface" | Should -BeFalse
    }
    It 'blocks a destination that is the drive being cleaned' {
        $p = @(Get-TriageRedirectPlan -Result (Get-SampleTriageResult) -DestinationDrive 'C')
        @($p | Where-Object State -ne 'Blocked').Count | Should -Be 0
    }
    It 'does not offer a variable the user has already set' {
        [Environment]::SetEnvironmentVariable('HF_HOME', 'E:\somewhere', 'User')
        try {
            $p = @(Get-TriageRedirectPlan -Result (Get-SampleTriageResult) -DestinationDrive $script:Dest)
            ($p | Where-Object Variable -eq 'HF_HOME').State | Should -Be 'AlreadySet'
        } finally { [Environment]::SetEnvironmentVariable('HF_HOME', $null, 'User') }
    }
}

Describe 'Set-TriageRedirect refuses anything outside its narrow job' -Skip:$script:NoOtherDrive {
    It 'refuses a variable that is not on its list' {
        { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = 'PATH'; ProposedValue = "$($script:Dest):\FromC\Users\x\y" }) -LogDirectory $script:LogDir } | Should -Throw '*Not a variable*'
        { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = 'triton_cache_dir'; ProposedValue = $script:Value }) -LogDirectory $script:LogDir } | Should -Throw '*Not a variable*'
    }
    It 'refuses any folder other than the one expected folder for that store' {
        foreach ($bad in @(
            "$($script:Dest):\Windows\.triton\cache",
            '\\server\share\FromC\Users\x\.triton\cache',
            "$($script:Dest):\FromC\Users\someone-else\.triton\cache",
            "$($script:Dest):\FromC\Users\x\..\..\..\.triton\cache",
            ($script:Value + '\deeper'),
            ($script:Value + '.'),
            ($script:Value.Replace('.triton\cache', '.cache\huggingface'))
        )) {
            { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = $script:Var; ProposedValue = $bad }) -LogDirectory $script:LogDir } | Should -Throw '*Refused*' -Because $bad
        }
    }
    It 'refuses the drive that holds Windows and the user profile' {
        $onSystem = 'C' + $script:Value.Substring(1)
        { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = $script:Var; ProposedValue = $onSystem }) -LogDirectory $script:LogDir } | Should -Throw '*Refused*'
    }
    It 'refuses a new folder that already has something in it' {
        if (-not $script:MadeStore) { Set-ItResult -Skipped -Because 'the store folder existed before the test'; return }
        New-Item -ItemType Directory -Path $script:Value -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:Value 'planted.txt') -Value 'x'
        try {
            { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = $script:Var; ProposedValue = $script:Value }) -LogDirectory $script:LogDir } | Should -Throw '*not empty*'
        } finally { Remove-Item -LiteralPath (Join-Path $script:Value 'planted.txt') -Force }
    }
    It 'left the variable unset after all those refusals' {
        [Environment]::GetEnvironmentVariable($script:Var, 'User') | Should -BeNullOrEmpty
    }
}

Describe 'Set and undo' -Skip:$script:NoOtherDrive {
    It 'creates the empty folder, sets the user variable and logs the change' {
        $script:Record = Set-TriageRedirect -Item ([pscustomobject]@{ Variable = $script:Var; ProposedValue = $script:Value }) -LogDirectory $script:LogDir
        [Environment]::GetEnvironmentVariable($script:Var, 'User') | Should -Be $script:Value
        Test-Path -LiteralPath $script:Value -PathType Container | Should -BeTrue
        @(Get-ChildItem -LiteralPath $script:Value -Force).Count | Should -Be 0
        $script:Record.LogPath | Should -Not -BeNullOrEmpty
        @(Import-Csv -LiteralPath $script:Record.LogPath)[-1].Variable | Should -Be $script:Var
    }
    It 'does not touch the machine-level variable' {
        [Environment]::GetEnvironmentVariable($script:Var, 'Machine') | Should -BeNullOrEmpty
    }
    It 'gives an undo record that names exactly what was set' {
        $script:Record.NewValue | Should -Be $script:Value
        $script:Record.Variable | Should -Be $script:Var
    }
    It 'refuses to overwrite a variable that is already set' {
        { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = $script:Var; ProposedValue = $script:Value }) -LogDirectory $script:LogDir } | Should -Throw '*already set*'
    }
    It 'will not undo when the value was changed by someone else' {
        [Environment]::SetEnvironmentVariable($script:Var, 'E:\elsewhere', 'User')
        { Undo-TriageRedirect -Record $script:Record -LogDirectory $script:LogDir } | Should -Throw '*Not undone*'
        [Environment]::GetEnvironmentVariable($script:Var, 'User') | Should -Be 'E:\elsewhere'
        [Environment]::SetEnvironmentVariable($script:Var, $script:Value, 'User')
    }
    It 'undoes its own change and logs it' {
        $undo = Undo-TriageRedirect -Record $script:Record -LogDirectory $script:LogDir
        [Environment]::GetEnvironmentVariable($script:Var, 'User') | Should -BeNullOrEmpty
        $undo.Action | Should -Be 'Undo'
        @(Import-Csv -LiteralPath $undo.LogPath).Count | Should -Be 2
    }
}
