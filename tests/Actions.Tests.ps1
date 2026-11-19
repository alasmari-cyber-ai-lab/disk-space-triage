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
    $script:Folder = "$($script:Dest):\FromC\Users\triage-ci-test"
    $script:Value  = "$script:Folder\.triton\cache"
}

AfterAll {
    [Environment]::SetEnvironmentVariable($script:Var, $script:Saved, 'User')
    [Environment]::SetEnvironmentVariable('HF_HOME', $script:SavedHf, 'User')
    if ($script:Folder -and (Test-Path -LiteralPath $script:Folder)) { Remove-Item -LiteralPath $script:Folder -Recurse -Force }
    if ($script:LogDir -and (Test-Path -LiteralPath $script:LogDir)) { Remove-Item -LiteralPath $script:LogDir -Recurse -Force }
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
    It 'refuses a folder outside FromC' {
        { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = $script:Var; ProposedValue = "$($script:Dest):\Windows\.triton\cache" }) -LogDirectory $script:LogDir } | Should -Throw '*FromC*'
        { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = $script:Var; ProposedValue = '\\server\share\FromC\Users\x\.triton\cache' }) -LogDirectory $script:LogDir } | Should -Throw '*FromC*'
    }
    It 'refuses path tricks' {
        { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = $script:Var; ProposedValue = "$($script:Dest):\FromC\Users\x\..\..\..\.triton\cache" }) -LogDirectory $script:LogDir } | Should -Throw '*Refused*'
    }
    It 'refuses a folder that belongs to a different store' {
        { Set-TriageRedirect -Item ([pscustomobject]@{ Variable = $script:Var; ProposedValue = "$($script:Dest):\FromC\Users\x\.cache\huggingface" }) -LogDirectory $script:LogDir } | Should -Throw '*does not match*'
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
