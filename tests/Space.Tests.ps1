# Free-space measurement, Recycle Bin size, the store-move plan and the
# shareable summary. Read-only: nothing here moves, deletes or empties
# anything. The actions themselves are exercised on throw-away volumes in
# Volume.Tests.ps1.

BeforeDiscovery {
    $sys = $env:SystemDrive.Substring(0, 1)
    $script:OtherDrive = [System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady -and $_.DriveFormat -eq 'NTFS' -and $_.Name.Substring(0, 1) -ne $sys } |
        Select-Object -First 1 | ForEach-Object { $_.Name.Substring(0, 1) }
    $script:NoOtherDrive = [string]::IsNullOrEmpty($script:OtherDrive)
}

BeforeAll {
    . (Join-Path $PSScriptRoot '..\DiskSpaceTriage.ps1') -ImportOnly
    $script:Sys  = $env:SystemDrive.Substring(0, 1)
    $script:Dest = [System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady -and $_.DriveFormat -eq 'NTFS' -and $_.Name.Substring(0, 1) -ne $script:Sys } |
        Select-Object -First 1 | ForEach-Object { $_.Name.Substring(0, 1) }
}

Describe 'Free space and Recycle Bin, read-only' {
    It 'reports the same free bytes as Windows does' {
        $snap = Get-TriageSpaceSnapshot -Letter $script:Sys
        $real = (New-Object System.IO.DriveInfo ($script:Sys + ':\')).AvailableFreeSpace
        [math]::Abs($snap.FreeBytes - $real) | Should -BeLessThan 200MB
        $snap.Letter | Should -Be $script:Sys.ToUpper()
    }
    It 'can read the size of the current user''s Recycle Bin' {
        $bin = Get-TriageRecycleBinInfo -Letter $script:Sys
        $bin.Known | Should -BeTrue
        $bin.Items | Should -BeGreaterOrEqual 0
        $bin.Bytes | Should -BeGreaterOrEqual 0
    }
    It 'answers "unknown", not zero, for a drive that does not exist' {
        $free = [char[]](70..90) | Where-Object { -not (Test-Path -LiteralPath ($_ + ':\')) } | Select-Object -First 1
        (Get-TriageSpaceSnapshot -Letter ([string]$free)).FreeBytes | Should -Be -1
    }
    It 'words the change with both figures, the difference and what the bin still holds' {
        $before = [pscustomobject]@{ Letter = 'C'; FreeBytes = [long]10GB; BinBytes = [long]0; BinItems = 0; BinKnown = $true }
        $after  = [pscustomobject]@{ Letter = 'C'; FreeBytes = [long]10GB; BinBytes = [long]2GB; BinItems = 1; BinKnown = $true }
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        $old = [System.Threading.Thread]::CurrentThread.CurrentCulture
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $inv
        try {
            Format-TriageSpaceChange -Before $before -After $after | Should -Be 'C: free 10.00 GB -> 10.00 GB (+0 KB). Recycle Bin on C: holds 2.00 GB.'
            $after.FreeBytes = [long]12GB; $after.BinBytes = 0
            Format-TriageSpaceChange -Before $before -After $after | Should -Be 'C: free 10.00 GB -> 12.00 GB (+2.00 GB). Recycle Bin on C: holds 0 KB.'
            $after.FreeBytes = [long]9GB
            Format-TriageSpaceChange -Before $before -After $after | Should -BeLike '*(-1.00 GB)*'
        } finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $old }
    }
    It 'refuses to empty anything that is not a local fixed drive letter' {
        { Clear-TriageRecycleBin -Letter 'CD' -LogDirectory $env:TEMP }  | Should -Throw '*Refused*'
        { Clear-TriageRecycleBin -Letter '\\' -LogDirectory $env:TEMP }  | Should -Throw '*Refused*'
        $free = [char[]](70..90) | Where-Object { -not (Test-Path -LiteralPath ($_ + ':\')) } | Select-Object -First 1
        { Clear-TriageRecycleBin -Letter ([string]$free) -LogDirectory $env:TEMP } | Should -Throw '*Refused*'
    }
}

Describe 'Store-move plan' -Skip:$script:NoOtherDrive {
    BeforeAll {
        $script:SavedHf = [Environment]::GetEnvironmentVariable('HF_HOME', 'User')
        [Environment]::SetEnvironmentVariable('HF_HOME', $null, 'User')
        $script:HfSource = Join-Path $env:USERPROFILE '.cache\huggingface'
        $script:MadeHf   = -not (Test-Path -LiteralPath $script:HfSource)
        if ($script:MadeHf) { New-Item -ItemType Directory -Path $script:HfSource -Force | Out-Null }
    }
    AfterAll {
        [Environment]::SetEnvironmentVariable('HF_HOME', $script:SavedHf, 'User')
        if ($script:MadeHf -and (Test-Path -LiteralPath $script:HfSource)) { Remove-Item -LiteralPath $script:HfSource -Recurse -Force }
    }
    It 'says for every store whether its files can move, and why not' {
        $plan = @(Get-TriageRedirectPlan -Result (Get-SampleTriageResult) -DestinationDrive $script:Dest)
        foreach ($p in $plan) {
            $p.MoveState | Should -BeIn @('Ready', 'Blocked')
            if ($p.MoveState -eq 'Blocked') { $p.MoveReason | Should -Not -BeNullOrEmpty }
        }
        ($plan | Where-Object Variable -eq 'HF_HOME').MoveState | Should -Be 'Ready'
    }
    It 'offers to move the old files when the setting already points at the tool''s own folder' {
        $target = $script:TriageRedirectTargets | Where-Object Variable -eq 'HF_HOME'
        [Environment]::SetEnvironmentVariable('HF_HOME', (Get-TriageRedirectFolder -Letter $script:Dest -Target $target), 'User')
        try {
            $hf = @(Get-TriageRedirectPlan -Result (Get-SampleTriageResult) -DestinationDrive $script:Dest) | Where-Object Variable -eq 'HF_HOME'
            $hf.State     | Should -Be 'AlreadySet'
            $hf.MoveState | Should -Be 'Ready'
        } finally { [Environment]::SetEnvironmentVariable('HF_HOME', $null, 'User') }
    }
    It 'does not offer it when the setting points anywhere else' {
        [Environment]::SetEnvironmentVariable('HF_HOME', 'E:\somewhere', 'User')
        try {
            $hf = @(Get-TriageRedirectPlan -Result (Get-SampleTriageResult) -DestinationDrive $script:Dest) | Where-Object Variable -eq 'HF_HOME'
            $hf.MoveState | Should -Be 'Blocked'
        } finally { [Environment]::SetEnvironmentVariable('HF_HOME', $null, 'User') }
    }
    It 'blocks every move when the destination is the drive being cleaned' {
        $plan = @(Get-TriageRedirectPlan -Result (Get-SampleTriageResult) -DestinationDrive $script:Sys)
        @($plan | Where-Object MoveState -ne 'Blocked').Count | Should -Be 0
    }
}

Describe 'Move-TriageStore refuses anything outside its narrow job' -Skip:$script:NoOtherDrive {
    It 'refuses a variable that is not on the list, and any folder but the expected one' {
        { Move-TriageStore -Item ([pscustomobject]@{ Variable = 'PATH'; ProposedValue = "$($script:Dest):\FromC\Users\x\y" }) -LogDirectory $env:TEMP } | Should -Throw '*Not a variable*'
        $target = $script:TriageRedirectTargets | Where-Object Variable -eq 'TRITON_CACHE_DIR'
        $value  = Get-TriageRedirectFolder -Letter $script:Dest -Target $target
        foreach ($bad in @("$($script:Dest):\Windows\.triton\cache", '\\server\share\x', ($value + '\deeper'), ($script:Sys + $value.Substring(1)))) {
            { Move-TriageStore -Item ([pscustomobject]@{ Variable = 'TRITON_CACHE_DIR'; ProposedValue = $bad }) -LogDirectory $env:TEMP } | Should -Throw '*Refused*' -Because $bad
        }
    }
}

Describe 'Session summary' {
    It 'contains sizes and counts but no path, user name or computer name' {
        $start = [pscustomobject]@{ Letter = 'C'; FreeBytes = [long]10GB; BinBytes = [long]0; BinItems = 0; BinKnown = $true }
        $now   = [pscustomobject]@{ Letter = 'C'; FreeBytes = [long]13GB; BinBytes = [long]0; BinItems = 0; BinKnown = $true }
        $records = @(
            [pscustomobject]@{ Action = 'Move store'; SizeBytes = [long]3GB; Before = $start; After = $start }
            [pscustomobject]@{ Action = 'Empty Recycle Bin'; SizeBytes = [long]3GB; Before = $start; After = $now }
            [pscustomobject]@{ Action = 'Setting changed (nothing moved)'; SizeBytes = [long]0; Before = $null; After = $null }
        )
        $text = Get-TriageSessionSummary -Start $start -Now $now -Records $records
        $text | Should -Match 'free at start'
        $text | Should -Match '2\. Empty Recycle Bin'
        $text | Should -Not -Match '\\'
        $text.IndexOf($env:USERNAME, [System.StringComparison]::OrdinalIgnoreCase)     | Should -Be -1
        $text.IndexOf($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1
    }
    It 'says so when nothing was done' {
        Get-TriageSessionSummary -Start $null -Now $null -Records @() | Should -Match 'No action was carried out'
    }
}
