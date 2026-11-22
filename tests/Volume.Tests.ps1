# The claim that matters: after an action, the drive really has more free
# space. Proven on two throw-away NTFS volumes (virtual disks created by the
# CI job), never on a real drive: these tests EMPTY the Recycle Bin of the
# source volume.
#
# They run only when both variables name such volumes:
#   TRIAGE_VOLUME_SOURCE = letter of the volume to free      (e.g. S)
#   TRIAGE_VOLUME_DEST   = letter of the volume to move to   (e.g. T)

BeforeDiscovery {
    $script:NoVolumes = [string]::IsNullOrEmpty($env:TRIAGE_VOLUME_SOURCE) -or [string]::IsNullOrEmpty($env:TRIAGE_VOLUME_DEST)
}

BeforeAll {
    # Discovery-time variables do not exist at run time; work it out again.
    $script:NoVolumes = [string]::IsNullOrEmpty($env:TRIAGE_VOLUME_SOURCE) -or [string]::IsNullOrEmpty($env:TRIAGE_VOLUME_DEST)
    . (Join-Path $PSScriptRoot '..\DiskSpaceTriage.ps1') -ImportOnly

    $script:S = [string]$env:TRIAGE_VOLUME_SOURCE
    $script:T = [string]$env:TRIAGE_VOLUME_DEST
    $script:Payload = 40MB
    $script:Slack   = 6MB          # file-system bookkeeping may move this much

    function New-RandomFile {
        # Real, incompressible bytes: a sparse or empty file would prove nothing.
        param([string]$Path, [long]$Bytes, [int]$Seed)
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $random = New-Object System.Random $Seed
        $buffer = New-Object byte[] (1MB)
        $stream = [System.IO.File]::Create($Path)
        try {
            $left = $Bytes
            while ($left -gt 0) {
                $random.NextBytes($buffer)
                $n = [int][math]::Min([long]$buffer.Length, $left)
                $stream.Write($buffer, 0, $n)
                $left -= $n
            }
            $stream.Flush($true)
        } finally { $stream.Dispose() }
    }

    function Get-Free { param([string]$Letter) (New-Object System.IO.DriveInfo ($Letter + ':\')).AvailableFreeSpace }

    function Wait-Free {
        # NTFS can take a moment to return clusters; wait for the figure to move.
        param([string]$Letter, [long]$AtLeast)
        $now = [long]0
        foreach ($try in 1..40) {
            $now = Get-Free -Letter $Letter
            if ($now -ge $AtLeast) { break }
            Start-Sleep -Milliseconds 250
        }
        return $now
    }

    if (-not $script:NoVolumes) {
        $script:SavedProfile = $env:USERPROFILE
        $script:SavedVar     = [Environment]::GetEnvironmentVariable('TRITON_CACHE_DIR', 'User')
        $script:SavedKeras   = [Environment]::GetEnvironmentVariable('KERAS_HOME', 'User')
        [Environment]::SetEnvironmentVariable('TRITON_CACHE_DIR', $null, 'User')
        [Environment]::SetEnvironmentVariable('KERAS_HOME', $null, 'User')
        # The stores of a pretend user who lives on the source volume.
        $env:USERPROFILE = "$($script:S):\Users\ci"
        New-Item -ItemType Directory -Path $env:USERPROFILE -Force | Out-Null
        $script:Log = "$($script:T):\triage-log"
    }
}

AfterAll {
    if (-not $script:NoVolumes) {
        $env:USERPROFILE = $script:SavedProfile
        [Environment]::SetEnvironmentVariable('TRITON_CACHE_DIR', $script:SavedVar, 'User')
        [Environment]::SetEnvironmentVariable('KERAS_HOME', $script:SavedKeras, 'User')
    }
}

Describe 'Test volumes' -Skip:$script:NoVolumes {
    It 'are two different, local, fixed NTFS volumes that are not the system drive' {
        $script:S | Should -Not -Be $script:T
        foreach ($letter in @($script:S, $script:T)) {
            $letter | Should -Not -Be $env:SystemDrive.Substring(0, 1)
            $facts = Get-DriveFacts -Letter $letter
            $facts.Type   | Should -Be 'Fixed'
            $facts.Format | Should -Be 'NTFS'
        }
        (Get-TriageRecycleBinInfo -Letter $script:S).Known | Should -BeTrue
    }
}

Describe 'Delete: the space comes back when the Recycle Bin is emptied' -Skip:$script:NoVolumes {
    BeforeAll {
        $script:Proj = "$($script:S):\work\proj"
        New-RandomFile -Path "$script:Proj\node_modules\pkg\big.bin" -Bytes $script:Payload -Seed 1
        Set-Content -LiteralPath "$script:Proj\package.json" -Value '{}'
        Set-Content -LiteralPath "$script:Proj\package-lock.json" -Value '{}'
        $script:Free0 = Get-Free -Letter $script:S
    }
    It 'sends the folder to the Recycle Bin - and that alone frees nothing (the reported bug)' {
        $script:Rec = Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Proj\node_modules" }) -LogDirectory $script:Log
        $script:Rec.StillExists | Should -BeFalse
        Test-Path -LiteralPath "$script:Proj\node_modules" | Should -BeFalse
        $free1 = Get-Free -Letter $script:S
        [math]::Abs($free1 - $script:Free0) | Should -BeLessThan $script:Slack -Because 'the folder is still on this volume, inside the Recycle Bin'
    }
    It 'measures that, and says where the space is' {
        $script:Rec.After.BinBytes | Should -BeGreaterOrEqual $script:Payload
        $script:Rec.After.BinItems | Should -BeGreaterOrEqual 1
        [math]::Abs($script:Rec.After.FreeBytes - $script:Rec.Before.FreeBytes) | Should -BeLessThan $script:Slack
        $script:Rec.Space | Should -Match 'Recycle Bin on .: holds'
    }
    It 'frees the space when the Recycle Bin is emptied, and reports the measured gain' {
        $empty = Clear-TriageRecycleBin -Letter $script:S -LogDirectory $script:Log
        $empty.Action         | Should -Be 'Empty Recycle Bin'
        $empty.After.BinItems | Should -Be 0
        $free2 = Wait-Free -Letter $script:S -AtLeast ($script:Free0 + $script:Payload - $script:Slack)
        ($free2 - $script:Free0) | Should -BeGreaterThan ($script:Payload - $script:Slack)
        Write-Host ("    Delete: free {0:N1} MB -> {1:N1} MB (+{2:N1} MB for a {3:N0} MB folder)" -f ($script:Free0 / 1MB), ($free2 / 1MB), (($free2 - $script:Free0) / 1MB), ($script:Payload / 1MB))
        @(Import-Csv -LiteralPath $empty.LogPath)[-1].Action | Should -Be 'Empty Recycle Bin'
    }
    It 'does nothing, and says so, when the Recycle Bin is already empty' {
        $again = Clear-TriageRecycleBin -Letter $script:S -LogDirectory $script:Log
        $again.Before.BinItems | Should -Be 0
        $again.Failure         | Should -Be ''
    }
}

Describe 'Move a file: it arrives intact and the space comes back' -Skip:$script:NoVolumes {
    BeforeAll {
        $script:File   = "$($script:S):\Datasets\run\weights.safetensors"
        $script:Target = "$($script:T):\FromC\Datasets\run\weights.safetensors"
        New-RandomFile -Path $script:File -Bytes $script:Payload -Seed 2
        $script:Hash   = (Get-FileHash -LiteralPath $script:File -Algorithm SHA256).Hash
        $script:Free0  = Get-Free -Letter $script:S
        $script:Dest0  = Get-Free -Letter $script:T
    }
    It 'copies, verifies and recycles the original' {
        $rec = Move-TriageFile -Item ([pscustomobject]@{ Path = $script:File; Target = $script:Target }) -LogDirectory $script:Log
        $rec.OriginalRecycled | Should -BeTrue
        (Get-FileHash -LiteralPath $script:Target -Algorithm SHA256).Hash | Should -Be $script:Hash
        $rec.After.BinBytes | Should -BeGreaterOrEqual $script:Payload
        ($script:Dest0 - (Get-Free -Letter $script:T)) | Should -BeGreaterThan ($script:Payload - $script:Slack)
    }
    It 'frees the source volume once the Recycle Bin is emptied' {
        [void](Clear-TriageRecycleBin -Letter $script:S -LogDirectory $script:Log)
        $free2 = Wait-Free -Letter $script:S -AtLeast ($script:Free0 + $script:Payload - $script:Slack)
        ($free2 - $script:Free0) | Should -BeGreaterThan ($script:Payload - $script:Slack)
        Write-Host ("    Move file: free {0:N1} MB -> {1:N1} MB (+{2:N1} MB)" -f ($script:Free0 / 1MB), ($free2 / 1MB), (($free2 - $script:Free0) / 1MB))
    }
}

Describe 'Move a store: contents, setting and space' -Skip:$script:NoVolumes {
    BeforeAll {
        $script:Var    = 'TRITON_CACHE_DIR'
        $script:Store  = Join-Path $env:USERPROFILE '.triton\cache'
        $script:Tgt    = $script:TriageRedirectTargets | Where-Object Variable -eq $script:Var
        $script:Value  = Get-TriageRedirectFolder -Letter $script:T -Target $script:Tgt
        $script:Item   = [pscustomobject]@{ Variable = $script:Var; ProposedValue = $script:Value }
        New-RandomFile -Path "$script:Store\a\big.bin" -Bytes $script:Payload -Seed 3
        New-RandomFile -Path "$script:Store\a\b\small.bin" -Bytes 300KB -Seed 4
        New-Item -ItemType Directory -Path "$script:Store\empty" -Force | Out-Null
        $script:HashBig   = (Get-FileHash -LiteralPath "$script:Store\a\big.bin" -Algorithm SHA256).Hash
        $script:HashSmall = (Get-FileHash -LiteralPath "$script:Store\a\b\small.bin" -Algorithm SHA256).Hash
        $script:Free0 = Get-Free -Letter $script:S
    }
    It 'keeps the folder at the same place below FromC, under the pretend user' {
        $script:Value | Should -Be "$($script:T):\FromC\Users\ci\.triton\cache"
    }
    It 'takes back every copy and changes nothing when cancelled part-way' {
        { Move-TriageStore -Item $script:Item -LogDirectory $script:Log -OnProgress { param($stage, $done, $total) if ($done -gt 8MB) { $script:TriageCancel = $true } } } | Should -Throw '*Cancelled*'
        [Environment]::GetEnvironmentVariable($script:Var, 'User') | Should -BeNullOrEmpty
        @(Get-ChildItem -LiteralPath "$($script:T):\FromC\Users\ci" -Recurse -File -Force -ErrorAction SilentlyContinue).Count | Should -Be 0
        Test-Path -LiteralPath $script:Value | Should -BeFalse
        (Get-FileHash -LiteralPath "$script:Store\a\big.bin" -Algorithm SHA256).Hash | Should -Be $script:HashBig
    }
    It 'refuses a store that contains a junction, and changes nothing' {
        cmd /c mklink /J "$script:Store\a\link" "$($script:S):\work" | Out-Null
        try {
            { Move-TriageStore -Item $script:Item -LogDirectory $script:Log } | Should -Throw '*link*'
            [Environment]::GetEnvironmentVariable($script:Var, 'User') | Should -BeNullOrEmpty
            Test-Path -LiteralPath $script:Value | Should -BeFalse
        } finally { cmd /c rmdir "$script:Store\a\link" | Out-Null }
    }
    It 'refuses a new folder that somebody else already filled' {
        New-Item -ItemType Directory -Path $script:Value -Force | Out-Null
        Set-Content -LiteralPath "$script:Value\planted.txt" -Value 'x'
        try {
            { Move-TriageStore -Item $script:Item -LogDirectory $script:Log } | Should -Throw '*not empty*'
        } finally { Remove-Item -LiteralPath "$script:Value\planted.txt" -Force }
        Test-Path -LiteralPath "$script:Store\a\big.bin" | Should -BeTrue
    }
    It 'copies and verifies every file, sets the variable, and recycles the old folder' {
        $script:Rec = Move-TriageStore -Item $script:Item -LogDirectory $script:Log
        $script:Rec.Action           | Should -Be 'Move store'
        $script:Rec.OriginalRecycled | Should -BeTrue
        $script:Rec.Copied           | Should -Be 2
        (Get-FileHash -LiteralPath "$script:Value\a\big.bin" -Algorithm SHA256).Hash     | Should -Be $script:HashBig
        (Get-FileHash -LiteralPath "$script:Value\a\b\small.bin" -Algorithm SHA256).Hash | Should -Be $script:HashSmall
        Test-Path -LiteralPath "$script:Value\empty" -PathType Container | Should -BeTrue
        @(Get-ChildItem -LiteralPath $script:Value -Recurse -Force -Filter '*.triage-partial').Count | Should -Be 0
        [Environment]::GetEnvironmentVariable($script:Var, 'User')    | Should -Be $script:Value
        [Environment]::GetEnvironmentVariable($script:Var, 'Machine') | Should -BeNullOrEmpty
        Test-Path -LiteralPath $script:Store | Should -BeFalse
        $actions = @(Import-Csv -LiteralPath $script:Rec.LogPath | ForEach-Object Action)
        $actions | Should -Contain 'Set'
        $actions[-1] | Should -Be 'Move store'
    }
    It 'frees the source volume once the Recycle Bin is emptied' {
        [void](Clear-TriageRecycleBin -Letter $script:S -LogDirectory $script:Log)
        $free2 = Wait-Free -Letter $script:S -AtLeast ($script:Free0 + $script:Payload - $script:Slack)
        ($free2 - $script:Free0) | Should -BeGreaterThan ($script:Payload - $script:Slack)
        Write-Host ("    Move store: free {0:N1} MB -> {1:N1} MB (+{2:N1} MB)" -f ($script:Free0 / 1MB), ($free2 / 1MB), (($free2 - $script:Free0) / 1MB))
    }
    It 'moves files that reappear in the old place into the folder already in use, without overwriting' {
        # The variable now points at the new folder. A tool that ignored it wrote to the old place again.
        New-RandomFile -Path "$script:Store\late\new.bin" -Bytes 200KB -Seed 5
        New-Item -ItemType Directory -Path "$script:Store\a" -Force | Out-Null
        Copy-Item -LiteralPath "$script:Value\a\b\small.bin" -Destination "$script:Store\a\same.bin"
        Copy-Item -LiteralPath "$script:Value\a\b\small.bin" -Destination "$script:Value\a\same.bin"
        Set-Content -LiteralPath "$script:Store\a\differs.txt" -Value 'old'
        Set-Content -LiteralPath "$script:Value\a\differs.txt" -Value 'new'
        $rec = Move-TriageStore -Item $script:Item -LogDirectory $script:Log
        $rec.Copied | Should -Be 1
        $rec.Same   | Should -Be 1
        $rec.Kept   | Should -Be 1 -Because 'this store is a pure cache, so the file already in use wins'
        (Get-Content -LiteralPath "$script:Value\a\differs.txt" -Raw).Trim() | Should -Be 'new'
        Test-Path -LiteralPath "$script:Value\late\new.bin" | Should -BeTrue
        Test-Path -LiteralPath $script:Store | Should -BeFalse
    }
}

Describe 'Move a store that is not a pure cache' -Skip:$script:NoVolumes {
    It 'stops, and removes nothing, when both folders hold different versions of a file' {
        $store  = Join-Path $env:USERPROFILE '.keras'
        $target = $script:TriageRedirectTargets | Where-Object Variable -eq 'KERAS_HOME'
        $value  = Get-TriageRedirectFolder -Letter $script:T -Target $target
        New-Item -ItemType Directory -Path $store -Force | Out-Null
        Set-Content -LiteralPath "$store\keras.json" -Value '{"backend":"old"}'
        $item = [pscustomobject]@{ Variable = 'KERAS_HOME'; ProposedValue = $value }
        [void](Set-TriageRedirect -Item $item -LogDirectory $script:Log)
        Set-Content -LiteralPath "$value\keras.json" -Value '{"backend":"new"}'
        { Move-TriageStore -Item $item -LogDirectory $script:Log } | Should -Throw '*different contents*'
        (Get-Content -LiteralPath "$store\keras.json" -Raw).Trim() | Should -Be '{"backend":"old"}'
        (Get-Content -LiteralPath "$value\keras.json" -Raw).Trim() | Should -Be '{"backend":"new"}'
    }
}

Describe 'What a user would paste into a bug report' -Skip:$script:NoVolumes {
    It 'is a summary with the measured figures and no path' {
        $start = Get-TriageSpaceSnapshot -Letter $script:S
        $text  = Get-TriageSessionSummary -Start $start -Now $start -Records @([pscustomobject]@{ Action = 'Move store'; SizeBytes = [long]$script:Payload; Before = $start; After = $start })
        $text | Should -Match 'Recycle Bin on'
        $text | Should -Not -Match '\\'
        Write-Host $text
    }
}
