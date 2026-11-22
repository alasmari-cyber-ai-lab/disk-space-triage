# Delete (send a rebuildable store folder to the Recycle Bin) and Move (copy,
# verify by SHA-256, then recycle the original). Everything runs on synthetic
# folders created here; nothing outside them is touched.

BeforeDiscovery {
    $sys = $env:SystemDrive.Substring(0, 1)
    $script:OtherDrive = [System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady -and $_.DriveFormat -eq 'NTFS' -and $_.Name.Substring(0, 1) -ne $sys } |
        Select-Object -First 1 | ForEach-Object { $_.Name.Substring(0, 1) }
    $script:NoOtherDrive = [string]::IsNullOrEmpty($script:OtherDrive)
}

BeforeAll {
    . (Join-Path $PSScriptRoot '..\DiskSpaceTriage.ps1') -ImportOnly

    function New-SizedFile {
        param([string]$Path, [long]$Bytes)
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $stream = [System.IO.File]::Create($Path)
        try { $stream.SetLength($Bytes) } finally { $stream.Dispose() }
    }

    $sys = $env:SystemDrive.Substring(0, 1)
    $script:Dest = [System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady -and $_.DriveFormat -eq 'NTFS' -and $_.Name.Substring(0, 1) -ne $sys } |
        Select-Object -First 1 | ForEach-Object { $_.Name.Substring(0, 1) }

    # The fixture lives on the system drive (so another drive can be the
    # destination), outside Temp and outside any known folder.
    $script:Tag  = 'triage-dm-' + [guid]::NewGuid().ToString('N')
    $script:Root = Join-Path $env:PUBLIC $script:Tag
    $script:Src  = $script:Root.Substring(0, 1)
    $script:Log  = Join-Path $script:Root 'log'

    # Delete fixtures
    New-SizedFile "$script:Root\good\node_modules\pkg\index.js" 4096
    New-SizedFile "$script:Root\good\node_modules\pkg\sub\lib.js" 2048
    Set-Content -LiteralPath "$script:Root\good\package-lock.json" -Value '{}'
    Set-Content -LiteralPath "$script:Root\good\package.json" -Value '{}'
    # A lockfile but no package.json
    New-SizedFile "$script:Root\nopkg\node_modules\pkg\index.js" 4096
    Set-Content -LiteralPath "$script:Root\nopkg\package-lock.json" -Value '{}'
    # Somebody's document inside node_modules (small, so only the file-type check can see it)
    New-SizedFile "$script:Root\work\node_modules\pkg\index.js" 4096
    New-SizedFile "$script:Root\work\node_modules\pkg\thesis.docx" 2048
    Set-Content -LiteralPath "$script:Root\work\package-lock.json" -Value '{}'
    Set-Content -LiteralPath "$script:Root\work\package.json" -Value '{}'
    # An application's own node_modules, with a lockfile, below an AppData-style path
    New-SizedFile "$script:Root\AppData\Local\Programs\app\resources\app\node_modules\x\index.js" 4096
    Set-Content -LiteralPath "$script:Root\AppData\Local\Programs\app\resources\app\package-lock.json" -Value '{}'
    Set-Content -LiteralPath "$script:Root\AppData\Local\Programs\app\resources\app\package.json" -Value '{}'
    # A real browser cache folder, and a site database whose name merely contains "cache"
    New-SizedFile "$script:Root\AppData\Local\Vendor\User Data\Default\Cache\data_1" 8192
    New-SizedFile "$script:Root\AppData\Local\Vendor\User Data\Default\IndexedDB\https_cachefly.net_0.indexeddb.leveldb\000003.log" 8192
    New-SizedFile "$script:Root\nolock\node_modules\pkg\index.js" 4096
    New-SizedFile "$script:Root\mixed\node_modules\pkg\index.js" 4096
    New-SizedFile "$script:Root\mixed\node_modules\pkg\disk.vhdx" (2MB)
    Set-Content -LiteralPath "$script:Root\mixed\package-lock.json" -Value '{}'
    Set-Content -LiteralPath "$script:Root\mixed\package.json" -Value '{}'
    New-SizedFile "$script:Root\linked\node_modules\pkg\index.js" 4096
    Set-Content -LiteralPath "$script:Root\linked\package-lock.json" -Value '{}'
    Set-Content -LiteralPath "$script:Root\linked\package.json" -Value '{}'
    New-Item -ItemType Directory -Path "$script:Root\elsewhere" -Force | Out-Null
    New-SizedFile "$script:Root\elsewhere\keep.txt" 100
    cmd /c mklink /J "$script:Root\linked\node_modules\pkg\link" "$script:Root\elsewhere" | Out-Null
    New-SizedFile "$script:Root\crate\target\debug\app.exe" 8192
    Set-Content -LiteralPath "$script:Root\crate\Cargo.toml" -Value '[package]'
    New-SizedFile "$script:Root\notrust\target\debug\thing.bin" 8192

    # Move fixtures: real bytes, so the hash means something.
    $bytes = New-Object byte[] (3MB)
    (New-Object System.Random 7).NextBytes($bytes)
    New-Item -ItemType Directory -Path "$script:Root\data" -Force | Out-Null
    [System.IO.File]::WriteAllBytes("$script:Root\data\weights.safetensors", $bytes)
    [System.IO.File]::WriteAllBytes("$script:Root\data\second.parquet", $bytes)
    [System.IO.File]::WriteAllBytes("$script:Root\data\third.parquet", $bytes)
    [System.IO.File]::SetLastWriteTimeUtc("$script:Root\data\weights.safetensors", [datetime]'2024-03-02T10:20:30Z')
    New-SizedFile "$script:Root\steamapps\common\game\data.pak" (2MB)

    $script:Result = Invoke-TriageScan -SourceDrive $script:Src -DestinationDrive $script:Src -MinSizeMB 1 -SkipDefaultRoots -AdditionalRoot $script:Root
    $script:FromC = ''
    if ($script:Dest) { $script:FromC = "$($script:Dest):\FromC" + $script:Root.Substring(2) }
}

AfterAll {
    if ($script:Root -and (Test-Path -LiteralPath $script:Root)) {
        $link = "$script:Root\linked\node_modules\pkg\link"
        if (Test-Path -LiteralPath $link) { cmd /c rmdir "$link" | Out-Null }
        Remove-Item -LiteralPath $script:Root -Recurse -Force
    }
    if ($script:FromC -and (Test-Path -LiteralPath $script:FromC)) { Remove-Item -LiteralPath $script:FromC -Recurse -Force }
}

Describe 'Test environment' {
    It 'is an interactive desktop with a second NTFS drive on CI, so every test below really runs' {
        if ($env:CI) {
            [Environment]::UserInteractive | Should -BeTrue
            $script:Dest | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Delete plan' {
    BeforeAll {
        $script:DPlan = @(Get-TriageDeletePlan -Result $script:Result)
        $script:ByPath = @{}
        foreach ($p in $script:DPlan) { $script:ByPath[$p.Path] = $p }
    }
    It 'offers the top folder of each store, once' {
        $script:ByPath.ContainsKey("$script:Root\good\node_modules")         | Should -BeTrue
        $script:ByPath.ContainsKey("$script:Root\good\node_modules\pkg")     | Should -BeFalse
        $script:ByPath["$script:Root\good\node_modules"].SizeBytes           | Should -Be (4096 + 2048)
        $script:ByPath["$script:Root\good\node_modules"].State               | Should -Be 'Ready'
    }
    It 'blocks node_modules without a lockfile'    { $script:ByPath["$script:Root\nolock\node_modules"].State | Should -Be 'Blocked' }
    It 'blocks node_modules without a package.json' { $script:ByPath["$script:Root\nopkg\node_modules"].State | Should -Be 'Blocked' }
    It 'blocks a store that contains somebody''s document, however small' {
        $script:ByPath["$script:Root\work\node_modules"].State  | Should -Be 'Blocked'
        $script:ByPath["$script:Root\work\node_modules"].Reason | Should -BeLike '*thesis.docx*'
    }
    It 'blocks node_modules that belong to an installed application' {
        $script:ByPath["$script:Root\AppData\Local\Programs\app\resources\app\node_modules"].State | Should -Be 'Blocked'
    }
    It 'offers a real cache folder but not a site database whose name contains "cache"' {
        $script:ByPath["$script:Root\AppData\Local\Vendor\User Data\Default\Cache"].State | Should -Be 'Ready'
        $script:ByPath["$script:Root\AppData\Local\Vendor\User Data\Default\IndexedDB\https_cachefly.net_0.indexeddb.leveldb"].State | Should -Be 'Blocked'
    }
    It 'blocks a store larger than the Recycle Bin would take' {
        $big = [pscustomobject]@{ Path = "$script:Root\good\node_modules"; Match = ''; Note = 'node_modules; needs a package-lock file to rebuild, never copy'
                                  TotalBytes = [long]4000GB; Files = [long]1; Mixed = $false; Incomplete = $false; HasLink = $false; Personal = ''; LongPath = $false }
        @(Get-TriageDeletePlan -Result ([pscustomobject]@{ DeleteCandidates = @($big) }))[0].Reason | Should -BeLike '*too large*'
        $big.TotalBytes = [long]10; $big.LongPath = $true
        @(Get-TriageDeletePlan -Result ([pscustomobject]@{ DeleteCandidates = @($big) }))[0].Reason | Should -BeLike '*too long*'
    }
    It 'blocks a store that contains foreign files' { $script:ByPath["$script:Root\mixed\node_modules"].State  | Should -Be 'Blocked' }
    It 'blocks a store that contains a junction'    { $script:ByPath["$script:Root\linked\node_modules"].State | Should -Be 'Blocked' }
    It 'accepts Rust output only beside a Cargo.toml' {
        $script:ByPath["$script:Root\crate\target\debug"].State   | Should -Be 'Ready'
        $script:ByPath["$script:Root\notrust\target\debug"].State | Should -Be 'Blocked'
    }
}

Describe 'Remove-TriageStore' {
    It 'refuses a folder that is not a store' {
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\data" }) -LogDirectory $script:Log } | Should -Throw '*Refused*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = $script:Root }) -LogDirectory $script:Log }        | Should -Throw '*Refused*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = $env:USERPROFILE }) -LogDirectory $script:Log }    | Should -Throw '*Refused*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$($script:Src):\Windows" }) -LogDirectory $script:Log } | Should -Throw '*Refused*'
    }
    It 'refuses a folder inside a store, and path tricks' {
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\good\node_modules\pkg" }) -LogDirectory $script:Log } | Should -Throw '*inside a store*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\good\node_modules\..\..\data" }) -LogDirectory $script:Log } | Should -Throw '*Refused*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\good\node_modules\" }) -LogDirectory $script:Log } | Should -Throw '*Refused*'
    }
    It 'refuses the blocked stores even when asked directly' {
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\nolock\node_modules" }) -LogDirectory $script:Log }   | Should -Throw '*lockfile*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\notrust\target\debug" }) -LogDirectory $script:Log } | Should -Throw '*Cargo.toml*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\mixed\node_modules" }) -LogDirectory $script:Log }   | Should -Throw '*another store*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\work\node_modules" }) -LogDirectory $script:Log }    | Should -Throw '*thesis.docx*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\nopkg\node_modules" }) -LogDirectory $script:Log }   | Should -Throw '*package.json*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\AppData\Local\Programs\app\resources\app\node_modules" }) -LogDirectory $script:Log } | Should -Throw '*application*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\AppData\Local\Vendor\User Data\Default\IndexedDB\https_cachefly.net_0.indexeddb.leveldb" }) -LogDirectory $script:Log } | Should -Throw '*not a plain cache*'
        { Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\linked\node_modules" }) -LogDirectory $script:Log }  | Should -Throw '*junction*'
    }
    It 'left everything in place after those refusals' {
        Test-Path -LiteralPath "$script:Root\good\node_modules\pkg\index.js" | Should -BeTrue
        Test-Path -LiteralPath "$script:Root\data\weights.safetensors"       | Should -BeTrue
        Test-Path -LiteralPath "$script:Root\elsewhere\keep.txt"             | Should -BeTrue
        Test-Path -LiteralPath "$script:Root\mixed\node_modules\pkg\disk.vhdx"  | Should -BeTrue
        Test-Path -LiteralPath "$script:Root\linked\node_modules\pkg\index.js" | Should -BeTrue
    }
    It 'removes exactly the one store folder and logs it' {
        $record = Remove-TriageStore -Item ([pscustomobject]@{ Path = "$script:Root\good\node_modules" }) -LogDirectory $script:Log
        Test-Path -LiteralPath "$script:Root\good\node_modules"      | Should -BeFalse
        Test-Path -LiteralPath "$script:Root\good\package-lock.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Root\nolock\node_modules"    | Should -BeTrue
        $record.Action      | Should -Be 'Recycle'
        $record.Space       | Should -Match 'Recycle Bin on'
        $record.After.BinBytes | Should -BeGreaterOrEqual (4096 + 2048) -Because 'what was recycled is still on the drive, in the Recycle Bin'
        $record.StillExists | Should -BeFalse
        @(Import-Csv -LiteralPath $record.LogPath)[-1].OldValue | Should -Be "$script:Root\good\node_modules"
    }
}

Describe 'Move plan' -Skip:$script:NoOtherDrive {
    BeforeAll { $script:MPlan = @(Get-TriageMovePlan -Result $script:Result -DestinationDrive $script:Dest) }
    It 'lists plain data files with the same path below FromC' {
        $w = $script:MPlan | Where-Object Path -eq "$script:Root\data\weights.safetensors"
        $w.State  | Should -Be 'Ready'
        $w.Target | Should -Be "$script:FromC\data\weights.safetensors"
    }
    It 'does not list files that belong to a game library' {
        @($script:MPlan | Where-Object Path -like '*steamapps*').Count | Should -Be 0
    }
    It 'judges movability by location and type' {
        Test-TriageMovableFile -Path 'C:\Datasets\run\train.parquet'                         | Should -Be ''
        Test-TriageMovableFile -Path 'C:\Users\a\Downloads\ubuntu.iso'                      | Should -Be ''
        Test-TriageMovableFile -Path 'C:\Users\a\Documents\repo\.git\objects\pack\p.zip'  | Should -Not -Be ''
        Test-TriageMovableFile -Path 'C:\Users\a\Documents\db\prod.mdf'                     | Should -Not -Be ''
        Test-TriageMovableFile -Path 'C:\Users\a\Documents\mail\archive.pst'                | Should -Not -Be ''
        Test-TriageMovableFile -Path 'C:\Users\a\AppData\Local\Packages\X\LocalState\m.onnx' | Should -Not -Be ''
        Test-TriageMovableFile -Path 'C:\ProgramData\Package Cache\{guid}\cab1.cab'          | Should -Not -Be ''
        Test-TriageMovableFile -Path 'C:\Users\a\iCloudDrive\film.mp4'                      | Should -Not -Be ''
        Test-TriageMovableFile -Path 'C:\Users\a\OneDrive - Contoso\big.zip'                | Should -Not -Be ''
        Test-TriageMovableFile -Path 'C:\Users\a\Pictures\iCloud Photos\Photos\clip.mov'    | Should -Not -Be ''
        Test-TriageMovableFile -Path 'C:\Users\ANACON~1\Downloads\x.iso'                    | Should -Not -Be ''
    }
    It 'blocks everything when the destination is the system drive' {
        $p = @(Get-TriageMovePlan -Result $script:Result -DestinationDrive $script:Src)
        @($p | Where-Object State -ne 'Blocked').Count | Should -Be 0
    }
}

Describe 'Move-TriageFile' -Skip:$script:NoOtherDrive {
    BeforeAll {
        $script:File   = "$script:Root\data\weights.safetensors"
        $script:Target = "$script:FromC\data\weights.safetensors"
        $script:Hash   = (Get-FileHash -LiteralPath $script:File -Algorithm SHA256).Hash
    }
    It 'refuses any target other than the one expected place' {
        foreach ($bad in @("$($script:Dest):\other\weights.safetensors", "$script:FromC\weights.safetensors", ($script:Target + '.bak'), "$($script:Src):\FromC" + $script:File.Substring(2))) {
            { Move-TriageFile -Item ([pscustomobject]@{ Path = $script:File; Target = $bad }) -LogDirectory $script:Log } | Should -Throw '*Refused*' -Because $bad
        }
    }
    It 'refuses a file that belongs to a program or store' {
        $pak = "$script:Root\steamapps\common\game\data.pak"
        { Move-TriageFile -Item ([pscustomobject]@{ Path = $pak; Target = (Get-TriageMoveTarget -Source $pak -Letter $script:Dest) }) -LogDirectory $script:Log } | Should -Throw '*Refused*'
    }
    It 'never overwrites an existing file' {
        $f = "$script:Root\data\third.parquet"; $t = "$script:FromC\data\third.parquet"
        New-Item -ItemType Directory -Path (Split-Path -Parent $t) -Force | Out-Null
        Set-Content -LiteralPath $t -Value 'already here'
        { Move-TriageFile -Item ([pscustomobject]@{ Path = $f; Target = $t }) -LogDirectory $script:Log } | Should -Throw '*overwritten*'
        (Get-Content -LiteralPath $t -Raw).Trim() | Should -Be 'already here'
        Test-Path -LiteralPath $f | Should -BeTrue
    }
    It 'leaves no partial copy and keeps the original when cancelled while copying' {
        $f = "$script:Root\data\second.parquet"; $t = "$script:FromC\data\second.parquet"
        { Move-TriageFile -Item ([pscustomobject]@{ Path = $f; Target = $t }) -LogDirectory $script:Log -OnProgress { $script:TriageCancel = $true } } | Should -Throw '*Cancelled*'
        Test-Path -LiteralPath $t                       | Should -BeFalse
        Test-Path -LiteralPath ($t + '.triage-partial') | Should -BeFalse
        Test-Path -LiteralPath $f                       | Should -BeTrue
    }
    It 'does the same when cancelled while verifying' {
        $f = "$script:Root\data\second.parquet"; $t = "$script:FromC\data\second.parquet"
        { Move-TriageFile -Item ([pscustomobject]@{ Path = $f; Target = $t }) -LogDirectory $script:Log -OnProgress { param($stage) if ($stage -eq 'Verifying') { $script:TriageCancel = $true } } } | Should -Throw '*Cancelled*'
        Test-Path -LiteralPath $t                       | Should -BeFalse
        Test-Path -LiteralPath ($t + '.triage-partial') | Should -BeFalse
        Test-Path -LiteralPath $f                       | Should -BeTrue
    }
    It 'refuses when a leftover from an interrupted move is in the way, and does not delete it' {
        $f = "$script:Root\data\second.parquet"; $t = "$script:FromC\data\second.parquet"
        Set-Content -LiteralPath ($t + '.triage-partial') -Value 'leftover'
        try {
            { Move-TriageFile -Item ([pscustomobject]@{ Path = $f; Target = $t }) -LogDirectory $script:Log } | Should -Throw '*leftover*'
            Test-Path -LiteralPath ($t + '.triage-partial') | Should -BeTrue
            Test-Path -LiteralPath $f | Should -BeTrue
        } finally { Remove-Item -LiteralPath ($t + '.triage-partial') -Force }
    }
    It 'refuses a hidden file' {
        $f = "$script:Root\data\second.parquet"; $t = "$script:FromC\data\second.parquet"
        (Get-Item -LiteralPath $f).Attributes = 'Hidden'
        try { { Move-TriageFile -Item ([pscustomobject]@{ Path = $f; Target = $t }) -LogDirectory $script:Log } | Should -Throw '*hidden*' }
        finally { (Get-Item -LiteralPath $f -Force).Attributes = 'Normal' }
    }
    It 'copies, verifies, keeps the timestamp, and only then removes the original' {
        $record = Move-TriageFile -Item ([pscustomobject]@{ Path = $script:File; Target = $script:Target }) -LogDirectory $script:Log
        Test-Path -LiteralPath $script:Target | Should -BeTrue
        (Get-FileHash -LiteralPath $script:Target -Algorithm SHA256).Hash | Should -Be $script:Hash
        $record.Sha256                         | Should -Be $script:Hash
        (Get-Item -LiteralPath $script:Target).LastWriteTimeUtc | Should -Be ([datetime]'2024-03-02T10:20:30Z').ToUniversalTime()
        $record.OriginalRecycled               | Should -BeTrue
        Test-Path -LiteralPath $script:File    | Should -BeFalse
        Test-Path -LiteralPath ($script:Target + '.triage-partial') | Should -BeFalse
        $logged = @(Import-Csv -LiteralPath $record.LogPath)[-1]
        $logged.NewValue | Should -Be $script:Target
        $logged.Detail   | Should -BeLike ('SHA256 ' + $script:Hash + '*free*')
        $record.Space    | Should -Match 'free .+ -> .+'
        $record.After.BinKnown | Should -BeTrue
    }
}
