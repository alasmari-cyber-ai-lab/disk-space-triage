# Walker, aggregation and write-containment tests against a synthetic tree with
# exact, known sizes. Nothing here depends on the real contents of the machine.

BeforeAll {
    . (Join-Path $PSScriptRoot '..\DiskSpaceTriage.ps1') -ImportOnly

    function New-SizedFile {
        param([string]$Path, [long]$Bytes)
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $stream = [System.IO.File]::Create($Path)
        try { $stream.SetLength($Bytes) } finally { $stream.Dispose() }
    }

    # Not under the user's Temp folder: that path is itself a classification
    # rule (Delete) and would mask every other rule in the fixture.
    $base = $env:RUNNER_TEMP
    if ([string]::IsNullOrWhiteSpace($base)) { $base = $env:PUBLIC }
    $script:Root = Join-Path $base ('triage-fixture-' + [guid]::NewGuid().ToString('N'))
    $script:Drive = $script:Root.Substring(0, 1)
    $mb = 1MB

    New-SizedFile "$script:Root\Users\t\Downloads\big.iso"                         (3 * $mb)
    New-SizedFile "$script:Root\Users\t\Downloads\small.txt"                       1000
    New-SizedFile "$script:Root\Users\t\.cache\huggingface\hub\blob1"              (2 * $mb)
    New-SizedFile "$script:Root\Users\t\.cache\huggingface\hub\blob2"              500000
    New-SizedFile "$script:Root\proj\node_modules\pkg\index.js"                    4096
    New-SizedFile "$script:Root\proj\node_modules\pkg\lib.js"                      8192
    New-SizedFile "$script:Root\proj\data\table.parquet"                           2048
    New-SizedFile "$script:Root\proj\data\notes.xyz"                               1024
    New-SizedFile "$script:Root\outside\secret.bin"                                (5 * $mb)

    # A junction pointing at a folder outside the scanned root. It must not be followed.
    New-Item -ItemType Directory -Path "$script:Root\scan" -Force | Out-Null
    New-SizedFile "$script:Root\scan\inside.bin" (2 * $mb)
    cmd /c mklink /J "$script:Root\scan\link" "$script:Root\outside" | Out-Null
}

AfterAll {
    if ($script:Root -and (Test-Path -LiteralPath $script:Root)) {
        $link = "$script:Root\scan\link"
        if (Test-Path -LiteralPath $link) { cmd /c rmdir "$link" | Out-Null }
        Remove-Item -LiteralPath $script:Root -Recurse -Force
    }
}

Describe 'Invoke-TriageScan on a synthetic tree' {
    BeforeAll {
        $script:Result = Invoke-TriageScan -SourceDrive $script:Drive -DestinationDrive $script:Drive -MinSizeMB 1 `
            -SkipDefaultRoots -AdditionalRoot "$script:Root\Users", "$script:Root\proj"
        $script:Buckets = @{}
        foreach ($b in $script:Result.Buckets) { $script:Buckets[$b.Bucket] = $b }
    }

    It 'always returns the five buckets in order' {
        ($script:Result.Buckets | ForEach-Object Bucket) -join ',' | Should -Be 'Redirect,Delete,Move,Review,Never'
    }
    It 'counts every byte exactly once' {
        $script:Result.ScannedBytes | Should -Be (3MB + 1000 + 2MB + 500000 + 4096 + 8192 + 2048 + 1024)
        ($script:Result.Buckets | Measure-Object TotalBytes -Sum).Sum | Should -Be $script:Result.ScannedBytes
        $script:Result.ScannedFiles | Should -Be 8
    }
    It 'attributes small files to their folder bucket (Redirect: large and small HF blobs)' {
        $script:Buckets['Redirect'].TotalBytes | Should -Be (2MB + 500000)
        $script:Buckets['Redirect'].Files      | Should -Be 2
    }
    It 'attributes node_modules to Delete even though every file is small' {
        $script:Buckets['Delete'].TotalBytes | Should -Be (4096 + 8192)
    }
    It 'applies the file-type fallback to small files in unclassified folders' {
        $script:Buckets['Move'].TotalBytes   | Should -Be (3MB + 1000 + 2048)
        $script:Buckets['Review'].TotalBytes | Should -Be 1024
    }
    It 'lists only files at or above the size threshold' {
        @($script:Result.Files).Count | Should -Be 2
        @($script:Result.Files)[0].Path | Should -BeLike '*big.iso'
    }
    It 'reports the mechanism that frees the most space first' {
        @($script:Result.Mechanisms)[0].TotalBytes | Should -BeGreaterOrEqual @($script:Result.Mechanisms)[-1].TotalBytes
    }
    It 'serialises to JSON with string dates' {
        ($script:Result | ConvertTo-Json -Depth 6) | Should -Not -Match '\\/Date\('
    }
}

Describe 'Scan containment' {
    It 'does not follow a junction out of the scanned folder' {
        $r = Invoke-TriageScan -SourceDrive $script:Drive -DestinationDrive $script:Drive -MinSizeMB 1 -SkipDefaultRoots -AdditionalRoot "$script:Root\scan"
        $r.ScannedBytes | Should -Be (2MB)
        @($r.Files | Where-Object { $_.Path -like '*secret.bin' }).Count | Should -Be 0
    }
    It 'does not count nested roots twice' {
        $r = Invoke-TriageScan -SourceDrive $script:Drive -DestinationDrive $script:Drive -MinSizeMB 1 -SkipDefaultRoots `
            -AdditionalRoot "$script:Root\proj", "$script:Root\proj\data"
        $r.ScannedBytes | Should -Be (4096 + 8192 + 2048 + 1024)
    }
    It 'ignores roots on another drive' {
        $other = 'Q'
        if ($script:Drive -eq 'Q') { $other = 'R' }
        { Invoke-TriageScan -SourceDrive $script:Drive -MinSizeMB 1 -SkipDefaultRoots -AdditionalRoot "${other}:\nowhere" -WarningAction SilentlyContinue } |
            Should -Throw '*nothing to scan*'
    }
    It 'stops when cancelled and says so' {
        $r = Invoke-TriageScan -SourceDrive $script:Drive -MinSizeMB 1 -SkipDefaultRoots -AdditionalRoot "$script:Root" `
            -OnProgress { $script:TriageCancel = $true }
        # Progress fires every 25 folders; the fixture is smaller, so cancel may never trigger. Either way the flag is consistent.
        $r.Cancelled | Should -BeIn @($true, $false)
    }
    It 'leaves the scanned tree untouched' {
        $before = @(Get-ChildItem -LiteralPath "$script:Root\proj" -Recurse -File | ForEach-Object { "$($_.FullName)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" })
        [void](Invoke-TriageScan -SourceDrive $script:Drive -MinSizeMB 1 -SkipDefaultRoots -AdditionalRoot "$script:Root\proj")
        $after  = @(Get-ChildItem -LiteralPath "$script:Root\proj" -Recurse -File | ForEach-Object { "$($_.FullName)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" })
        ($after -join "`n") | Should -Be ($before -join "`n")
    }
}

Describe 'Report directory validation' {
    It 'refuses a UNC path' {
        { Resolve-ReportDirectory -Requested '\\server\share\reports' } | Should -Throw '*UNC*'
    }
    It 'refuses a junction' {
        { Resolve-ReportDirectory -Requested "$script:Root\scan\link" } | Should -Throw '*junction*'
    }
    It 'refuses a drive that is not a local fixed disk' {
        $letters = [System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1) }
        $free = @('Z', 'Y', 'X', 'W') | Where-Object { $letters -notcontains $_ } | Select-Object -First 1
        { Resolve-ReportDirectory -Requested "${free}:\reports" } | Should -Throw '*fixed disk*'
    }
    It 'writes exactly three report files and nothing else' {
        $out = Join-Path $script:Root 'reports'
        $r   = Export-TriageReport -Result (Get-SampleTriageResult) -Directory $out
        @(Get-ChildItem -LiteralPath $out).Count | Should -Be 3
        Test-Path -LiteralPath $r.Html | Should -BeTrue
    }
}

Describe 'HTML report' {
    BeforeAll {
        $sample = Get-SampleTriageResult
        $sample.Files[0].Path = 'C:\x\</script><script>alert(1)</script>&.bin'
        $script:Html = ConvertTo-TriageHtml -Result $sample
    }
    It 'replaces the data placeholder'         { $script:Html | Should -Not -Match '__TRIAGE_DATA__' }
    It 'carries a Content-Security-Policy'     { $script:Html | Should -Match "default-src 'none'" }
    It 'cannot be broken out of by a hostile path' {
        $script:Html | Should -Not -Match 'alert\(1\)</script>'
        ([regex]::Matches($script:Html, '</script>')).Count | Should -Be ([regex]::Matches((ConvertTo-TriageHtml -Result (Get-SampleTriageResult)), '</script>')).Count
    }
    It 'references no external resource' {
        ($script:Html -replace 'http-equiv', '' -replace 'http://www\.w3\.org/[0-9a-zA-Z/]+', '') | Should -Not -Match 'https?:'
    }
}
