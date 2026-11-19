# The oracle (tests/oracle/expected_classifications.csv) was written from
# docs/SPEC.md by a reviewer that never saw the implementation. This test is
# the only place the two meet.

BeforeDiscovery {
    # Pester expands hashtable keys into variables for each case.
    $script:Cases = @(Import-Csv -LiteralPath (Join-Path $PSScriptRoot 'oracle\expected_classifications.csv') | ForEach-Object {
        @{ id = $_.id; path = $_.path; expected_bucket = $_.expected_bucket; spec_section = $_.spec_section; rationale = $_.rationale }
    })
}

BeforeAll {
    . (Join-Path $PSScriptRoot '..\DiskSpaceTriage.ps1') -ImportOnly
}

Describe 'Classification matches the independent oracle' {
    It 'has a meaningful number of cases' {
        @(Import-Csv -LiteralPath (Join-Path $PSScriptRoot 'oracle\expected_classifications.csv')).Count | Should -BeGreaterThan 200
    }

    It '<id> <path> is <expected_bucket>' -ForEach $script:Cases {
        (Get-TriageClassification -Path $path).Bucket | Should -Be $expected_bucket -Because "spec section $spec_section - $rationale"
    }
}

Describe 'Oracle file integrity' {
    It 'matches the recorded SHA-256 (the oracle is frozen; change it only with a recorded reason)' {
        $csv      = Join-Path $PSScriptRoot 'oracle\expected_classifications.csv'
        $expected = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'oracle\expected_classifications.sha256') -Raw).Trim().Split(' ')[0]
        (Get-FileHash -LiteralPath $csv -Algorithm SHA256).Hash.ToLower() | Should -Be $expected.ToLower()
    }
}
