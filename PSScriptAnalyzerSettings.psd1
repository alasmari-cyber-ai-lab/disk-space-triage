@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',                 # console mode is interactive output by design
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns',
        'PSReviewUnusedParameter',               # scriptblock parameters are positional by contract
        'PSUseBOMForUnicodeEncodedFile'          # the file is ASCII-only (enforced by a test)
    )
}
