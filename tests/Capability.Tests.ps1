# Capability allowlist. The security claims in the README are enforced here:
# the script is parsed (never executed) and every command, .NET type and
# sensitive call in it must be on a short list. Adding a network call, a
# process launch, dynamic code or a new write path fails the build.

BeforeAll {
    $script:ScriptPath = (Resolve-Path (Join-Path $PSScriptRoot '..\DiskSpaceTriage.ps1')).Path
    $tokens = $null; $errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
    $script:ParseErrors = $errors

    $script:Functions = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object { $_.Name })
    $script:Commands = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))

    function Get-EnclosingFunction {
        param($Node)
        $p = $Node.Parent
        while ($null -ne $p) {
            if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $p.Name }
            $p = $p.Parent
        }
        return '<script>'
    }

    $script:AllowedCommands = @(
        'Set-StrictMode', 'New-Object', 'Add-Type',
        'Write-Host', 'Write-Warning', 'Write-Verbose',
        'Where-Object', 'ForEach-Object', 'Select-Object', 'Sort-Object',
        'Format-Table', 'Out-Host', 'Out-Null',
        'Test-Path', 'Join-Path', 'Get-Date', 'ConvertTo-Json', 'Get-Item',
        'Out-File', 'Export-Csv', 'New-Item'
    )

    $script:AllowedTypes = @(
        'Environment', 'math', 'void', 'bool', 'char', 'double', 'int', 'long', 'object', 'string', 'string[]',
        'switch', 'hashtable', 'scriptblock', 'pscustomobject', 'Parameter', 'CmdletBinding',
        'ValidateSet', 'ValidatePattern', 'ValidateRange',
        'Security.Principal.WindowsIdentity', 'Security.Principal.WindowsBuiltInRole',
        'System.Action', 'System.StringComparison', 'System.Globalization.CultureInfo',
        'System.IO.FileAttributes', 'System.IO.Path', 'System.IO.File', 'System.IO.IOException',
        'System.UnauthorizedAccessException', 'System.Security.SecurityException',
        'System.Management.Automation.WildcardOptions', 'System.Text.RegularExpressions.RegexOptions',
        'System.Security.Cryptography.SHA256', 'System.BitConverter', 'System.IO.FileMode', 'System.IO.FileAccess', 'System.IO.FileShare',
        'Microsoft.VisualBasic.FileIO.FileSystem', 'Microsoft.VisualBasic.FileIO.UIOption', 'Microsoft.VisualBasic.FileIO.RecycleOption', 'Microsoft.VisualBasic.FileIO.UICancelOption',
        'System.Windows.Clipboard', 'System.Windows.MessageBox', 'System.Windows.MessageBoxButton',
        'System.Windows.MessageBoxImage', 'System.Windows.MessageBoxResult', 'System.Windows.Markup.XamlReader',
        'System.Windows.Media.Imaging.BitmapFrame', 'System.Windows.Media.PixelFormats',
        'System.Windows.Threading.DispatcherPriority'
    )

    $script:AllowedNewObject = @(
        'Security.Principal.WindowsPrincipal',
        'System.Collections.Generic.List[object]', 'System.Collections.Generic.List[string]',
        'System.Collections.Generic.Queue[object]',
        'System.Collections.ObjectModel.ObservableCollection[object]',
        'System.IO.DirectoryInfo', 'System.IO.DriveInfo', 'System.IO.FileStream', 'byte[]',
        'System.Management.Automation.WildcardPattern', 'System.Text.RegularExpressions.Regex', 'System.Text.StringBuilder',
        'System.Windows.Size', 'System.Windows.Rect',
        'System.Windows.Media.Imaging.RenderTargetBitmap', 'System.Windows.Media.Imaging.PngBitmapEncoder'
    )

    # Every instance method the script calls. Anything that could write, delete,
    # move, copy, open or execute (Delete, MoveTo, CopyTo, Open*, Create*, Start,
    # InvokeScript ...) is absent, so adding such a call fails the build.
    $script:AllowedInstanceMethods = @(
        'Add', 'Add_Click', 'Add_Closing', 'Add_SelectionChanged', 'AppendLine', 'Arrange', 'Contains',
        'ContainsKey', 'Dequeue', 'Dispose', 'EndsWith', 'Enqueue', 'EnumerateDirectories', 'EnumerateFiles',
        'FindName', 'FindResource', 'GetEnumerator', 'Invoke', 'IsInRole', 'IsMatch', 'LastIndexOf', 'Measure',
        'Render', 'Replace', 'Save', 'ShowDialog', 'StartsWith', 'Substring', 'ToArray', 'ToLowerInvariant',
        'Add_Checked', 'Add_Unchecked', 'RemoveAt', 'EnumerateFileSystemInfos',
        'Read', 'Write', 'Flush', 'TransformBlock', 'TransformFinalBlock',
        'ToString', 'ToUpper', 'Trim', 'TrimEnd', 'UpdateLayout'
    )

    # Static members allowed on the types that could otherwise read, write or reach out.
    $script:AllowedStaticMembers = @{
        'System.IO.File'                    = @('Create', 'OpenRead', 'Delete', 'SetLastWriteTimeUtc')
        'System.Security.Cryptography.SHA256' = @('Create')
        'System.BitConverter'               = @('ToString')
        'Microsoft.VisualBasic.FileIO.FileSystem' = @('DeleteDirectory', 'DeleteFile')
        'System.IO.Path'                    = @('GetFullPath', 'GetDirectoryName', 'GetFileName')
        'scriptblock'                       = @()
        'System.Globalization.CultureInfo'  = @('InvariantCulture')
        'Environment'                       = @('GetFolderPath', 'GetEnvironmentVariable', 'SetEnvironmentVariable')
        'System.Windows.Markup.XamlReader'  = @('Parse')
        'System.Windows.Clipboard'          = @('SetText')
        'System.Windows.MessageBox'         = @('Show')
    }
}

Describe 'The script parses' {
    It 'has no syntax errors' {
        @($script:ParseErrors).Count | Should -Be 0 -Because (@($script:ParseErrors) | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" } | Out-String)
    }
    It 'is plain ASCII (Windows PowerShell 5.1 misreads UTF-8 without a BOM)' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'Commands' {
    It 'calls only allowlisted cmdlets and its own functions' {
        $unknown = foreach ($c in $script:Commands) {
            $name = $c.GetCommandName()
            if ($null -eq $name) { continue }
            if ($script:AllowedCommands -notcontains $name -and $script:Functions -notcontains $name) {
                "$name (line $($c.Extent.StartLineNumber))"
            }
        }
        @($unknown) | Should -BeNullOrEmpty
    }

    It 'invokes nothing dynamically except the caller-supplied progress callback' {
        $dynamic = foreach ($c in $script:Commands) {
            if ($null -ne $c.GetCommandName()) { continue }
            $first = $c.CommandElements[0]
            $ok = ($c.InvocationOperator -eq 'Ampersand') -and
                  ($first -is [System.Management.Automation.Language.VariableExpressionAst]) -and
                  ($first.VariablePath.UserPath -eq 'OnProgress')
            if (-not $ok) { "line $($c.Extent.StartLineNumber): $($c.Extent.Text)" }
        }
        @($dynamic) | Should -BeNullOrEmpty
    }

    It 'loads only two assemblies that ship with Windows, and compiles nothing' {
        $addType = @($script:Commands | Where-Object { $_.GetCommandName() -eq 'Add-Type' } | ForEach-Object { $_.Extent.Text -replace '\s+', ' ' } | Sort-Object)
        $addType.Count | Should -Be 2
        $addType[0] | Should -Be 'Add-Type -AssemblyName Microsoft.VisualBasic'
        $addType[1] | Should -Be 'Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase'
    }

    It 'creates only allowlisted .NET objects, and never COM objects' {
        $bad = foreach ($c in ($script:Commands | Where-Object { $_.GetCommandName() -eq 'New-Object' })) {
            $text = $c.Extent.Text
            if ($text -match '(?i)-ComObject|-Com\b') { "COM: line $($c.Extent.StartLineNumber)"; continue }
            $typeArg = $c.CommandElements[1]
            $typeName = $null
            if ($typeArg -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $typeName = $typeArg.Value }
            if ($null -eq $typeName -or $script:AllowedNewObject -notcontains $typeName) {
                "line $($c.Extent.StartLineNumber): $text"
            }
        }
        @($bad) | Should -BeNullOrEmpty
    }

    It 'writes files only from the report, self-test and action-log functions' {
        $writers = @('Out-File', 'Export-Csv', 'New-Item')
        $allowedIn = @('Export-TriageReport', 'Resolve-ReportDirectory', 'Invoke-TriageSelfTest', 'Set-TriageRedirect', 'Write-TriageActionLog', 'Move-TriageFile')
        $bad = foreach ($c in ($script:Commands | Where-Object { $writers -contains $_.GetCommandName() })) {
            $where = Get-EnclosingFunction -Node $c
            if ($allowedIn -notcontains $where) { "$($c.GetCommandName()) in $where (line $($c.Extent.StartLineNumber))" }
        }
        @($bad) | Should -BeNullOrEmpty
    }
}

Describe '.NET surface' {
    It 'references only allowlisted types' {
        $types = @($script:Ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.TypeExpressionAst] -or
            $n -is [System.Management.Automation.Language.TypeConstraintAst] -or
            $n -is [System.Management.Automation.Language.AttributeAst] }, $true))
        $bad = foreach ($t in $types) {
            $name = $t.TypeName.FullName
            if ($script:AllowedTypes -notcontains $name) { "$name (line $($t.Extent.StartLineNumber))" }
        }
        @($bad | Sort-Object -Unique) | Should -BeNullOrEmpty
    }

    It 'calls only allowlisted static members on sensitive types' {
        $calls = @($script:Ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Static -and
            $n.Expression -is [System.Management.Automation.Language.TypeExpressionAst] }, $true))
        $bad = foreach ($call in $calls) {
            $type = $call.Expression.TypeName.FullName
            if (-not $script:AllowedStaticMembers.ContainsKey($type)) { continue }
            $member = $call.Member.Extent.Text
            if ($script:AllowedStaticMembers[$type] -notcontains $member) { "[$type]::$member (line $($call.Extent.StartLineNumber))" }
        }
        @($bad) | Should -BeNullOrEmpty
    }

    It 'calls only allowlisted instance methods (nothing that writes, deletes, moves, opens or executes)' {
        $calls = @($script:Ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and -not $n.Static }, $true))
        $bad = foreach ($call in $calls) {
            $name = $call.Member.Extent.Text
            if ($script:AllowedInstanceMethods -notcontains $name) { ".$name() (line $($call.Extent.StartLineNumber))" }
        }
        @($bad | Sort-Object -Unique) | Should -BeNullOrEmpty
    }

    It 'uses Dispatcher.Invoke only with an empty action, and Save only on the screenshot encoder' {
        $calls = @($script:Ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and -not $n.Static -and
            ($n.Member.Extent.Text -eq 'Invoke' -or $n.Member.Extent.Text -eq 'Save') }, $true))
        foreach ($call in $calls) {
            if ($call.Member.Extent.Text -eq 'Invoke') {
                ($call.Extent.Text -replace '\s+', ' ') | Should -Match 'Dispatcher\.Invoke\(\[System\.Action\]\{ \}, \[System\.Windows\.Threading\.DispatcherPriority\]::(Background|ApplicationIdle)\)$'
            } else {
                Get-EnclosingFunction -Node $call | Should -Be 'Save-TriageWindowPng'
            }
        }
    }

    It 'has no output redirection to files' {
        @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst] }, $true)).Count | Should -Be 0
    }

    It 'never touches the engine internals that can run arbitrary code' {
        $vars = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
            ForEach-Object { $_.VariablePath.UserPath })
        foreach ($name in @('ExecutionContext', 'PSCmdlet', 'Host', 'MyInvocation')) {
            $vars | Should -Not -Contain $name
        }
    }

    It 'has a window definition with no code, object providers or external sources' {
        $xaml = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) |
            Where-Object { $_.Value -like '<Window*' })
        $xaml.Count | Should -Be 1
        foreach ($word in @('ObjectDataProvider', 'x:Type', 'x:Static', 'x:Code', 'x:Class', 'clr-namespace', 'Source=', 'NavigateUri', 'Hyperlink', 'WebBrowser', 'Frame ', 'MediaElement', '<Image')) {
            $xaml[0].Value.IndexOf($word, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1 -Because "$word must not appear in the window XAML"
        }
    }

    It 'changes environment variables only in the two action functions, and only for the current user' {
        $sets = @($script:Ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static -and
            $n.Member.Extent.Text -eq 'SetEnvironmentVariable' }, $true))
        $sets.Count | Should -Be 2
        foreach ($call in $sets) {
            Get-EnclosingFunction -Node $call | Should -BeIn @('Set-TriageRedirect', 'Undo-TriageRedirect')
            $call.Arguments.Count            | Should -Be 3
            $call.Arguments[0].Extent.Text   | Should -Be '$target.Variable' -Because 'the name must come from the fixed list, never from the caller'
            $call.Arguments[2].Extent.Text   | Should -Be "'User'"
            if ((Get-EnclosingFunction -Node $call) -eq 'Set-TriageRedirect') {
                $call.Arguments[1].Extent.Text | Should -Be '$value' -Because 'the value must be the folder recomputed inside the function'
            } else {
                $call.Arguments[1].Extent.Text | Should -Be '$null' -Because 'undo may only remove the variable'
            }
        }
        $gets = @($script:Ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static -and
            $n.Member.Extent.Text -eq 'GetEnvironmentVariable' }, $true))
        foreach ($call in $gets) { $call.Arguments[1].Extent.Text | Should -BeIn @("'User'", "'Machine'") }
    }

    It 'manages exactly this list of variables and no other' {
        . $script:ScriptPath -ImportOnly
        $names = @($script:TriageRedirectTargets | ForEach-Object Variable | Sort-Object)
        ($names -join ',') | Should -Be 'COMPOSER_CACHE_DIR,GOMODCACHE,HF_HOME,KERAS_HOME,NLTK_DATA,npm_config_cache,NUGET_PACKAGES,OLLAMA_MODELS,PIP_CACHE_DIR,TORCH_HOME,TRITON_CACHE_DIR,UV_CACHE_DIR'
    }

    It 'creates folders, and only folders, with one pinned command per place' {
        $newItems = @($script:Commands | Where-Object { $_.GetCommandName() -eq 'New-Item' })
        foreach ($c in $newItems) { ($c.Extent.Text -replace '\s+', ' ') | Should -Match '^New-Item -ItemType Directory -Path \$(value|target|folder) -Force$' }
        @($newItems | Where-Object { (Get-EnclosingFunction -Node $_) -eq 'Set-TriageRedirect' }).Count | Should -Be 1
    }

    It 'pins every call that can create, delete or change a file to one function and one argument' {
        $static = @($script:Ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static }, $true))

        function Get-Calls { param($Type, $Member)
            @($static | Where-Object { $_.Expression.Extent.Text -eq "[$Type]" -and $_.Member.Extent.Text -eq $Member }) }

        # Self-test screenshot
        $create = Get-Calls 'System.IO.File' 'Create'
        $create.Count | Should -Be 1
        Get-EnclosingFunction -Node $create[0] | Should -Be 'Save-TriageWindowPng'

        # Reading file contents happens only while moving a file
        foreach ($call in (Get-Calls 'System.IO.File' 'OpenRead')) {
            Get-EnclosingFunction -Node $call | Should -BeIn @('Move-TriageFile', 'Get-TriageFileHash')
        }

        # The only permanent delete: an unverified partial copy the tool itself just created
        $delete = Get-Calls 'System.IO.File' 'Delete'
        $delete.Count | Should -Be 1
        Get-EnclosingFunction -Node $delete[0] | Should -Be 'Move-TriageFile'
        $delete[0].Arguments[0].Extent.Text    | Should -Be '$destination'

        $stamp = Get-Calls 'System.IO.File' 'SetLastWriteTimeUtc'
        $stamp.Count | Should -Be 1
        $stamp[0].Arguments[0].Extent.Text | Should -Be '$destination'

        # Recycle Bin only, never a permanent delete
        $recycleDir = Get-Calls 'Microsoft.VisualBasic.FileIO.FileSystem' 'DeleteDirectory'
        $recycleDir.Count | Should -Be 1
        Get-EnclosingFunction -Node $recycleDir[0] | Should -Be 'Remove-TriageStore'
        $recycleFile = Get-Calls 'Microsoft.VisualBasic.FileIO.FileSystem' 'DeleteFile'
        $recycleFile.Count | Should -Be 1
        Get-EnclosingFunction -Node $recycleFile[0] | Should -Be 'Move-TriageFile'
        $recycleFile[0].Arguments[0].Extent.Text    | Should -Be '$source'
        foreach ($call in @($recycleDir + $recycleFile)) {
            $call.Arguments.Count          | Should -Be 4
            $call.Arguments[2].Extent.Text | Should -Be '[Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin'
        }
    }

    It 'opens a file for writing in exactly one place, and only as a new file' {
        $streams = @($script:Commands | Where-Object { $_.GetCommandName() -eq 'New-Object' -and $_.Extent.Text -match 'System\.IO\.FileStream' })
        $streams.Count | Should -Be 1
        Get-EnclosingFunction -Node $streams[0] | Should -Be 'Move-TriageFile'
        $streams[0].Extent.Text | Should -Match '^New-Object System\.IO\.FileStream\(\$destination, \[System\.IO\.FileMode\]::CreateNew, '
        @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Static -and
            $n.Expression.Extent.Text -eq '[System.IO.FileMode]' }, $true) | ForEach-Object { $_.Member.Extent.Text } | Sort-Object -Unique) | Should -Be @('CreateNew')
    }
}

Describe 'Strings' {
    It 'contains no URL other than XML namespace identifiers' {
        $strings = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                                                     $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true))
        $bad = foreach ($s in $strings) {
            $text = $s.Extent.Text
            $text = $text -replace 'http://schemas\.microsoft\.com/winfx/2006/xaml(/presentation)?', ''
            $text = $text -replace 'http://www\.w3\.org/(2000/svg|1999/xhtml|1999/xlink)', ''
            $text = $text -replace 'http-equiv', ''
            if ($text -match '(?i)\b(https?|ftp|wss?|file)://') { "line $($s.Extent.StartLineNumber)" }
        }
        @($bad) | Should -BeNullOrEmpty
    }

    It 'never names a persistence or remote-execution mechanism' {
        $source = Get-Content -LiteralPath $script:ScriptPath -Raw
        foreach ($word in @('HKLM:', 'HKCU:', 'Registry::', 'schtasks', 'Register-ScheduledTask', 'New-Service', 'Invoke-Command', 'New-PSSession', 'Start-Process', 'Invoke-Item', 'System.Net', 'System.Reflection', 'DllImport')) {
            $source.IndexOf($word, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1 -Because "$word must not appear anywhere in the script"
        }
    }
}
