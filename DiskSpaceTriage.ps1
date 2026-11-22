#requires -Version 5.1
<#
.SYNOPSIS
    Disk Space Triage - shows what is filling a Windows system drive and how
    each item can leave it safely. The scan is read-only; changes happen only
    through four optional, confirmed actions, and each one reports the free
    space it measured before and after.

.DESCRIPTION
    Every finding is sorted into one of five buckets:

      Redirect - a tool owns the store. Change its setting or environment
                 variable so it lives on another drive. Permanent fix.
      Move     - copy, verify, then delete the original. One-time recovery.
      Delete   - regenerates or is reproducible from source. Never copy it.
      Never    - registry-bound, system state or app configuration. Leave it.
      Review   - nothing matched. Confirm what owns it before acting.

    SECURITY PROPERTIES (enforced by tests/Capability.Tests.ps1 on every commit)

      1. LEAST PRIVILEGE. Needs no administrator rights and refuses to run
         elevated unless -AllowElevated is given.
      2. THE SCAN IS READ-ONLY and reads metadata only: names, sizes,
         timestamps and attributes. It never opens a file.
      3. FOUR ACTIONS, each confirmed one item at a time (default answer
         No), each logged, each followed by the measured free space before
         and after:
           Move a store - for a fixed list of caches and model stores: copy
                      every file to <drive>:\FromC\<same path>, verify each
                      copy by SHA-256, set the one user environment variable
                      that tells the owning tool where the store now is, then
                      send the old folder to the Recycle Bin. (Setting the
                      variable alone is also offered, and is undoable.)
           Delete   - send one rebuildable store folder (from a short list)
                      to the Recycle Bin.
           Move a file - copy one plain data file to <drive>:\FromC\<same
                      path>, verify the copy by SHA-256, then send the
                      original to the Recycle Bin.
           Empty the Recycle Bin - of the one drive being freed. The Recycle
                      Bin of a drive is on that drive, so this is the step
                      that returns the space. It is the only permanent
                      removal the tool can ask Windows for, and it says so.
         File contents are read only while copying. Nothing is overwritten,
         and apart from emptying the Recycle Bin the script deletes nothing
         permanently except its own unfinished copies.
      4. NO NETWORK. No download, upload, telemetry or remoting. The HTML
         report is self-contained and carries a Content-Security-Policy that
         blocks every external request.
      5. NO HIDDEN CODE. No Invoke-Expression, no compiled C#, no reflection,
         no COM, no external processes. Two Add-Type calls load assemblies
         that ship with Windows (WPF, and the Visual Basic runtime used to
         reach the Recycle Bin). One registry value is read (whether Windows
         apps use the dark theme); none is written.
      6. CONTAINED WRITES. Reports and the action log go to one folder on a
         local fixed disk. Folders and moved files are created only below
         <drive>:\FromC. UNC paths, network drives and junctions are refused.
      7. NO LINK TRAVERSAL. Junctions and symbolic links are never followed,
         and a folder that contains one is never deleted.
      8. NO PERSISTENCE. No services, scheduled tasks or start-up entries.

.PARAMETER Mode
    Gui (default) opens the window. Console prints a summary and writes the
    reports. SelfTest runs the built-in checks used by CI.

.PARAMETER SourceDrive
    Drive letter to analyse. Default C.

.PARAMETER DestinationDrive
    Drive letter you intend to relocate to. The scan only checks its capacity;
    confirmed moves create folders and files below <drive>:\FromC on it.

.PARAMETER MinSizeMB
    Smallest individual file listed. Smaller files still count in all totals.

.PARAMETER AdditionalRoot
    Extra folders on the source drive to include in the scan.

.PARAMETER SkipDefaultRoots
    Scan only the folders given with -AdditionalRoot.

.PARAMETER ReportDirectory
    Where reports are written. Default: Documents\DiskReports.

.PARAMETER ShowRules
    Print the classification rules and exit.

.PARAMETER ImportOnly
    Define the functions and return without running anything (used by tests).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\DiskSpaceTriage.ps1

.EXAMPLE
    .\DiskSpaceTriage.ps1 -Mode Console -MinSizeMB 250 -AdditionalRoot C:\Datasets

.LINK
    https://github.com/alasmari-cyber-ai-lab/disk-space-triage
#>

[CmdletBinding()]
param(
    [ValidateSet('Gui', 'Console', 'SelfTest')] [string] $Mode = 'Gui',
    [ValidatePattern('^[A-Za-z]$')] [string]   $SourceDrive      = 'C',
    [ValidatePattern('^[A-Za-z]$')] [string]   $DestinationDrive = 'D',
    [ValidateRange(1, 1048576)]     [int]      $MinSizeMB        = 100,
    [ValidateRange(1, 5000)]        [int]      $TopCount         = 300,
    [ValidateRange(1, 64)]          [int]      $MaxDepth         = 24,
                                    [string]   $ReportDirectory,
                                    [string[]] $AdditionalRoot   = @(),
                                    [switch]   $SkipDefaultRoots,
                                    [switch]   $ShowRules,
                                    [switch]   $AllowElevated,
                                    [switch]   $ImportOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TriageVersion = '1.1.0'
$script:TriageCancel  = $false
$script:TriageUi      = $null
$script:TriageLastResult = $null
$script:TriageRedirectPlan    = @()
$script:TriageRedirectHistory = $null
$script:TriageScanning        = $false
$script:TriageBusy            = $false
$script:TriageSession         = $null
$script:TriageSessionStart    = $null
$script:TriageSpaceNow        = $null
$script:TriageDeletePlan      = @()
$script:TriageMovePlan        = @()
$script:TriageMoveTicks       = 0
$script:TriageGuiRoots       = @($AdditionalRoot)
$script:TriageGuiSkipDefault = [bool]$SkipDefaultRoots
$script:TriageGuiReportDir   = $ReportDirectory

#region Rules ----------------------------------------------------------------
# First match wins, and the order follows the precedence tiers of docs/SPEC.md.
# A pattern is a PowerShell wildcard matched against the whole path, or, when
# it starts with "re:", a case-insensitive regular expression (used where a
# wildcard cannot say "exactly one directory", for example "directly inside a
# profile"). tests/oracle checks these rules against the specification.

function New-TriageRule {
    param([string]$Match, [string]$Bucket, [string]$Mechanism, [string]$Note)
    [pscustomobject]@{ Match = $Match; Bucket = $Bucket; Mechanism = $Mechanism; Note = $Note; Pattern = $null }
}

$script:TriageRules = @(

    # === TIER 1: protected system locations (drive root only) ================
    New-TriageRule '?:\Windows\Installer\*'           'Never' 'Leave in place' 'MSI cache; deleting breaks uninstall, repair and updates'
    New-TriageRule '?:\Windows\WinSxS\*'              'Never' 'DISM only'      'Component store; size is mostly hard links. Use DISM StartComponentCleanup'
    New-TriageRule '?:\Windows\System32\DriverStore\*' 'Never' 'pnputil only'  'Driver repository; never delete by hand'
    New-TriageRule '?:\Windows\*'                     'Never' 'Leave in place' 'Operating system files'
    New-TriageRule '?:\System Volume Information\*'   'Never' 'System Protection' 'Restore points; cap via System Protection, not the folder'
    New-TriageRule '?:\$Recycle.Bin\*'                'Delete' 'Empty Recycle Bin' 'Already-deleted content still occupying space'

    # === TIER 2: named stores ================================================
    # --- Python and data-science toolchain ---
    New-TriageRule '*\AppData\Local\pip\Cache\*'      'Redirect' 'PIP_CACHE_DIR'         'pip wheel cache'
    New-TriageRule '*\AppData\Local\uv\*'             'Redirect' 'UV_CACHE_DIR'          'uv cache'
    New-TriageRule '*\AppData\Local\pypoetry\*'       'Redirect' 'POETRY_CACHE_DIR'      'Poetry cache and virtualenvs'
    New-TriageRule '*\anaconda3\pkgs\*'               'Redirect' 'pkgs_dirs in .condarc' 'conda package cache'
    New-TriageRule '*\miniconda3\pkgs\*'              'Redirect' 'pkgs_dirs in .condarc' 'conda package cache'
    New-TriageRule '*\AppData\Local\conda\*'          'Redirect' 'pkgs_dirs in .condarc' 'conda package cache'
    New-TriageRule '*\anaconda3\envs\*'               'Delete'   'Export, then recreate on the other drive' 'conda environment; export it first (conda env export), never copy'
    New-TriageRule '*\miniconda3\envs\*'              'Delete'   'Export, then recreate on the other drive' 'conda environment; export it first (conda env export), never copy'

    # --- ML and AI model stores ---
    New-TriageRule '*\.cache\huggingface\*'           'Redirect' 'HF_HOME'               'Hugging Face cache. Re-downloadable; safe to delete after redirecting'
    New-TriageRule '*\.cache\torch\*'                 'Redirect' 'TORCH_HOME'            'PyTorch hub cache'
    New-TriageRule '*\.keras\*'                       'Redirect' 'KERAS_HOME'            'Keras models and datasets'
    New-TriageRule '*\tensorflow_datasets\*'          'Redirect' 'TFDS_DATA_DIR'         'TensorFlow Datasets'
    New-TriageRule '*\nltk_data\*'                    'Redirect' 'NLTK_DATA'             'NLTK corpora'
    New-TriageRule '*\.ollama\models\*'               'Redirect' 'OLLAMA_MODELS'         'Ollama models. Re-downloadable; move them to avoid downloading again'
    New-TriageRule '*\.lmstudio\models\*'             'Redirect' 'Settings > Models directory' 'LM Studio models. Re-downloadable; move them to avoid downloading again'
    New-TriageRule '*\.triton\*'                      'Redirect' 'TRITON_CACHE_DIR'      'Triton kernel cache'
    New-TriageRule '*\.dvc\cache\*'                   'Redirect' 'dvc cache dir'         'DVC cache'
    # wandb and mlruns can nest; the deeper directory wins. A wandb directory
    # inside site-packages is the installed package, not run data.
    New-TriageRule 're:\\mlruns\\(?!.*\\wandb\\)'  'Move'     'MLflow artifact root' 'MLflow runs'
    New-TriageRule 're:^(?:(?!\\site-packages\\).)*?\\wandb\\' 'Redirect' 'WANDB_DIR' 'Weights and Biases run data. Your data: move it, do not delete'
    New-TriageRule 're:\\mlruns\\'                   'Move'     'MLflow artifact root' 'MLflow runs'

    # --- Package managers and developer tools ---
    New-TriageRule '*\AppData\Local\npm-cache\*'      'Redirect' 'npm config set cache'  'npm cache'
    New-TriageRule '*\AppData\Local\Yarn\Cache\*'     'Redirect' 'yarn cache-folder'     'Yarn cache'
    New-TriageRule '*\AppData\Local\pnpm-store\*'     'Redirect' 'pnpm store-dir'        'pnpm store'
    New-TriageRule '*\.nuget\packages\*'              'Redirect' 'NUGET_PACKAGES'        'NuGet packages'
    New-TriageRule '*\.m2\repository\*'               'Redirect' 'localRepository'       'Maven repository'
    New-TriageRule '*\.gradle\*'                      'Redirect' 'GRADLE_USER_HOME'      'Gradle caches'
    New-TriageRule '*\.cargo\*'                       'Redirect' 'CARGO_HOME'            'Cargo registry and crates'
    New-TriageRule '*\go\pkg\mod\*'                   'Redirect' 'GOMODCACHE'            'Go module cache'
    New-TriageRule '*\AppData\Local\Composer\*'       'Redirect' 'COMPOSER_CACHE_DIR'    'Composer cache'
    New-TriageRule '*\.gem\*'                         'Redirect' 'GEM_HOME'              'RubyGems'
    New-TriageRule '*\scoop\apps\*'                   'Redirect' 'SCOOP'                 'Scoop apps'
    New-TriageRule '*\AppData\Local\Android\Sdk\*'    'Redirect' 'ANDROID_SDK_ROOT'      'Android SDK'
    New-TriageRule '*\.android\avd\*'                 'Redirect' 'ANDROID_AVD_HOME'      'Android emulator images. Move them or recreate the devices'
    New-TriageRule '*\.vscode\extensions\*'           'Redirect' 'code --extensions-dir' 'VS Code extensions'
    New-TriageRule '*\AppData\Local\Unity\caches\*'   'Redirect' 'Preferences > GI Cache' 'Unity caches'
    New-TriageRule '*\AppData\Local\UnrealEngine\Common\DerivedDataCache\*' 'Redirect' 'UE-LocalDataCachePath' 'Unreal derived data cache'
    New-TriageRule '*\.vagrant.d\*'                   'Redirect' 'VAGRANT_HOME'          'Vagrant boxes'
    New-TriageRule '?:\ProgramData\Microsoft\VisualStudio\Packages\*' 'Delete' 'Visual Studio Installer' 'Visual Studio package cache'

    # --- Containers and virtual machines ---
    New-TriageRule '*\AppData\Local\Docker\*'         'Redirect' 'Settings > Resources > Disk image location' 'Docker Desktop data: images, containers and volumes. Move it with this setting; do not delete it'
    New-TriageRule '*\AppData\Local\Packages\*\LocalState\*.vhdx' 'Redirect' 'wsl --manage --move' 'WSL distribution disk'
    New-TriageRule '?:\ProgramData\Microsoft\Windows\Hyper-V\*' 'Move' 'Hyper-V Manager > Move' 'Hyper-V virtual machine (needs administrator)'
    New-TriageRule '?:\Users\Public\Documents\Hyper-V\*' 'Move' 'Hyper-V Manager > Move' 'Hyper-V virtual machine (needs administrator)'
    New-TriageRule '*\VirtualBox VMs\*'               'Move'     'Machine > Move'        'VirtualBox virtual machine'
    New-TriageRule '*\Documents\Virtual Machines\*'   'Move'     'Move the folder, reopen the .vmx' 'VMware virtual machine'

    # --- Games ---
    New-TriageRule '*\steamapps\shadercache\*'        'Delete'   'Regenerates'           'Steam shader cache'
    New-TriageRule '*\steamapps\downloading\*'        'Delete'   'Regenerates'           'Interrupted Steam downloads'
    New-TriageRule '*\steamapps\*'                    'Move'     'Steam > Storage > Move' 'Steam game library'
    New-TriageRule '?:\Program Files\Epic Games\*'    'Move'     'Reinstall on the other drive' 'Epic Games has no move function'
    New-TriageRule '?:\Program Files (x86)\Epic Games\*' 'Move'  'Reinstall on the other drive' 'Epic Games has no move function'
    New-TriageRule '?:\Program Files (x86)\GOG Galaxy\Games\*' 'Move' 'Manage installation > Move' 'GOG Galaxy game'
    New-TriageRule '?:\Program Files (x86)\Battle.net\*' 'Move'  'Locate game after move' 'Battle.net game'
    New-TriageRule '?:\Program Files (x86)\Ubisoft\*' 'Move'     'Reinstall on the other drive' 'Ubisoft Connect game'
    New-TriageRule '?:\Program Files\WindowsApps\*'   'Move'     'Settings > Apps > Move' 'Microsoft Store or Xbox app'
    New-TriageRule '*\AppData\Roaming\.minecraft\*'   'Redirect' 'Launcher > game directory' 'Minecraft Java, including your worlds. Your data: move it, do not delete'
    New-TriageRule '*\AppData\Local\NVIDIA\DXCache\*' 'Delete'   'Regenerates'           'GPU shader cache'
    New-TriageRule '*\AppData\Local\AMD\DxCache\*'    'Delete'   'Regenerates'           'GPU shader cache'
    New-TriageRule '*\AppData\Local\D3DSCache\*'      'Delete'   'Regenerates'           'DirectX shader cache'
    New-TriageRule '*\Documents\My Games\*'           'Move'     'Moves with Documents'  'Game saves'
    New-TriageRule '*\Saved Games\*'                  'Move'     'Properties > Location tab' 'Game saves'

    # --- Creative and media ---
    New-TriageRule '*\AppData\Roaming\Adobe\Common\Media Cache Files\*' 'Redirect' 'Preferences > Media Cache' 'Adobe media cache; often very large'
    New-TriageRule '*\AppData\Roaming\Adobe\Common\Media Cache\*' 'Redirect' 'Preferences > Media Cache' 'Adobe media cache; often very large'
    New-TriageRule '*\AppData\Local\Adobe\CameraRaw\Cache\*' 'Redirect' 'Preferences > Camera Raw' 'Camera Raw cache'
    New-TriageRule '* Previews.lrdata\*'              'Move'     'Move the catalog, reopen it' 'Lightroom previews'
    New-TriageRule '*\AppData\Roaming\Blackmagic Design\*' 'Redirect' 'Project Settings > Working Folders' 'DaVinci Resolve data. May include your project library: move it, do not delete'
    New-TriageRule '*\AppData\Local\Blackmagic Design\*' 'Redirect' 'Project Settings > Working Folders' 'DaVinci Resolve data. May include your project library: move it, do not delete'
    New-TriageRule '*\AppData\Local\Microsoft\Office\*\OfficeFileCache\*' 'Delete' 'Regenerates' 'Office document cache. Let Office finish uploading before clearing it'
    New-TriageRule '*\AppData\Local\Plex Media Server\*' 'Move'  'Move, then repoint in the registry' 'Plex metadata'
    New-TriageRule '*\AppData\Local\Spotify\Storage\*' 'Redirect' 'Settings > Storage'  'Spotify offline songs'
    New-TriageRule '*\Music\iTunes\iTunes Media\*'    'Redirect' 'Preferences > Files'   'iTunes / Apple Music library. Your data: let the app consolidate it to the new place'

    # --- Communication ---
    New-TriageRule '*\AppData\Local\Microsoft\Outlook\*.ost' 'Redirect' 'Shrink cached period, or ForceOSTPath' 'Outlook offline mailbox'
    New-TriageRule '*\Documents\Outlook Files\*'      'Move'     'Account Settings > Data Files' 'Outlook archives'
    New-TriageRule '*\Documents\Zoom\*'               'Redirect' 'Settings > Recording'  'Zoom recordings. Your data: after changing the setting, move them, do not delete'
    New-TriageRule '*\AppData\Local\Packages\MSTeams_*\LocalCache\*' 'Delete' 'Regenerates' 'Teams cache'
    # Only the cache directories; the rest of these folders is profile data.
    New-TriageRule 're:\\AppData\\Roaming\\Microsoft\\Teams\\(?:[^\\]+\\)*?[^\\]*cache[^\\]*\\' 'Delete' 'Regenerates' 'Teams (classic) cache'
    New-TriageRule 're:\\AppData\\Roaming\\Slack\\(?:[^\\]+\\)*?[^\\]*cache[^\\]*\\' 'Delete' 'Regenerates' 'Slack cache'
    New-TriageRule '*\AppData\Roaming\discord\Cache\*' 'Delete'  'Regenerates'           'Discord cache'
    New-TriageRule '*\AppData\Roaming\discord\Code Cache\*' 'Delete' 'Regenerates'       'Discord cache'
    New-TriageRule '*\AppData\Roaming\Telegram Desktop\*' 'Redirect' 'Settings > Advanced > Data and storage' 'Telegram Desktop data. Change the folder in the app; do not delete this one by hand'

    # --- Mobile backups and sync caches ---
    New-TriageRule '*\Apple\MobileSync\Backup\*'      'Move'     'Move + mklink /J'      'iPhone / iPad backup; no setting exists'
    New-TriageRule '*\AppData\Roaming\Apple Computer\MobileSync\Backup\*' 'Move' 'Move + mklink /J' 'iPhone / iPad backup; no setting exists'
    New-TriageRule '*\AppData\Local\Google\DriveFS\*' 'Redirect' 'Preferences > Local cached files directory' 'Google Drive stream cache'
    New-TriageRule '*\AppData\Local\Box\Box\*'        'Redirect' 'Box settings'          'Box Drive cache'

    # --- Browsers, temp and crash data ---
    New-TriageRule '*\AppData\Local\Mozilla\Firefox\Profiles\*' 'Redirect' 'browser.cache.disk.parent_directory' 'Firefox cache'
    # A cache-named directory inside a browser "User Data" folder below AppData\Local.
    New-TriageRule 're:\\AppData\\Local\\(?:[^\\]+\\)*?User Data\\(?:[^\\]+\\)*?[^\\]*cache[^\\]*\\' 'Delete' 'Regenerates' 'Browser cache'
    New-TriageRule '*\AppData\Local\Microsoft\Windows\INetCache\*' 'Delete' 'Regenerates' 'Windows internet cache'
    New-TriageRule '*\AppData\Local\Temp\*'           'Delete'   'TEMP / TMP'            'User temporary files'
    New-TriageRule '*\AppData\Local\CrashDumps\*'     'Delete'   'Regenerates'           'Crash dumps'
    New-TriageRule '?:\ProgramData\Microsoft\Windows\WER\*' 'Delete' 'Regenerates'       'Error reporting queue'
    New-TriageRule '*\AppData\Local\Microsoft\Windows\WER\*' 'Delete' 'Regenerates'      'Error reporting queue'

    # === TIER 2b: file-keyed rows (only when no named store above applied) ===
    New-TriageRule '*.vhdx'                           'Move'     'Owning tool only'      'Virtual disk'
    New-TriageRule '*.vhd'                            'Move'     'Owning tool only'      'Virtual disk'
    New-TriageRule '*.vmdk'                           'Move'     'Owning tool only'      'Virtual disk'
    New-TriageRule '*.vdi'                            'Move'     'Owning tool only'      'Virtual disk'
    New-TriageRule '*.dmp'                            'Delete'   'Startup and Recovery'  'Memory dump'

    # === TIER 3: reproducible artefacts ======================================
    New-TriageRule '*\node_modules\*'                 'Delete'   'Reinstall from lockfile' 'node_modules; needs a package-lock file to rebuild, never copy'
    New-TriageRule '*\.venv\*'                        'Delete'   'Recreate on the other drive' 'Virtual environment; save requirements first (pip freeze), never copy'
    New-TriageRule '*\venv\Scripts\*'                 'Delete'   'Recreate on the other drive' 'Virtual environment; save requirements first (pip freeze), never copy'
    New-TriageRule '*\venv\Lib\*'                     'Delete'   'Recreate on the other drive' 'Virtual environment; save requirements first (pip freeze), never copy'
    New-TriageRule '*\venv\Include\*'                 'Delete'   'Recreate on the other drive' 'Virtual environment; save requirements first (pip freeze), never copy'
    New-TriageRule '*\__pycache__\*'                  'Delete'   'Regenerates'           'Compiled Python bytecode'
    New-TriageRule '*\target\debug\*'                 'Delete'   'CARGO_TARGET_DIR'      'Rust build output, if this is a Cargo project'
    New-TriageRule '*\target\release\*'               'Delete'   'CARGO_TARGET_DIR'      'Rust build output, if this is a Cargo project'

    # === TIER 4: cloud-sync roots (directly inside a profile) ================
    New-TriageRule 're:^[a-z]:\\Users\\[^\\]+\\OneDrive( - [^\\]+)?\\' 'Never' 'Files On-Demand' 'Cloud-synced; use Free up space, do not move'
    New-TriageRule 're:^[a-z]:\\Users\\[^\\]+\\Dropbox\\' 'Move' 'Preferences > Sync'    'Move through the Dropbox client, never by hand'
    New-TriageRule 're:^[a-z]:\\Users\\[^\\]+\\My Drive\\' 'Move' 'Reconnect with a folder on the other drive' 'Google Drive mirrored folder'

    # === TIER 5: install paths ===============================================
    New-TriageRule '?:\Program Files\*'               'Never'    'Uninstall, then reinstall on the other drive' 'Install path is registry-bound'
    New-TriageRule '?:\Program Files (x86)\*'         'Never'    'Uninstall, then reinstall on the other drive' 'Install path is registry-bound'
    New-TriageRule '*\AppData\Local\Programs\*'       'Never'    'Uninstall, then reinstall on the other drive' 'Per-user install path'

    # === TIER 6: known folders (directly inside a profile) ===================
    New-TriageRule 're:^[a-z]:\\Users\\[^\\]+\\Downloads\\' 'Move' 'Properties > Location tab' 'Downloads'
    New-TriageRule 're:^[a-z]:\\Users\\[^\\]+\\Documents\\' 'Move' 'Properties > Location tab' 'Documents'
    New-TriageRule 're:^[a-z]:\\Users\\[^\\]+\\Pictures\\'  'Move' 'Properties > Location tab' 'Pictures'
    New-TriageRule 're:^[a-z]:\\Users\\[^\\]+\\Videos\\'    'Move' 'Properties > Location tab' 'Videos'
    New-TriageRule 're:^[a-z]:\\Users\\[^\\]+\\Music\\'     'Move' 'Properties > Location tab' 'Music'
    New-TriageRule 're:^[a-z]:\\Users\\[^\\]+\\3D Objects\\' 'Move' 'Properties > Location tab' '3D Objects'

    # === TIER 7: generic fallbacks ===========================================
    # Not caches, despite the names. These are final: no file-type fallback.
    New-TriageRule 're:\\AppData\\Local\\Packages\\[^\\]+\\LocalCache\\' 'Review' 'Confirm owner' 'Packaged-app data, not a cache despite the name'
    New-TriageRule '*\AppData\Local\Microsoft\TokenBroker\*' 'Review' 'Confirm owner' 'Sign-in tokens'
    # A directory whose whole name begins or ends with "cache".
    New-TriageRule 're:\\AppData\\Local\\(?:[^\\]+\\)*?(?:cache[^\\]*|[^\\]*cache)\\' 'Delete' 'Regenerates' 'Application cache'
    New-TriageRule '*\AppData\Local\*\logs\*'         'Delete'   'Regenerates'           'Application logs'
    New-TriageRule '*\AppData\Roaming\*'              'Never'    'Leave in place'        'Application settings, profiles, licences, keys'
)

# File-type fallback for files no path rule caught.
$script:TriageMoveExtensions = @(
    '.iso','.img','.wim','.esd','.zip','.7z','.rar','.tar','.gz','.bz2','.xz','.cab',
    '.mp4','.mkv','.avi','.mov','.wmv','.flv','.mp3','.flac','.wav','.aac',
    '.psd','.psb','.ai','.indd','.aep','.prproj','.drp','.blend',
    '.raw','.cr2','.cr3','.nef','.arw','.dng','.tif','.tiff',
    '.csv','.tsv','.parquet','.feather','.arrow','.h5','.hdf5','.npz','.npy','.mat',
    '.ckpt','.safetensors','.pt','.pth','.pb','.onnx','.gguf','.tflite',
    '.bak','.vbk','.pst','.ost','.sql','.bacpac','.dump',
    '.docx','.xlsx','.pptx','.pdf','.epub'
)


# Delete-bucket stores the tool may send to the Recycle Bin when asked (keyed
# by the rule's description). Everything else in the Delete bucket stays
# advice only: temp folders, environments, Office and Windows caches.
$script:TriageRecyclableNotes = @{
    'node_modules; needs a package-lock file to rebuild, never copy' = 'NodeModules'
    'Rust build output, if this is a Cargo project'                  = 'RustTarget'
    'Steam shader cache'          = 'Cache'
    'GPU shader cache'            = 'Cache'
    'DirectX shader cache'        = 'Cache'
    'Crash dumps'                 = 'Cache'
    'Discord cache'               = 'AppCache'
    'Slack cache'                 = 'AppCache'
    'Teams (classic) cache'       = 'AppCache'
    'Browser cache'               = 'AppCache'
}

# Folder names that really are caches. An application "cache" store is only
# removable when its top folder has one of these names.
$script:TriageCacheFolderNames = @{
    'cache' = $true; 'code cache' = $true; 'gpucache' = $true; 'shadercache' = $true; 'grshadercache' = $true
    'dawncache' = $true; 'dawngraphitecache' = $true; 'dawnwebgpucache' = $true; 'graphitedawncache' = $true
}

# File types that are somebody's work or data. One of these inside a
# "rebuildable" folder means the folder is not purely rebuildable.
$script:TriagePersonalExtensions = @{}
foreach ($ext in @('.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.odt', '.psd', '.psb', '.ai', '.indd', '.aep', '.prproj', '.drp', '.blend',
                   '.safetensors', '.ckpt', '.pt', '.pth', '.gguf', '.parquet', '.feather', '.arrow', '.h5', '.hdf5', '.npz', '.npy', '.mat',
                   '.pst', '.ost', '.bak', '.vbk', '.bacpac', '.iso', '.img', '.vhdx', '.vhd', '.vmdk', '.vdi', '.qcow2',
                   '.mkv', '.mov', '.avi', '.raw', '.cr2', '.cr3', '.nef', '.arw', '.dng', '.kdbx', '.sqlite', '.db', '.mdf')) {
    $script:TriagePersonalExtensions[$ext] = $true
}

# Types the Move action never touches, even in a known folder.
$script:TriageNeverMoveExtensions = @{ '.pst' = $true; '.ost' = $true }

# Move-bucket rules whose files the tool may move itself: plain user files in
# the known folders. (Files matched only by the file-type fallback are also
# movable.) Games, virtual machines, backups and sync folders are never moved
# by the tool.
$script:TriageMovableNotes = @{
    'Downloads' = $true; 'Documents' = $true; 'Pictures' = $true; 'Videos' = $true; 'Music' = $true; '3D Objects' = $true
}

# Stores the tool deliberately does not measure, because doing so needs
# administrator rights. They are listed in every report as a checklist.
$script:TriageElevatedChecklist = @(
    [pscustomobject]@{ Item = 'pagefile.sys';          Action = 'System Properties > Advanced > Performance > Virtual Memory (leave about 800 MB on the system drive)' }
    [pscustomobject]@{ Item = 'hiberfil.sys';          Action = 'powercfg /h off, or powercfg /h /size 40 to shrink it' }
    [pscustomobject]@{ Item = 'MEMORY.DMP';            Action = 'Startup and Recovery > Small memory dump, or None' }
    [pscustomobject]@{ Item = 'Windows Update cache';  Action = 'cleanmgr > Clean up system files > Windows Update Cleanup' }
    [pscustomobject]@{ Item = 'Delivery Optimization'; Action = 'Settings > Windows Update > Delivery Optimization > cache limit' }
    [pscustomobject]@{ Item = 'Windows.old';           Action = 'cleanmgr > Previous Windows installations' }
    [pscustomobject]@{ Item = 'System Restore quota';  Action = 'System Protection > Configure > Max Usage' }
    [pscustomobject]@{ Item = 'Reserved storage';      Action = 'DISM /Online /Set-ReservedStorageState /State:Disabled' }
    [pscustomobject]@{ Item = 'Search index';          Action = 'Indexing Options > Advanced > Index location' }
    [pscustomobject]@{ Item = 'Old driver packages';   Action = 'cleanmgr > Device driver packages' }
)
#endregion

#region Engine ---------------------------------------------------------------

function Test-IsElevated {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

function Get-DriveFacts {
    # System.IO.DriveInfo needs no privilege and makes no WMI/CIM call.
    param([string]$Letter)
    try {
        $drive = New-Object System.IO.DriveInfo ($Letter + ':\')
        if (-not $drive.IsReady) { return $null }

        $percentFree = 0
        if ($drive.TotalSize -gt 0) {
            $percentFree = [math]::Round(100 * $drive.AvailableFreeSpace / $drive.TotalSize, 1)
        }

        return [pscustomobject]@{
            Letter      = $Letter.ToUpper()
            Label       = [string]$drive.VolumeLabel
            Format      = [string]$drive.DriveFormat
            Type        = $drive.DriveType.ToString()
            TotalBytes  = [long]$drive.TotalSize
            FreeBytes   = [long]$drive.AvailableFreeSpace
            UsedBytes   = [long]($drive.TotalSize - $drive.AvailableFreeSpace)
            PercentFree = $percentFree
        }
    } catch { return $null }
}

function Get-PressureStatus {
    param($Facts)
    if ($null -eq $Facts)          { return 'UNKNOWN' }
    if ($Facts.FreeBytes -lt 2GB)  { return 'CRITICAL' }
    if ($Facts.PercentFree -lt 10) { return 'LOW' }
    if ($Facts.PercentFree -lt 15) { return 'WARNING' }
    return 'HEALTHY'
}

function Initialize-TriageRules {
    # Compile each wildcard once. WildcardPattern is the engine behind -like.
    if ($null -ne $script:TriageRules[0].Pattern) { return }

    $options = [System.Management.Automation.WildcardOptions]::IgnoreCase
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    foreach ($rule in $script:TriageRules) {
        if ($rule.Match.StartsWith('re:')) {
            $rule.Pattern = New-Object System.Text.RegularExpressions.Regex($rule.Match.Substring(3), $regexOptions)
        } else {
            $rule.Pattern = New-Object System.Management.Automation.WildcardPattern($rule.Match, $options)
        }
    }

    $script:TriageExtensionSet = @{}
    foreach ($ext in $script:TriageMoveExtensions) { $script:TriageExtensionSet[$ext] = $true }

    $script:TriageFallbackMove   = [pscustomobject]@{ Match = ''; Bucket = 'Move';   Mechanism = 'Explorer move'; Note = 'Self-contained data file with no registry dependency' }
    $script:TriageFallbackReview = [pscustomobject]@{ Match = ''; Bucket = 'Review'; Mechanism = 'Confirm owner'; Note = 'No rule matched' }
}

function Get-TriageClassification {
    <#
        Pure function: path in, classification out. No file-system access.
        Returns an object with Bucket, Mechanism and Note.
    #>
    param([Parameter(Mandatory)][string]$Path)

    Initialize-TriageRules

    foreach ($rule in $script:TriageRules) {
        if ($rule.Pattern.IsMatch($Path)) { return $rule }
    }

    $leafStart = $Path.LastIndexOf('\') + 1
    $dot       = $Path.LastIndexOf('.')
    if ($dot -gt $leafStart) {
        $extension = $Path.Substring($dot).ToLowerInvariant()
        if ($script:TriageExtensionSet.ContainsKey($extension)) { return $script:TriageFallbackMove }
    }
    return $script:TriageFallbackReview
}

function Get-ScanRoots {
    <#
        Only user-readable locations are enumerated. System directories are
        excluded on purpose: nothing there is safely relocatable, and walking
        them would only produce access-denied noise or tempt elevation.
    #>
    [CmdletBinding()]
    param([string]$Drive, [string[]]$Extra, [switch]$SkipDefaultRoots)

    $prefix = $Drive.ToUpper() + ':\'
    $found  = New-Object System.Collections.Generic.List[string]

    if (-not $SkipDefaultRoots) {
        if ($env:USERPROFILE -and $env:USERPROFILE.ToUpper().StartsWith($prefix)) {
            $found.Add($env:USERPROFILE)
        }
        $candidates = @(
            'Users\Public', 'ProgramData',
            'Program Files\Steam', 'Program Files (x86)\Steam', 'SteamLibrary',
            'Program Files\Epic Games', 'Program Files (x86)\Epic Games',
            'Program Files (x86)\GOG Galaxy\Games', 'Program Files (x86)\Battle.net',
            'Program Files (x86)\Ubisoft', 'Games',
            'data', 'dev', 'src', 'Projects', 'tools', 'Datasets', 'models'
        )
        foreach ($candidate in $candidates) {
            $full = $prefix + $candidate
            if (Test-Path -LiteralPath $full -PathType Container) { $found.Add($full) }
        }
    }

    foreach ($candidate in $Extra) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $full = $null
        # Absolute paths only: a relative path would resolve against the
        # process directory, which is not where the user thinks they are.
        if ($candidate -match '^[A-Za-z]:\\') {
            try { $full = [System.IO.Path]::GetFullPath($candidate) } catch { $full = $null }
        }
        if ($null -ne $full -and $full.ToUpper().StartsWith($prefix) -and (Test-Path -LiteralPath $full -PathType Container)) {
            $found.Add($full)
        } else {
            Write-Warning "Skipping folder (give a full path to an existing folder on drive $($Drive.ToUpper()):): $candidate"
        }
    }

    # Drop duplicates and any root that sits inside another root, so nothing
    # is counted twice.
    # A drive root keeps its backslash ("C:" alone means "current folder on C:").
    $normalised = @($found | ForEach-Object {
        $trimmed = $_.TrimEnd('\')
        if ($trimmed.Length -eq 2) { $trimmed + '\' } else { $trimmed }
    } | Sort-Object -Unique)
    $kept = New-Object System.Collections.Generic.List[string]
    foreach ($root in $normalised) {
        $inside = $false
        foreach ($other in $normalised) {
            $base = $other.TrimEnd('\') + '\'
            if ($base.Length -lt $root.Length -and $root.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
                $inside = $true
                break
            }
        }
        if (-not $inside) { $kept.Add($root) }
    }
    return $kept.ToArray()
}

function Test-TriageLink {
    <#
        True for junctions and symbolic links (which must never be followed).
        False for other reparse points, such as OneDrive placeholder folders,
        which are ordinary local folders. If the type cannot be read, the
        folder is treated as a link and not followed.
    #>
    param([string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -Force
        $type = [string]$item.LinkType
        return ($type -eq 'Junction' -or $type -eq 'SymbolicLink')
    } catch { return $true }
}

function Add-TriageTally {
    param($State, $Class, [long]$Bytes, [long]$Count)

    $State.BucketBytes[$Class.Bucket] += $Bytes
    $State.BucketFiles[$Class.Bucket] += $Count

    # One row per store: several stores can share the same instruction text.
    $key = $Class.Bucket + '|' + $Class.Mechanism + '|' + $Class.Note
    if (-not $State.Mechanisms.ContainsKey($key)) {
        $State.Mechanisms[$key] = [pscustomobject]@{
            Bucket = $Class.Bucket; Mechanism = $Class.Mechanism; Note = $Class.Note
            Files = [long]0; TotalBytes = [long]0
        }
    }
    $entry = $State.Mechanisms[$key]
    $entry.Files      += $Count
    $entry.TotalBytes += $Bytes
}

function Invoke-TriageWalk {
    <#
        Breadth-first walk of one root. Skips reparse points (junctions and
        symbolic links), contains errors per directory, and never opens a file.
        Cloud placeholders that occupy no local space are not counted.
    #>
    param([string]$Root, [int]$MaxDepth, [long]$MinBytes, $State, [scriptblock]$OnProgress)

    $reparse   = [System.IO.FileAttributes]::ReparsePoint
    $cloudOnly = 0x401000    # Offline (0x1000) + RecallOnDataAccess (0x400000)
    $now       = Get-Date
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $queue     = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue([pscustomobject]@{ Path = $Root; Depth = 0; Subtree = $Root; StoreRoot = $null; StoreRule = $null })

    while ($queue.Count -gt 0) {
        if ($script:TriageCancel) { $State.Cancelled = $true; return }
        $node = $queue.Dequeue()

        $dir = $null
        $parentStore = $null
        if ($null -ne $node.StoreRoot) { $parentStore = $State.Stores[$node.StoreRoot] }

        try { $dir = New-Object System.IO.DirectoryInfo $node.Path } catch {
            $State.DeniedCount++
            if ($null -ne $parentStore) { $parentStore.Incomplete = $true }
            continue
        }
        try {
            if (-not $dir.Exists) { continue }
            if (($dir.Attributes -band $reparse) -and (Test-TriageLink -Path $dir.FullName)) {
                $State.LinkCount++
                if ($null -ne $parentStore) { $parentStore.HasLink = $true }
                continue
            }
        } catch {
            $State.DeniedCount++
            if ($null -ne $parentStore) { $parentStore.Incomplete = $true }
            continue
        }

        $dirKey = $dir.FullName
        if (-not $dirKey.EndsWith('\')) { $dirKey += '\' }
        $dirClass      = Get-TriageClassification -Path $dirKey
        $dirIsFallback = [object]::ReferenceEquals($dirClass, $script:TriageFallbackReview)

        # Delete candidates: the topmost folder of each recyclable store. A
        # store is one folder tree in which everything has the same rule.
        $store = $null
        if ($dirClass.Bucket -eq 'Delete' -and $script:TriageRecyclableNotes.ContainsKey($dirClass.Note)) {
            if ($null -ne $parentStore -and [object]::ReferenceEquals($node.StoreRule, $dirClass)) {
                $store = $parentStore
            } else {
                if ($null -ne $parentStore) { $parentStore.Mixed = $true }
                $store = [pscustomobject]@{
                    Path = $dir.FullName; Match = $dirClass.Match; Note = $dirClass.Note
                    TotalBytes = [long]0; Files = [long]0; Mixed = $false; Incomplete = $false; HasLink = $false
                    Personal = ''; LongPath = $false
                }
                $State.Stores[$dir.FullName] = $store
            }
        } elseif ($null -ne $parentStore) {
            $parentStore.Mixed = $true
        }
        $deniedBefore = $State.DeniedCount
        $depthBefore  = $State.DepthLimited
        $dirFiles     = [long]0

        $smallBytes = [long]0; $smallCount = [long]0
        $moveBytes  = [long]0; $moveCount  = [long]0
        $dirBytes   = [long]0

        try {
            foreach ($file in $dir.EnumerateFiles()) {
                # One unreadable or odd file must not cost the rest of the folder.
                try {
                    if (([int]$file.Attributes -band $cloudOnly) -ne 0) { $State.CloudOnlyFiles++; continue }

                    $length = $file.Length

                    if ($length -ge $MinBytes) {
                        $class = Get-TriageClassification -Path $file.FullName
                        $idle  = [int][math]::Floor(($now - $file.LastWriteTime).TotalDays)
                        if ($idle -lt 0) { $idle = 0 }
                        $State.Files.Add([pscustomobject]@{
                            Bucket    = $class.Bucket
                            Mechanism = $class.Mechanism
                            Note      = $class.Note
                            SizeBytes = [long]$length
                            LastWrite = $file.LastWriteTime.ToString('yyyy-MM-dd', $invariant)
                            DaysIdle  = $idle
                            Path      = $file.FullName
                        })
                        Add-TriageTally -State $State -Class $class -Bytes $length -Count 1
                        if ($null -ne $store -and -not [object]::ReferenceEquals($class, $dirClass)) { $store.Mixed = $true }
                    }
                    elseif ($dirIsFallback -and $script:TriageExtensionSet.ContainsKey($file.Extension.ToLowerInvariant())) {
                        $moveBytes += $length; $moveCount++
                    }
                    else {
                        $smallBytes += $length; $smallCount++
                    }
                    $dirBytes += $length
                    $dirFiles++
                    if ($null -ne $store) {
                        # A personal file type inside a rebuildable store means it is not purely rebuildable.
                        if ($store.Personal -eq '' -and $script:TriagePersonalExtensions.ContainsKey($file.Extension.ToLowerInvariant())) { $store.Personal = $file.FullName }
                        if ($file.FullName.Length -ge 248) { $store.LongPath = $true }
                    }
                }
                catch { $State.DeniedCount++ }
            }
        }
        catch [System.UnauthorizedAccessException]      { $State.DeniedCount++ }
        catch [System.Security.SecurityException]       { $State.DeniedCount++ }
        catch [System.IO.IOException]                   { $State.DeniedCount++ }
        catch                                           { $State.DeniedCount++ }

        if ($smallCount -gt 0) { Add-TriageTally -State $State -Class $dirClass -Bytes $smallBytes -Count $smallCount }
        if ($moveCount  -gt 0) { Add-TriageTally -State $State -Class $script:TriageFallbackMove -Bytes $moveBytes -Count $moveCount }

        if ($dirBytes -gt 0) { $State.Folders[$node.Subtree] += $dirBytes }
        $State.ScannedBytes += $dirBytes
        $State.DirCount++

        if ($null -ne $OnProgress -and ($State.DirCount % 25) -eq 0) {
            & $OnProgress $State.DirCount $State.ScannedBytes $dir.FullName
        }

        try {
            foreach ($child in $dir.EnumerateDirectories()) {
                if ($node.Depth -ge $MaxDepth) { $State.DepthLimited++; break }
                $subtree = $node.Subtree
                if ($node.Depth -lt 2) { $subtree = $child.FullName }
                $childRoot = $null; $childRule = $null
                if ($null -ne $store) { $childRoot = $store.Path; $childRule = $dirClass }
                $queue.Enqueue([pscustomobject]@{ Path = $child.FullName; Depth = $node.Depth + 1; Subtree = $subtree; StoreRoot = $childRoot; StoreRule = $childRule })
            }
        }
        catch [System.UnauthorizedAccessException]      { $State.DeniedCount++ }
        catch [System.Security.SecurityException]       { $State.DeniedCount++ }
        catch [System.IO.IOException]                   { $State.DeniedCount++ }
        catch                                           { $State.DeniedCount++ }

        if ($null -ne $store) {
            $store.TotalBytes += $dirBytes
            $store.Files      += $dirFiles
            if ($State.DeniedCount -ne $deniedBefore -or $State.DepthLimited -ne $depthBefore) { $store.Incomplete = $true }
        }
    }
}

function New-TriageScanState {
    $state = [pscustomobject]@{
        BucketBytes    = @{}
        BucketFiles    = @{}
        Mechanisms     = @{}
        Folders        = @{}
        Stores         = @{}
        Files          = New-Object System.Collections.Generic.List[object]
        DeniedCount    = 0
        LinkCount      = 0
        DepthLimited   = 0
        CloudOnlyFiles = [long]0
        ScannedBytes   = [long]0
        DirCount       = 0
        Cancelled      = $false
    }
    foreach ($name in @('Redirect', 'Delete', 'Move', 'Review', 'Never')) { $state.BucketBytes[$name] = [long]0; $state.BucketFiles[$name] = [long]0 }
    return $state
}

function Invoke-TriageScan {
    <#
        Runs the whole read-only scan and returns one Result object.
        Set $script:TriageCancel = $true (for example from -OnProgress) to stop
        early; the partial result is returned with Cancelled = $true.
    #>
    [CmdletBinding()]
    param(
        [ValidatePattern('^[A-Za-z]$')] [string]   $SourceDrive      = 'C',
        [ValidatePattern('^[A-Za-z]$')] [string]   $DestinationDrive = 'D',
        [ValidateRange(1, 1048576)]     [int]      $MinSizeMB        = 100,
        [ValidateRange(1, 64)]          [int]      $MaxDepth         = 24,
        [ValidateRange(1, 5000)]        [int]      $TopCount         = 300,
                                        [string[]] $AdditionalRoot   = @(),
                                        [switch]   $SkipDefaultRoots,
                                        [scriptblock] $OnProgress
    )

    Initialize-TriageRules

    $source = Get-DriveFacts -Letter $SourceDrive
    if ($null -eq $source) { throw "Drive $($SourceDrive.ToUpper()): is not available." }
    if ($source.Type -ne 'Fixed') {
        throw "Drive $($SourceDrive.ToUpper()): is a $($source.Type) drive. Only local fixed disks are scanned, so nothing is ever read over the network."
    }
    $destination = $null
    if ($DestinationDrive.ToUpper() -ne $SourceDrive.ToUpper()) {
        $destination = Get-DriveFacts -Letter $DestinationDrive
    }

    $roots = @(Get-ScanRoots -Drive $SourceDrive -Extra $AdditionalRoot -SkipDefaultRoots:$SkipDefaultRoots)
    if ($roots.Count -eq 0) { throw 'There is nothing to scan: no readable folder was found on the source drive.' }

    $bucketNames = @('Redirect', 'Delete', 'Move', 'Review', 'Never')
    $state = New-TriageScanState
    foreach ($root in $roots)       { $state.Folders[$root] = [long]0 }

    $script:TriageCancel = $false
    $minBytes = [long]$MinSizeMB * 1MB

    foreach ($root in $roots) {
        if ($state.Cancelled) { break }
        # Subtree keys are created lazily; make sure "+=" never hits a missing key.
        Invoke-TriageWalk -Root $root -MaxDepth $MaxDepth -MinBytes $minBytes -State $state -OnProgress $OnProgress
    }

    $scannedFiles = [long]0
    $buckets = foreach ($name in $bucketNames) {
        $scannedFiles += $state.BucketFiles[$name]
        [pscustomobject]@{ Bucket = $name; Files = [long]$state.BucketFiles[$name]; TotalBytes = [long]$state.BucketBytes[$name] }
    }

    $mechanisms = @($state.Mechanisms.Values |
        Where-Object { $_.Bucket -eq 'Redirect' -or $_.Bucket -eq 'Delete' -or $_.Bucket -eq 'Move' } |
        Sort-Object TotalBytes -Descending)

    $folders = @($state.Folders.GetEnumerator() | Where-Object { $_.Value -gt 0 } |
        Sort-Object Value -Descending | Select-Object -First 25 |
        ForEach-Object { [pscustomobject]@{ Folder = [string]$_.Key; TotalBytes = [long]$_.Value } })

    $files = @($state.Files | Sort-Object SizeBytes -Descending | Select-Object -First $TopCount)

    $deleteCandidates = @($state.Stores.Values | Where-Object { $_.TotalBytes -gt 0 } |
        Sort-Object TotalBytes -Descending | Select-Object -First 200)

    return [pscustomobject]@{
        ToolVersion       = $script:TriageVersion
        GeneratedAt       = (Get-Date).ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
        UserName          = [string]$env:USERNAME
        ComputerName      = [string]$env:COMPUTERNAME
        Source            = $source
        Destination       = $destination
        Status            = Get-PressureStatus -Facts $source
        MinSizeMB         = $MinSizeMB
        Roots             = @($roots)
        DeniedCount       = [int]$state.DeniedCount
        LinkFoldersSkipped  = [int]$state.LinkCount
        DepthLimitedFolders = [int]$state.DepthLimited
        CloudOnlyFiles    = [long]$state.CloudOnlyFiles
        ScannedBytes      = [long]$state.ScannedBytes
        ScannedFiles      = $scannedFiles
        Cancelled         = [bool]$state.Cancelled
        Buckets           = @($buckets)
        Mechanisms        = $mechanisms
        Folders           = $folders
        Files             = $files
        DeleteCandidates  = $deleteCandidates
        ElevatedChecklist = @($script:TriageElevatedChecklist)
    }
}

function Get-SampleTriageResult {
    # Fixed, fictional data. Used by the self-test and for previews; it never
    # touches the disk.
    $gb = [long]1GB
    $profilePath = 'C:\Users\sample'

    $mechanisms = @(
        [pscustomobject]@{ Bucket = 'Redirect'; Mechanism = 'HF_HOME'; Note = 'Hub, datasets and metrics caches'; Files = [long]1840; TotalBytes = [long](94.2 * $gb) }
        [pscustomobject]@{ Bucket = 'Move'; Mechanism = 'Steam > Storage > Move'; Note = 'Steam game library'; Files = [long]51200; TotalBytes = [long](71.4 * $gb) }
        [pscustomobject]@{ Bucket = 'Redirect'; Mechanism = 'Settings > Resources > Disk image location'; Note = 'Docker Desktop data: images, containers and volumes. Move it with this setting; do not delete it'; Files = [long]3; TotalBytes = [long](61.0 * $gb) }
        [pscustomobject]@{ Bucket = 'Move'; Mechanism = 'Move + mklink /J'; Note = 'iPhone/iPad backup; no setting exists'; Files = [long]30211; TotalBytes = [long](44.0 * $gb) }
        [pscustomobject]@{ Bucket = 'Move'; Mechanism = 'Properties > Location tab'; Note = 'Downloads'; Files = [long]2210; TotalBytes = [long](38.5 * $gb) }
        [pscustomobject]@{ Bucket = 'Redirect'; Mechanism = 'pkgs_dirs in .condarc'; Note = 'conda package cache'; Files = [long]21450; TotalBytes = [long](22.7 * $gb) }
        [pscustomobject]@{ Bucket = 'Delete'; Mechanism = 'Reinstall from lockfile'; Note = 'Reproducible; never copy'; Files = [long]612044; TotalBytes = [long](14.6 * $gb) }
        [pscustomobject]@{ Bucket = 'Delete'; Mechanism = 'Recreate on the other drive'; Note = 'Virtual environment; save requirements first (pip freeze), never copy'; Files = [long]188230; TotalBytes = [long](12.2 * $gb) }
        [pscustomobject]@{ Bucket = 'Redirect'; Mechanism = 'PIP_CACHE_DIR'; Note = 'pip wheel cache'; Files = [long]6120; TotalBytes = [long](9.8 * $gb) }
        [pscustomobject]@{ Bucket = 'Delete'; Mechanism = 'TEMP / TMP'; Note = 'User temporary files'; Files = [long]9120; TotalBytes = [long](6.3 * $gb) }
    )

    $files = @(
        [pscustomobject]@{ Bucket = 'Redirect'; Mechanism = 'Settings > Resources > Disk image location'; Note = 'Docker Desktop data: images, containers and volumes. Move it with this setting; do not delete it'; SizeBytes = [long](61.0 * $gb); LastWrite = '2026-11-16'; DaysIdle = 3; Path = "$profilePath\AppData\Local\Docker\wsl\disk\docker_data.vhdx" }
        [pscustomobject]@{ Bucket = 'Redirect'; Mechanism = 'HF_HOME'; Note = 'Hub, datasets and metrics caches'; SizeBytes = [long](15.2 * $gb); LastWrite = '2026-11-07'; DaysIdle = 12; Path = "$profilePath\.cache\huggingface\hub\models--example--model-8b\blobs\2b1879f3" }
        [pscustomobject]@{ Bucket = 'Move'; Mechanism = 'Move + mklink /J'; Note = 'iPhone/iPad backup; no setting exists'; SizeBytes = [long](12.4 * $gb); LastWrite = '2026-10-09'; DaysIdle = 41; Path = "$profilePath\Apple\MobileSync\Backup\00008110-000A1D2E\Manifest.db" }
        [pscustomobject]@{ Bucket = 'Move'; Mechanism = 'Properties > Location tab'; Note = 'Downloads'; SizeBytes = [long](5.8 * $gb); LastWrite = '2026-05-13'; DaysIdle = 190; Path = "$profilePath\Downloads\ubuntu-24.04.1-desktop-amd64.iso" }
        [pscustomobject]@{ Bucket = 'Move'; Mechanism = 'Explorer move'; Note = 'Self-contained data file with no registry dependency'; SizeBytes = [long](4.9 * $gb); LastWrite = '2026-09-16'; DaysIdle = 64; Path = 'C:\Datasets\sample\flows.parquet' }
        [pscustomobject]@{ Bucket = 'Delete'; Mechanism = 'Recreate on the other drive'; Note = 'Virtual environment; save requirements first (pip freeze), never copy'; SizeBytes = [long](2.4 * $gb); LastWrite = '2026-10-17'; DaysIdle = 33; Path = 'C:\src\project\.venv\Lib\site-packages\torch\lib\torch_cuda.dll' }
        [pscustomobject]@{ Bucket = 'Review'; Mechanism = 'Confirm owner'; Note = 'No rule matched'; SizeBytes = [long](2.1 * $gb); LastWrite = '2026-01-23'; DaysIdle = 300; Path = "$profilePath\AppData\Local\SomeVendor\data\store.bin" }
        [pscustomobject]@{ Bucket = 'Never'; Mechanism = 'Uninstall and reinstall to D:'; Note = 'Install path is registry-bound'; SizeBytes = [long](1.9 * $gb); LastWrite = '2026-03-14'; DaysIdle = 250; Path = 'C:\Program Files\Example Toolkit\bin\library64.dll' }
    )

    $totals = @{ Redirect = [long]0; Delete = [long]0; Move = [long]0; Review = [long](11.8 * $gb); Never = [long](6.1 * $gb) }
    $counts = @{ Redirect = [long]0; Delete = [long]0; Move = [long]0; Review = [long]20311; Never = [long]88120 }
    foreach ($m in $mechanisms) { $totals[$m.Bucket] += $m.TotalBytes; $counts[$m.Bucket] += $m.Files }

    $scannedBytes = [long]0; $scannedFiles = [long]0
    $buckets = foreach ($name in @('Redirect', 'Delete', 'Move', 'Review', 'Never')) {
        $scannedBytes += $totals[$name]; $scannedFiles += $counts[$name]
        [pscustomobject]@{ Bucket = $name; Files = $counts[$name]; TotalBytes = $totals[$name] }
    }

    $total = [long](476 * $gb); $free = [long](21.6 * $gb)
    return [pscustomobject]@{
        ToolVersion       = $script:TriageVersion
        GeneratedAt       = '2026-11-19 14:02'
        UserName          = 'sample'
        ComputerName      = 'SAMPLE-PC'
        Source            = [pscustomobject]@{ Letter = 'C'; Label = 'Windows'; Format = 'NTFS'; Type = 'Fixed'; TotalBytes = $total; FreeBytes = $free; UsedBytes = $total - $free; PercentFree = 4.5 }
        Destination       = [pscustomobject]@{ Letter = 'D'; Label = 'Data'; Format = 'NTFS'; Type = 'Fixed'; TotalBytes = [long](1863 * $gb); FreeBytes = [long](1410 * $gb); UsedBytes = [long](453 * $gb); PercentFree = 75.7 }
        Status            = 'LOW'
        MinSizeMB         = 100
        Roots             = @($profilePath, 'C:\Users\Public', 'C:\ProgramData', 'C:\src', 'C:\Datasets')
        DeniedCount       = 14
        LinkFoldersSkipped  = 2
        DepthLimitedFolders = 0
        CloudOnlyFiles    = [long]0
        ScannedBytes      = $scannedBytes
        ScannedFiles      = $scannedFiles
        Cancelled         = $false
        Buckets           = @($buckets)
        Mechanisms        = $mechanisms
        Folders           = @(
            [pscustomobject]@{ Folder = "$profilePath\.cache\huggingface"; TotalBytes = [long](94.2 * $gb) }
            [pscustomobject]@{ Folder = 'C:\Program Files (x86)\Steam\steamapps'; TotalBytes = [long](71.4 * $gb) }
            [pscustomobject]@{ Folder = "$profilePath\AppData\Local\Docker"; TotalBytes = [long](61.0 * $gb) }
            [pscustomobject]@{ Folder = "$profilePath\Apple\MobileSync"; TotalBytes = [long](44.0 * $gb) }
            [pscustomobject]@{ Folder = "$profilePath\Downloads"; TotalBytes = [long](38.5 * $gb) }
        )
        Files             = $files
        DeleteCandidates  = @(
            [pscustomobject]@{ Path = 'C:\src\webapp\node_modules'; Match = '*\node_modules\*'; Note = 'node_modules; needs a package-lock file to rebuild, never copy'; TotalBytes = [long](9.4 * $gb); Files = [long]412044; Mixed = $false; Incomplete = $false; HasLink = $false; Personal = ''; LongPath = $false }
            [pscustomobject]@{ Path = "$profilePath\AppData\Local\D3DSCache"; Match = '*\AppData\Local\D3DSCache\*'; Note = 'DirectX shader cache'; TotalBytes = [long](2.2 * $gb); Files = [long]6120; Mixed = $false; Incomplete = $false; HasLink = $false; Personal = ''; LongPath = $false }
            [pscustomobject]@{ Path = "$profilePath\AppData\Local\CrashDumps"; Match = '*\AppData\Local\CrashDumps\*'; Note = 'Crash dumps'; TotalBytes = [long](1.1 * $gb); Files = [long]14; Mixed = $false; Incomplete = $false; HasLink = $false; Personal = ''; LongPath = $false }
        )
        ElevatedChecklist = @($script:TriageElevatedChecklist)
    }
}
#endregion

#region Reports --------------------------------------------------------------

function Resolve-ReportDirectory {
    <#
        The report directory is the only write target, so it is validated:
          - UNC paths are refused, so nothing is ever written over the network.
          - the target must be on a local fixed disk (no mapped network drives,
            no removable media).
          - an existing target that is a junction or symlink is refused, so a
            planted link cannot redirect the write.
    #>
    param([string]$Requested)

    if ([string]::IsNullOrWhiteSpace($Requested)) {
        $target = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'DiskReports'
    } else {
        $target = $Requested
    }

    if ($target.StartsWith('\\')) {
        throw "The report folder must be a local path. Network (UNC) paths are refused: $target"
    }
    if ($target -notmatch '^[A-Za-z]:\\') {
        throw "The report folder must be a full path on a local drive, for example C:\Reports. Got: $target"
    }
    $target = [System.IO.Path]::GetFullPath($target)

    $volume = Get-DriveFacts -Letter $target.Substring(0, 1)
    if ($null -eq $volume -or $volume.Type -ne 'Fixed') {
        throw "The report folder must be on a local fixed disk: $target"
    }

    # Neither the folder nor any folder above it may be a junction or a
    # symbolic link, so a link cannot send the report somewhere else.
    $probe = $target
    while (-not [string]::IsNullOrEmpty($probe) -and $probe.Length -gt 3) {
        if (Test-Path -LiteralPath $probe) {
            $info = New-Object System.IO.DirectoryInfo $probe
            if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and (Test-TriageLink -Path $probe)) {
                throw "The report folder is, or is inside, a junction or symbolic link, which is refused: $probe"
            }
        }
        $probe = [System.IO.Path]::GetDirectoryName($probe)
    }

    if (-not (Test-Path -LiteralPath $target)) {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
    }

    return $target
}

function ConvertTo-TriageMarkdown {
    param([Parameter(Mandatory)] $Result)

    $tick = [string][char]96
    $sb   = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# Disk space triage - drive $($Result.Source.Letter):")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Generated $($Result.GeneratedAt) by $($Result.UserName) on $($Result.ComputerName). Tool version $($Result.ToolVersion).")
    [void]$sb.AppendLine('Read-only scan with standard user rights. Nothing was moved, deleted or changed.')
    if ($Result.Cancelled) { [void]$sb.AppendLine(); [void]$sb.AppendLine('**The scan was cancelled. These results are partial.**') }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Drives')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Drive | Label | Total | Free | % free | Status |')
    [void]$sb.AppendLine('|---|---|---|---|---|---|')
    [void]$sb.AppendLine("| $($Result.Source.Letter): | $($Result.Source.Label) | $(Format-Size $Result.Source.TotalBytes) | $(Format-Size $Result.Source.FreeBytes) | $($Result.Source.PercentFree) | $($Result.Status) |")
    if ($null -ne $Result.Destination) {
        $d = $Result.Destination
        [void]$sb.AppendLine("| $($d.Letter): | $($d.Label) | $(Format-Size $d.TotalBytes) | $(Format-Size $d.FreeBytes) | $($d.PercentFree) | target |")
    }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Space by bucket')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Bucket | Files | Size |')
    [void]$sb.AppendLine('|---|---|---|')
    foreach ($b in @($Result.Buckets)) { [void]$sb.AppendLine("| $($b.Bucket) | $($b.Files) | $(Format-Size $b.TotalBytes) |") }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Do these first')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Size | Bucket | What to do | Why | Files |')
    [void]$sb.AppendLine('|---|---|---|---|---|')
    foreach ($m in @($Result.Mechanisms)) {
        [void]$sb.AppendLine("| $(Format-Size $m.TotalBytes) | $($m.Bucket) | $($m.Mechanism) | $($m.Note) | $($m.Files) |")
    }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Largest folders')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Size | Folder |')
    [void]$sb.AppendLine('|---|---|')
    foreach ($f in @($Result.Folders)) { [void]$sb.AppendLine("| $(Format-Size $f.TotalBytes) | $tick$(([string]$f.Folder).Replace($tick, "'"))$tick |") }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("## Largest files ($($Result.MinSizeMB) MB and larger)")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Size | Bucket | What to do | Idle days | Path |')
    [void]$sb.AppendLine('|---|---|---|---|---|')
    foreach ($f in @($Result.Files)) {
        [void]$sb.AppendLine("| $(Format-Size $f.SizeBytes) | $($f.Bucket) | $($f.Mechanism) | $($f.DaysIdle) | $tick$(([string]$f.Path).Replace($tick, "'"))$tick |")
    }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Not measured here - requires administrator')
    [void]$sb.AppendLine()
    foreach ($c in @($Result.ElevatedChecklist)) { [void]$sb.AppendLine("- **$($c.Item)**: $($c.Action)") }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Scan details')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("- Folders scanned: $(@($Result.Roots) -join '; ')")
    [void]$sb.AppendLine("- Unreadable locations skipped: $($Result.DeniedCount) (no privilege escalation attempted)")
    [void]$sb.AppendLine("- Junctions and symbolic links not followed: $($Result.LinkFoldersSkipped)")
    [void]$sb.AppendLine("- Folders deeper than the depth limit, not scanned: $($Result.DepthLimitedFolders)")
    [void]$sb.AppendLine("- Cloud-only placeholder files not counted: $($Result.CloudOnlyFiles)")
    [void]$sb.AppendLine("- Total scanned: $(Format-Size $Result.ScannedBytes) in $($Result.ScannedFiles) files")
    return $sb.ToString()
}

function Export-TriageReport {
    <#
        Writes the HTML, Markdown and CSV reports. Apart from the action log
        and the empty folders of confirmed redirects, these are the only files
        this tool writes.
    #>
    param([Parameter(Mandatory)] $Result, [string]$Directory)

    $target = Resolve-ReportDirectory -Requested $Directory
    $stamp  = (Get-Date).ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
    $html   = Join-Path $target "DiskTriage_$stamp.html"
    $md     = Join-Path $target "DiskTriage_$stamp.md"
    $csv    = Join-Path $target "DiskTriage_$stamp.csv"

    ConvertTo-TriageHtml -Result $Result     | Out-File -LiteralPath $html -Encoding UTF8
    ConvertTo-TriageMarkdown -Result $Result | Out-File -LiteralPath $md   -Encoding UTF8
    @($Result.Files) | Select-Object Bucket, Mechanism, SizeBytes, DaysIdle, LastWrite, Path, Note |
        Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8

    return [pscustomobject]@{ Directory = $target; Html = $html; Markdown = $md; Csv = $csv }
}

#region Actions --------------------------------------------------------------
# Redirect: after the user confirms each change, the tool can
#   1. create a folder on the destination drive,
#   2. set (or restore) a user-level environment variable from the list below,
#   3. optionally (Move-TriageStore) copy the existing contents across first,
#      verify every file by SHA-256, and then ask Windows to put the old
#      folder in the Recycle Bin.
# Set-TriageRedirect alone moves and deletes nothing. Every change is written
# to the action log.

function New-TriageRedirectTarget {
    param([string]$Variable, [string]$Mechanism, [string]$RelativePath, [string]$Effect, [string]$OldFolder)
    [pscustomobject]@{ Variable = $Variable; Mechanism = $Mechanism; RelativePath = $RelativePath; Effect = $Effect; OldFolder = $OldFolder }
}

# Only stores whose location is controlled by one environment variable and
# where pointing it elsewhere cannot break the tool. Stores that also hold
# tools on PATH, credentials or project data (CARGO_HOME, GRADLE_USER_HOME,
# GEM_HOME, Poetry, Yarn, TensorFlow Datasets, Docker, WSL ...) are
# deliberately absent and stay manual. The last column is what to do with the
# old folder afterwards; it is never "delete" for a store that can hold
# something that cannot be downloaded again.
$script:TriageRedirectTargets = @(
    New-TriageRedirectTarget 'PIP_CACHE_DIR'      'PIP_CACHE_DIR'        'AppData\Local\pip\Cache'  'The cache refills on the next install.' 'It is a pure cache: once new files appear in the new folder, you can delete the old one.'
    New-TriageRedirectTarget 'UV_CACHE_DIR'       'UV_CACHE_DIR'         'AppData\Local\uv\cache'   'The cache refills on the next install. If your projects stay on this drive, uv copies packages into each environment instead of linking them, so environments get larger.' 'It is a pure cache: once new files appear in the new folder, you can delete the old one.'
    New-TriageRedirectTarget 'npm_config_cache'   'npm config set cache' 'AppData\Local\npm-cache'  'The cache refills on the next install.' 'It is a pure cache: once new files appear in the new folder, you can delete the old one.'
    New-TriageRedirectTarget 'NUGET_PACKAGES'     'NUGET_PACKAGES'       '.nuget\packages'          'Restart Visual Studio. Packages restore again on the next build.' 'It is a pure cache: after a successful build, you can delete the old one.'
    New-TriageRedirectTarget 'GOMODCACHE'         'GOMODCACHE'           'go\pkg\mod'               'Modules download again on the next build.' 'It is a pure cache: after a successful build, you can delete the old one (go clean -modcache does it; the files are read-only).'
    New-TriageRedirectTarget 'COMPOSER_CACHE_DIR' 'COMPOSER_CACHE_DIR'   'AppData\Local\Composer'   'The cache refills on the next install.' 'It is a pure cache: once new files appear in the new folder, you can delete the old one.'
    New-TriageRedirectTarget 'TRITON_CACHE_DIR'   'TRITON_CACHE_DIR'     '.triton\cache'            'The cache refills on next use.' 'It is a pure cache: you can delete the old one.'
    New-TriageRedirectTarget 'TORCH_HOME'         'TORCH_HOME'           '.cache\torch'             'Pretrained weights download again on first use.' 'Weights you downloaded come back by themselves. Delete the old folder only if you put nothing of your own in it.'
    New-TriageRedirectTarget 'HF_HOME'            'HF_HOME'              '.cache\huggingface'       'New downloads go to the new folder. Your Hugging Face sign-in token is in the old folder, so sign in again or copy the file named token across. If you also set HF_HUB_CACHE or TRANSFORMERS_CACHE, those still win.' 'Do NOT delete the old folder straight away: it holds your sign-in token and may hold models that are no longer downloadable. Move what you need, then delete it.'
    New-TriageRedirectTarget 'KERAS_HOME'         'KERAS_HOME'           '.keras'                   'Keras datasets and weights download again. Copy the file keras.json into the new folder, or Keras falls back to its default backend.' 'Copy keras.json across first. After that the old folder can be deleted.'
    New-TriageRedirectTarget 'NLTK_DATA'          'NLTK_DATA'            'AppData\Roaming\nltk_data' 'New corpus downloads go to the new folder. Corpora already in the old folder keep working while it exists.' 'Keep the old folder, or move its contents into the new one before deleting it.'
    New-TriageRedirectTarget 'OLLAMA_MODELS'      'OLLAMA_MODELS'        '.ollama\models'           'Quit Ollama from the system tray and start it again. It will then look for models only in the new folder.' 'Do NOT delete the old folder: move its contents into the new one. Models you created or imported yourself cannot be downloaded again.'
)

# Stores that hold nothing but downloads the owning tool fetches again. Only
# for these may a file that already exists in the new folder win over a
# different old one when the old contents are moved across.
$script:TriagePureCaches = @{
    'PIP_CACHE_DIR' = $true; 'UV_CACHE_DIR' = $true; 'npm_config_cache' = $true; 'NUGET_PACKAGES' = $true
    'GOMODCACHE' = $true; 'COMPOSER_CACHE_DIR' = $true; 'TRITON_CACHE_DIR' = $true
}

function Get-TriageProfileName {
    if (-not $env:USERPROFILE) { return '' }
    return [System.IO.Path]::GetFileName($env:USERPROFILE.TrimEnd('\'))
}

function Get-TriageRedirectFolder {
    # The one folder this tool will ever create for a target on a given drive.
    param([string]$Letter, $Target)
    return ('{0}:\FromC\Users\{1}\{2}' -f $Letter.ToUpper(), (Get-TriageProfileName), $Target.RelativePath)
}

function Test-TriageRedirectDrive {
    <#
        Returns '' when the drive may hold redirected stores, otherwise the
        reason it may not. It must be a local fixed NTFS or ReFS disk and must
        not be the drive that holds Windows or the user profile.
    #>
    param([string]$Letter)
    $facts = Get-DriveFacts -Letter $Letter
    if ($null -eq $facts)          { return 'The destination drive is not available.' }
    if ($facts.Type -ne 'Fixed')   { return 'The destination is not a local fixed disk.' }
    if ($facts.Format -ne 'NTFS' -and $facts.Format -ne 'ReFS') { return "The destination is formatted $($facts.Format); NTFS is required." }
    $upper = $Letter.ToUpper()
    if ($env:USERPROFILE -and $env:USERPROFILE.Substring(0, 1).ToUpper() -eq $upper) { return 'The destination is the drive that holds your user profile.' }
    if ($env:SystemDrive -and $env:SystemDrive.Substring(0, 1).ToUpper() -eq $upper)  { return 'The destination is the Windows drive.' }
    return ''
}

function Test-TriageFolderEmpty {
    # True when the folder does not exist, or exists as a folder with nothing in it.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    $info = New-Object System.IO.DirectoryInfo $Path
    foreach ($entry in $info.EnumerateFileSystemInfos()) { return $false }
    return $true
}

function Test-TriageLinkInPath {
    # True when the path, or any existing folder above it, is a junction or
    # symbolic link.
    param([string]$Path)
    $probe = $Path
    while (-not [string]::IsNullOrEmpty($probe) -and $probe.Length -gt 3) {
        if (Test-Path -LiteralPath $probe) {
            $info = New-Object System.IO.DirectoryInfo $probe
            if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and (Test-TriageLink -Path $probe)) { return $true }
        }
        $probe = [System.IO.Path]::GetDirectoryName($probe)
    }
    return $false
}

function Get-TriageRedirectPlan {
    <#
        Read-only. For each supported store that the scan found, says which
        user variable would be set to which folder, and whether that is
        possible. The new folder keeps the same name and position it has on
        the source drive, below <destination>:\FromC, so nothing can clash
        with an existing folder and the origin of every folder stays obvious:
            C:\Users\me\.cache\huggingface  ->  D:\FromC\Users\me\.cache\huggingface
    #>
    param([Parameter(Mandatory)] $Result, [string]$DestinationDrive)

    $letter = $DestinationDrive
    if ([string]::IsNullOrWhiteSpace($letter) -and $null -ne $Result.Destination) { $letter = [string]$Result.Destination.Letter }

    $driveProblem = 'The destination drive is not available.'
    $destination  = $null
    if (-not [string]::IsNullOrWhiteSpace($letter)) {
        $driveProblem = Test-TriageRedirectDrive -Letter $letter
        $destination  = Get-DriveFacts -Letter $letter
        if ($driveProblem -eq '' -and $letter.ToUpper() -eq [string]$Result.Source.Letter) { $driveProblem = 'The destination is the drive being cleaned.' }
    }
    if ((Get-TriageProfileName) -eq '') { $driveProblem = 'Your user profile folder could not be determined.' }

    $plan = foreach ($target in $script:TriageRedirectTargets) {
        $bytes = [long]0
        foreach ($m in @($Result.Mechanisms)) {
            if ($m.Bucket -eq 'Redirect' -and $m.Mechanism -eq $target.Mechanism) { $bytes += [long]$m.TotalBytes }
        }
        if ($bytes -le 0) { continue }

        $source   = Join-Path ([string]$env:USERPROFILE) $target.RelativePath
        $current  = [string][Environment]::GetEnvironmentVariable($target.Variable, 'User')
        $machine  = [string][Environment]::GetEnvironmentVariable($target.Variable, 'Machine')
        $proposed = ''
        $state    = 'Ready'
        $reason   = ''

        if ($driveProblem -ne '') {
            $state = 'Blocked'; $reason = $driveProblem
        } else {
            $proposed = Get-TriageRedirectFolder -Letter $letter -Target $target
            if (-not [string]::IsNullOrEmpty($current)) {
                $state = 'AlreadySet'; $reason = 'This variable is already set for your account. Change it yourself if it points at the wrong place.'
            } elseif (-not [string]::IsNullOrEmpty($machine)) {
                $state = 'Blocked'; $reason = 'This variable is set for the whole computer by an administrator.'
            } elseif (-not (Test-Path -LiteralPath $source -PathType Container)) {
                $state = 'Blocked'; $reason = 'This store was found, but not in its usual folder. Redirect it yourself (see the user guide).'
            } elseif (Test-TriageLinkInPath -Path $proposed) {
                $state = 'Blocked'; $reason = 'The new folder would sit below a junction or symbolic link.'
            } elseif (-not (Test-TriageFolderEmpty -Path $proposed)) {
                $state = 'Blocked'; $reason = 'The new folder already exists and is not empty. Check what is in it first.'
            } elseif ($null -ne $destination -and $destination.FreeBytes -lt $bytes) {
                $reason = 'the destination has less free space than this store uses now'
            }
        }

        # Can the files that are on the source drive now be moved across as well?
        $moveState  = 'Blocked'
        $moveReason = $reason
        $room       = ($null -ne $destination -and $destination.FreeBytes -ge ($bytes + 1GB))
        if ($state -eq 'Ready') {
            $moveState = 'Ready'; $moveReason = ''
        } elseif ($state -eq 'AlreadySet') {
            if ($current.TrimEnd('\') -ieq $proposed -and (Test-Path -LiteralPath $source -PathType Container)) {
                $moveState = 'Ready'; $moveReason = 'the setting is already switched; only the old files still have to move'
            } else {
                $moveReason = 'The variable points at a folder this tool did not choose. Move the old files yourself.'
            }
        }
        if ($moveState -eq 'Ready' -and -not $room) {
            $moveState = 'Blocked'; $moveReason = 'Not enough free space on the destination for the files that are there now.'
        }

        [pscustomobject]@{
            Variable      = $target.Variable
            SizeBytes     = $bytes
            SourceFolder  = $source
            CurrentValue  = $current
            ProposedValue = $proposed
            Effect        = $target.Effect
            OldFolder     = $target.OldFolder
            State         = $state
            Reason        = $reason
            MoveState     = $moveState
            MoveReason    = $moveReason
        }
    }
    return @($plan)
}

function Write-TriageActionLog {
    param([Parameter(Mandatory)] $Record, [string]$Directory)
    $target = Resolve-ReportDirectory -Requested $Directory
    $path   = Join-Path $target 'DiskTriage_actions.csv'
    $detail = ''
    if ($Record.PSObject.Properties.Name -contains 'Detail') { $detail = [string]$Record.Detail }
    [pscustomobject]@{ When = $Record.When; Action = $Record.Action; Variable = $Record.Variable; OldValue = $Record.OldValue; NewValue = $Record.NewValue; Detail = $detail } |
        Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -Append -Force
    return $path
}

function Set-TriageRedirect {
    <#
        Applies one plan item: creates the empty folder and sets the user
        variable. Re-validates everything first; a stale or edited plan item
        cannot widen what this function does. Returns the record needed to
        undo the change. -Populated is passed only by Move-TriageStore, after
        it has filled the (previously empty) folder with verified copies.
    #>
    param([Parameter(Mandatory)] $Item, [string]$LogDirectory, [switch]$Populated)

    $target = $script:TriageRedirectTargets | Where-Object { $_.Variable -ceq [string]$Item.Variable }
    if ($null -eq $target) { throw "Not a variable this tool manages: $($Item.Variable)" }

    # The caller supplies only the drive letter. The folder is recomputed here
    # and must equal what the plan showed, so nothing but the one expected
    # folder for this store can ever be created or assigned.
    $shown = [string]$Item.ProposedValue
    if ($shown -notmatch '^[A-Za-z]:\\') { throw "Refused: not a full local path: $shown" }
    $letter = $shown.Substring(0, 1)
    $value  = Get-TriageRedirectFolder -Letter $letter -Target $target
    if ($shown -cne $value) { throw "Refused: the new folder must be exactly $value. Got: $shown" }

    $driveProblem = Test-TriageRedirectDrive -Letter $letter
    if ($driveProblem -ne '') { throw "Refused: $driveProblem" }
    if (Test-TriageLinkInPath -Path $value) { throw "Refused: the new folder would sit below a junction or symbolic link: $value" }
    if (-not $Populated -and -not (Test-TriageFolderEmpty -Path $value)) { throw "Refused: the new folder already exists and is not empty: $value" }

    $old = [string][Environment]::GetEnvironmentVariable($target.Variable, 'User')
    if (-not [string]::IsNullOrEmpty($old)) { throw "Refused: $($target.Variable) is already set to $old. Nothing was changed." }
    $machine = [string][Environment]::GetEnvironmentVariable($target.Variable, 'Machine')
    if (-not [string]::IsNullOrEmpty($machine)) { throw "Refused: $($target.Variable) is set for the whole computer. Nothing was changed." }

    # No change without a place to record it.
    $logTarget = Resolve-ReportDirectory -Requested $LogDirectory

    if (-not (Test-Path -LiteralPath $value)) { New-Item -ItemType Directory -Path $value -Force | Out-Null }
    [Environment]::SetEnvironmentVariable($target.Variable, $value, 'User')

    $record = [pscustomobject]@{
        When     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        Action   = 'Set'
        Variable = $target.Variable
        OldValue = ''
        NewValue = $value
        LogPath  = ''
    }
    try { $record.LogPath = Write-TriageActionLog -Record $record -Directory $logTarget } catch { $record.LogPath = '' }
    return $record
}

function Undo-TriageRedirect {
    <#
        Reverses one Set-TriageRedirect: removes the variable again, but only
        if it still holds the value this tool gave it. The folder that was
        created is left in place (it may already contain downloads).
    #>
    param([Parameter(Mandatory)] $Record, [string]$LogDirectory)

    $target = $script:TriageRedirectTargets | Where-Object { $_.Variable -ceq [string]$Record.Variable }
    if ($null -eq $target) { throw "Not a variable this tool manages: $($Record.Variable)" }

    $now = [string][Environment]::GetEnvironmentVariable($target.Variable, 'User')
    if ($now -ne [string]$Record.NewValue) {
        throw "Not undone: $($target.Variable) no longer holds the value this tool set (it is now '$now')."
    }
    [Environment]::SetEnvironmentVariable($target.Variable, $null, 'User')

    $undo = [pscustomobject]@{
        When     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        Action   = 'Undo'
        Variable = $target.Variable
        OldValue = [string]$Record.NewValue
        NewValue = ''
        LogPath  = ''
    }
    try { $undo.LogPath = Write-TriageActionLog -Record $undo -Directory $LogDirectory } catch { $undo.LogPath = '' }
    return $undo
}
#endregion

#region Delete and Move ------------------------------------------------------
# Two further actions, each off until the user enables it and confirms:
#   Delete - ask Windows to put ONE whole store folder (from a short list of
#            rebuildable stores) in the Recycle Bin.
#   Move   - copy ONE plain data file to <drive>:\FromC\<same path> under a
#            temporary name, re-read and compare it by SHA-256, give it its
#            final name, then ask Windows to put the original in the Recycle
#            Bin.
# The script itself never deletes anything permanently except its own
# unverified temporary copy, and never overwrites. Whether an item lands in
# the Recycle Bin is finally up to Windows; items Windows could not recycle
# (too large, paths too long) are refused up front instead.

function Initialize-TriageRecycleBin {
    # The Recycle Bin is reached through the Visual Basic runtime that ships
    # with Windows. This loads an existing assembly; it compiles nothing.
    Add-Type -AssemblyName Microsoft.VisualBasic
}

function Test-TriageInteractive {
    # Without an interactive desktop Windows cannot use the Recycle Bin and
    # would delete permanently, so both actions refuse to run.
    return [bool][Environment]::UserInteractive
}

function Get-TriageRecycleLimit {
    # A conservative estimate of the largest item the Recycle Bin of a drive
    # accepts: half of the Windows default quota.
    param([string]$Letter)
    $facts = Get-DriveFacts -Letter $Letter
    if ($null -eq $facts) { return [long]0 }
    $total = [double]$facts.TotalBytes
    $quota = $total * 0.10
    if ($total -gt 40GB) { $quota = 4GB + 0.05 * ($total - 40GB) }
    return [long]($quota / 2)
}

function Test-TriageProtectedLocation {
    <#
        Returns '' or the reason a path may not be removed or moved by the
        tool because of WHERE it is: installed software, application data,
        and cloud-sync folders.
    #>
    param([string]$Path)
    if ($Path -match '~[0-9]') { return 'The path contains a short (8.3) name.' }
    if ($Path -match '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData)\\') { return 'It is inside installed software or system data.' }
    if ($Path -match '^[A-Za-z]:\\Users\\[^\\]+\\(OneDrive[^\\]*|Dropbox|iCloudDrive|iCloud Drive|My Drive|Google Drive|Box|Box Sync|MEGA|pCloud[^\\]*|Sync)\\') { return 'It is inside a cloud-sync folder; change it through the sync client.' }
    if ($Path -match '\\(iCloud Photos|SharePoint|scoop|chocolatey)\\') { return 'It is inside a sync or package-manager folder.' }
    return ''
}

function Get-TriageDeletePlan {
    <#
        Read-only. Lists the store folders the scan found that the tool may
        ask Windows to recycle, and why any of them is not offered.
    #>
    param([Parameter(Mandatory)] $Result)

    $plan = foreach ($c in @($Result.DeleteCandidates)) {
        $state = 'Ready'; $reason = ''
        $path   = [string]$c.Path
        $kind   = [string]$script:TriageRecyclableNotes[[string]$c.Note]
        $parent = [System.IO.Path]::GetDirectoryName($path)
        $leaf   = [System.IO.Path]::GetFileName($path).ToLowerInvariant()
        $where  = Test-TriageProtectedLocation -Path $path

        if ($kind -eq '') {
            $state = 'Blocked'; $reason = 'It is not one of the stores the tool may remove.'
        } elseif ($where -ne '') {
            $state = 'Blocked'; $reason = $where
        } elseif ($c.Mixed) {
            $state = 'Blocked'; $reason = 'It contains another store or a virtual disk.'
        } elseif ([string]$c.Personal -ne '') {
            $state = 'Blocked'; $reason = "It contains what looks like your own work: $([System.IO.Path]::GetFileName([string]$c.Personal))"
        } elseif ($c.HasLink) {
            $state = 'Blocked'; $reason = 'It contains a junction or symbolic link.'
        } elseif ($c.Incomplete) {
            $state = 'Blocked'; $reason = 'Part of it could not be read, so its contents are not fully known.'
        } elseif ($c.LongPath) {
            $state = 'Blocked'; $reason = 'It has paths too long for the Recycle Bin; Windows would delete it permanently. Remove it yourself if you are sure.'
        } elseif ([long]$c.TotalBytes -gt (Get-TriageRecycleLimit -Letter $path.Substring(0, 1))) {
            $state = 'Blocked'; $reason = 'It is too large for the Recycle Bin; Windows would delete it permanently. Remove it yourself if you are sure.'
        } elseif ($kind -eq 'NodeModules' -or $kind -eq 'RustTarget') {
            if ($path -match '\\AppData\\' -or $path -match '\\\.[^\\]+\\') {
                $state = 'Blocked'; $reason = 'It belongs to an application or a tool, not to one of your projects.'
            } elseif ($kind -eq 'NodeModules') {
                $lock = $false
                foreach ($name in @('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'bun.lockb')) {
                    if (Test-Path -LiteralPath (Join-Path $parent $name) -PathType Leaf) { $lock = $true }
                }
                if (-not $lock -or -not (Test-Path -LiteralPath (Join-Path $parent 'package.json') -PathType Leaf)) {
                    $state = 'Blocked'; $reason = 'No package.json and lockfile next to it, so it could not be rebuilt exactly.'
                } else {
                    $reason = 'rebuild later with npm ci (or your package manager)'
                }
            } else {
                $project = [System.IO.Path]::GetDirectoryName($parent)
                if ([string]::IsNullOrEmpty($project) -or -not (Test-Path -LiteralPath (Join-Path $project 'Cargo.toml') -PathType Leaf)) {
                    $state = 'Blocked'; $reason = 'No Cargo.toml beside the target folder, so this may not be Rust build output.'
                }
            }
        } elseif ($kind -eq 'AppCache') {
            if (-not $script:TriageCacheFolderNames.ContainsKey($leaf)) {
                $state = 'Blocked'; $reason = 'Its name contains "cache" but it is not a plain cache folder; it may hold site or app data.'
            } else {
                $reason = 'close the application first'
            }
        }

        [pscustomobject]@{
            Path      = $path
            Note      = [string]$c.Note
            SizeBytes = [long]$c.TotalBytes
            Files     = [long]$c.Files
            State     = $state
            Reason    = $reason
        }
    }
    return @($plan)
}

function Remove-TriageStore {
    <#
        Asks Windows to put ONE store folder in the Recycle Bin. Everything is
        re-checked here against the disk as it is now, so a stale or edited
        plan item cannot widen what is removed. Returns a record whose
        StillExists field says whether the folder is really gone.
    #>
    param([Parameter(Mandatory)] $Item, [string]$LogDirectory)

    if (-not (Test-TriageInteractive)) { throw 'Refused: there is no interactive desktop, so Windows could not use the Recycle Bin.' }

    $path = [string]$Item.Path
    if ($path -notmatch '^[A-Za-z]:\\[^\\]+\\[^\\]+') { throw "Refused: not a folder at least two levels below a drive root: $path" }
    if ($path.Contains('..') -or $path.EndsWith('\') -or $path.EndsWith('.') -or $path.EndsWith(' ')) { throw "Refused: not a plain folder path: $path" }
    if ([System.IO.Path]::GetFullPath($path) -cne $path) { throw "Refused: not a normalised path: $path" }
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "Refused: the folder no longer exists: $path" }

    $volume = Get-DriveFacts -Letter $path.Substring(0, 1)
    if ($null -eq $volume -or $volume.Type -ne 'Fixed') { throw "Refused: not on a local fixed disk: $path" }
    if (Test-TriageLinkInPath -Path $path) { throw "Refused: the folder is, or is below, a junction or symbolic link: $path" }

    Initialize-TriageRules
    $class = Get-TriageClassification -Path ($path + '\')
    if ($class.Bucket -ne 'Delete' -or -not $script:TriageRecyclableNotes.ContainsKey([string]$class.Note)) {
        throw "Refused: this folder is not one of the stores the tool may remove: $path"
    }
    $parentClass = Get-TriageClassification -Path ([System.IO.Path]::GetDirectoryName($path) + '\')
    if ([object]::ReferenceEquals($parentClass, $class)) { throw "Refused: this is a folder inside a store, not the store itself: $path" }

    # Walk the folder as it is now and apply exactly the plan's conditions to
    # what is found: one store, nothing foreign, personal, linked, unreadable,
    # too long or too large.
    $state = New-TriageScanState
    $script:TriageCancel = $false
    Invoke-TriageWalk -Root $path -MaxDepth 64 -MinBytes 1MB -State $state -OnProgress $null
    $now = $state.Stores[$path]
    if ($state.Cancelled -or $null -eq $now) { throw "Refused: the folder could not be examined: $path" }
    if ($state.Stores.Count -ne 1) { $now.Mixed = $true }
    if ($state.DeniedCount -gt 0 -or $state.DepthLimited -gt 0) { $now.Incomplete = $true }
    $check = @(Get-TriageDeletePlan -Result ([pscustomobject]@{ DeleteCandidates = @($now) }))
    if ($check[0].State -ne 'Ready') { throw "Refused: $($check[0].Reason)" }

    $logTarget = Resolve-ReportDirectory -Requested $LogDirectory
    Initialize-TriageRecycleBin
    $before = Get-TriageSpaceSnapshot -Letter $path.Substring(0, 1)

    $failure = ''
    try {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($path, [Microsoft.VisualBasic.FileIO.UIOption]::AllDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin, [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
    } catch { $failure = $_.Exception.Message }

    # Report what is true on the disk, not what was asked for.
    $still = Test-Path -LiteralPath $path
    if ($still -and (Test-TriageFolderEmpty -Path $path) -eq $false -and $failure -eq '') { $failure = 'Windows did not remove everything (files in use?).' }
    if ($still -and $failure -eq '') { $failure = 'The folder is still there.' }

    $action = 'Recycle'
    if ($still) { $action = 'Recycle (not completed)' }
    $after = Get-TriageSpaceSnapshot -Letter $path.Substring(0, 1)
    $space = Format-TriageSpaceChange -Before $before -After $after
    $record = [pscustomobject]@{
        When        = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        Action      = $action
        Variable    = ''
        OldValue    = $path
        NewValue    = 'Recycle Bin'
        Detail      = ($failure + ' ' + $space).Trim()
        LogPath     = ''
        StillExists = [bool]$still
        SizeBytes   = [long]$check[0].SizeBytes
        Before      = $before
        After       = $after
        Space       = $space
    }
    try { $record.LogPath = Write-TriageActionLog -Record $record -Directory $logTarget } catch { $record.LogPath = '' }
    return $record
}

function Get-TriageMoveTarget {
    # C:\Users\me\Downloads\x.iso  ->  D:\FromC\Users\me\Downloads\x.iso
    param([string]$Source, [string]$Letter)
    return ('{0}:\FromC\{1}' -f $Letter.ToUpper(), $Source.Substring(3))
}

function Test-TriageMovableFile {
    <#
        Returns '' when the tool may move this file, otherwise the reason not.
        Judged from the path alone: a plain data file of a known type, outside
        installed software, application data, hidden tool folders and
        cloud-sync folders.
    #>
    param([string]$Path)
    Initialize-TriageRules

    $where = Test-TriageProtectedLocation -Path $Path
    if ($where -ne '') { return $where }
    if ($Path -match '\\AppData\\')      { return 'It is application data; move it with the owning application.' }
    if ($Path -match '\\\.[^\\]+\\' -or [System.IO.Path]::GetFileName($Path).StartsWith('.')) { return 'It is inside a hidden tool folder (for example .git).' }

    $leafStart = $Path.LastIndexOf('\') + 1
    $dot       = $Path.LastIndexOf('.')
    $extension = ''
    if ($dot -gt $leafStart) { $extension = $Path.Substring($dot).ToLowerInvariant() }
    if (-not $script:TriageExtensionSet.ContainsKey($extension)) { return 'It is not a plain data file type the tool recognises.' }
    if ($script:TriageNeverMoveExtensions.ContainsKey($extension)) { return 'Mail stores must be moved from within Outlook.' }

    $class = Get-TriageClassification -Path $Path
    if ([object]::ReferenceEquals($class, $script:TriageFallbackMove)) { return '' }
    if ($class.Bucket -eq 'Move' -and $script:TriageMovableNotes.ContainsKey([string]$class.Note)) { return '' }
    return 'This file belongs to a program or store; move it with the owning application.'
}

function Test-TriageReparseAbove {
    # True when any existing folder above the path carries a reparse point of
    # ANY kind. Stricter than the link test: it also catches cloud-sync trees.
    param([string]$Path)
    $probe = [System.IO.Path]::GetDirectoryName($Path)
    while (-not [string]::IsNullOrEmpty($probe) -and $probe.Length -gt 3) {
        if (Test-Path -LiteralPath $probe) {
            $info = New-Object System.IO.DirectoryInfo $probe
            if ($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { return $true }
        }
        $probe = [System.IO.Path]::GetDirectoryName($probe)
    }
    return $false
}

function Get-TriageMovePlan {
    <#
        Read-only. Lists the large plain data files the scan found that the
        tool may move, with the place each would go.
    #>
    param([Parameter(Mandatory)] $Result, [string]$DestinationDrive)

    $letter = $DestinationDrive
    if ([string]::IsNullOrWhiteSpace($letter) -and $null -ne $Result.Destination) { $letter = [string]$Result.Destination.Letter }
    $driveProblem = 'The destination drive is not available.'
    $free = [long]0
    if (-not [string]::IsNullOrWhiteSpace($letter)) {
        $driveProblem = Test-TriageRedirectDrive -Letter $letter
        $facts = Get-DriveFacts -Letter $letter
        if ($null -ne $facts) { $free = [long]$facts.FreeBytes }
    }

    $plan = foreach ($f in @($Result.Files)) {
        if ($f.Bucket -ne 'Move') { continue }
        $path = [string]$f.Path
        if ((Test-TriageMovableFile -Path $path) -ne '') { continue }

        $state = 'Ready'; $reason = ''; $target = ''
        if ($driveProblem -ne '') {
            $state = 'Blocked'; $reason = $driveProblem
        } else {
            $target = Get-TriageMoveTarget -Source $path -Letter $letter
            if ($letter.ToUpper() -eq $path.Substring(0, 1).ToUpper()) {
                $state = 'Blocked'; $reason = 'The destination is the drive the file is already on.'
            } elseif ($target.Length -gt 230) {
                $state = 'Blocked'; $reason = 'The new path would be too long for Windows.'
            } elseif ($free -lt ([long]$f.SizeBytes + 1GB)) {
                $state = 'Blocked'; $reason = 'Not enough free space on the destination.'
            } elseif (Test-Path -LiteralPath $target) {
                $state = 'Blocked'; $reason = 'A file with this name is already there. Check it first.'
            } elseif (Test-Path -LiteralPath ($target + '.triage-partial')) {
                $state = 'Blocked'; $reason = 'An earlier move of this file was interrupted. Delete the leftover .triage-partial file on the destination, then scan again.'
            } elseif (Test-TriageReparseAbove -Path $path) {
                $state = 'Blocked'; $reason = 'It is inside a linked or cloud-synced folder.'
            } elseif ([long]$f.SizeBytes -gt (Get-TriageRecycleLimit -Letter $path.Substring(0, 1))) {
                $reason = 'too large for the Recycle Bin: after the verified copy, Windows will ask before removing the original'
            }
        }

        [pscustomobject]@{
            Path      = $path
            SizeBytes = [long]$f.SizeBytes
            Target    = $target
            DaysIdle  = [int]$f.DaysIdle
            State     = $state
            Reason    = $reason
        }
    }
    return @($plan)
}

function Get-TriageFileHash {
    # SHA-256 of a file, read in blocks so progress can be reported and the
    # operation cancelled. Returns $null when cancelled.
    param([string]$Path, [scriptblock]$OnProgress, [string]$Stage)

    $sha    = [System.Security.Cryptography.SHA256]::Create()
    $buffer = New-Object byte[] 4194304
    $done   = [long]0
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $total = $stream.Length
        while ($true) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
            $done += $read
            if ($null -ne $OnProgress) { & $OnProgress $Stage $done $total }
            if ($script:TriageCancel) { return $null }
        }
        [void]$sha.TransformFinalBlock($buffer, 0, 0)
        return [System.BitConverter]::ToString($sha.Hash)
    }
    finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function Move-TriageFile {
    <#
        Moves ONE plain data file. Copy-TriageVerifiedFile writes the copy
        under a temporary name, compares it with the original by SHA-256 and
        only then gives it its final name; after that Windows is asked to put
        the original in the Recycle Bin. Never overwrites. If anything fails
        or the user cancels, the temporary copy is removed and the original is
        untouched.
    #>
    param([Parameter(Mandatory)] $Item, [string]$LogDirectory, [scriptblock]$OnProgress)

    if (-not (Test-TriageInteractive)) { throw 'Refused: there is no interactive desktop, so Windows could not use the Recycle Bin.' }

    $source = [string]$Item.Path
    if ($source -notmatch '^[A-Za-z]:\\') { throw "Refused: not a full local path: $source" }
    if ($source.Contains('..') -or [System.IO.Path]::GetFullPath($source) -cne $source) { throw "Refused: not a normalised path: $source" }
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Refused: the file no longer exists: $source" }

    $problem = Test-TriageMovableFile -Path $source
    if ($problem -ne '') { throw "Refused: $problem" }

    $shown = [string]$Item.Target
    if ($shown -notmatch '^[A-Za-z]:\\FromC\\') { throw "Refused: the new place must be below <drive>:\FromC. Got: $shown" }
    $letter      = $shown.Substring(0, 1)
    $destination = Get-TriageMoveTarget -Source $source -Letter $letter
    if ($shown -cne $destination) { throw "Refused: the new place must be exactly $destination. Got: $shown" }
    if ($letter.ToUpper() -eq $source.Substring(0, 1).ToUpper()) { throw 'Refused: the destination is the drive the file is already on.' }

    $driveProblem = Test-TriageRedirectDrive -Letter $letter
    if ($driveProblem -ne '') { throw "Refused: $driveProblem" }

    $info = Get-Item -LiteralPath $source -Force
    # ReparsePoint, Offline, Recall (cloud placeholders), Pinned / Unpinned
    # (cloud-synced), Encrypted, Hidden, System.
    if (([int]$info.Attributes -band 0x5C5406) -ne 0) { throw 'Refused: the file is a link, cloud-synced, encrypted, hidden or a system file.' }
    if (Test-TriageReparseAbove -Path $source) { throw 'Refused: the file is inside a linked or cloud-synced folder.' }
    $size = [long]$info.Length

    $facts = Get-DriveFacts -Letter $letter
    if ($facts.FreeBytes -lt ($size + 1GB)) { throw 'Refused: not enough free space on the destination.' }
    $partial = $destination + '.triage-partial'
    if (Test-Path -LiteralPath $destination) { throw "Refused: something already exists at $destination. Nothing is ever overwritten." }
    if (Test-Path -LiteralPath $partial)     { throw "Refused: a leftover from an interrupted move exists. Delete it first: $partial" }

    $folder = [System.IO.Path]::GetDirectoryName($destination)
    if (Test-TriageLinkInPath -Path $folder) { throw "Refused: the new place is below a junction or symbolic link: $folder" }

    $logTarget = Resolve-ReportDirectory -Requested $LogDirectory
    Initialize-TriageRecycleBin
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }

    $script:TriageCancel = $false
    $before     = Get-TriageSpaceSnapshot -Letter $source.Substring(0, 1)
    $sourceHash = Copy-TriageVerifiedFile -Source $source -Partial $partial -Destination $destination -Size $size -Stamp $info.LastWriteTimeUtc -BaseBytes 0 -TotalBytes $size -OnProgress $OnProgress

    # The original must be exactly what was copied, or it stays.
    $recheck = Get-Item -LiteralPath $source -Force
    if ($recheck.Length -ne $size -or $recheck.LastWriteTimeUtc -ne $info.LastWriteTimeUtc) {
        throw "The original changed after it was copied, so it was left in place. A verified copy of the earlier contents is at $destination."
    }

    $failure = ''
    try {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($source, [Microsoft.VisualBasic.FileIO.UIOption]::AllDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin, [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
    } catch { $failure = $_.Exception.Message }
    $recycled = -not (Test-Path -LiteralPath $source)

    $action = 'Move'
    if (-not $recycled) { $action = 'Copy (original kept)' }
    $after = Get-TriageSpaceSnapshot -Letter $source.Substring(0, 1)
    $space = Format-TriageSpaceChange -Before $before -After $after
    $record = [pscustomobject]@{
        When     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        Action   = $action
        Variable = ''
        OldValue = $source
        NewValue = $destination
        Detail   = ('SHA256 ' + $sourceHash.Replace('-', '') + ' ' + $failure + ' ' + $space).Replace('  ', ' ').Trim()
        LogPath  = ''
        OriginalRecycled = [bool]$recycled
        Sha256   = $sourceHash.Replace('-', '')
        SizeBytes = $size
        Before   = $before
        After    = $after
        Space    = $space
    }
    try { $record.LogPath = Write-TriageActionLog -Record $record -Directory $logTarget } catch { $record.LogPath = '' }
    return $record
}
#endregion

#region Free space, Recycle Bin and moving a whole store ----------------------
# Why this exists: Delete and Move put originals in the Recycle Bin, and the
# Recycle Bin of a drive is ON that drive. Nothing is freed until it is
# emptied. So every action measures the free space before and after, the
# window always shows what the Recycle Bin holds, and emptying it is an
# explicit, separately confirmed step - the only permanent removal the tool
# can ask Windows for.

function Get-TriageRecycleBinInfo {
    <#
        Read-only. What the current user has in the Recycle Bin of one drive,
        taken from the bin's own index records (one small $I file per item,
        with the item's size at byte 8). Opens none of the user's files.
    #>
    param([string]$Letter)
    $info = [pscustomobject]@{ Letter = $Letter.ToUpper(); Items = 0; Bytes = [long]0; Known = $false }
    try {
        $sid = [string][Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $bin = ('{0}:\$Recycle.Bin\{1}' -f $Letter.ToUpper(), $sid)
        if (-not (Test-Path -LiteralPath $bin -PathType Container)) { $info.Known = $true; return $info }
        $folder = New-Object System.IO.DirectoryInfo $bin
        $buffer = New-Object byte[] 16
        foreach ($entry in $folder.EnumerateFiles('$I*')) {
            $read   = 0
            $stream = [System.IO.File]::OpenRead($entry.FullName)
            try { $read = $stream.Read($buffer, 0, 16) } finally { $stream.Dispose() }
            if ($read -lt 16) { continue }
            $size = [System.BitConverter]::ToInt64($buffer, 8)
            if ($size -lt 0) { continue }
            $info.Items = $info.Items + 1
            $info.Bytes = $info.Bytes + $size
        }
        $info.Known = $true
    } catch { $info.Known = $false }
    return $info
}

function Get-TriageSpaceSnapshot {
    # Free bytes of a drive (the figure Windows reports to the current user)
    # and the contents of its Recycle Bin, at this moment.
    param([string]$Letter)
    $facts = Get-DriveFacts -Letter $Letter
    $bin   = Get-TriageRecycleBinInfo -Letter $Letter
    $free  = [long]-1
    if ($null -ne $facts) { $free = [long]$facts.FreeBytes }
    return [pscustomobject]@{
        Letter    = $Letter.ToUpper()
        FreeBytes = $free
        BinBytes  = [long]$bin.Bytes
        BinItems  = [int]$bin.Items
        BinKnown  = [bool]$bin.Known
    }
}

function Format-TriageSpaceChange {
    # 'C: free 10.00 GB -> 12.10 GB (+2.10 GB). Recycle Bin on C: holds 0 KB.'
    param($Before, $After)
    if ($null -eq $Before -or $null -eq $After -or $Before.FreeBytes -lt 0 -or $After.FreeBytes -lt 0) { return '' }
    $delta = [double]($After.FreeBytes - $Before.FreeBytes)
    $sign  = '+'
    if ($delta -lt 0) { $sign = '-'; $delta = -$delta }
    $text = ('{0}: free {1} -> {2} ({3}{4}).' -f $After.Letter, (Format-Size -Bytes ([double]$Before.FreeBytes)), (Format-Size -Bytes ([double]$After.FreeBytes)), $sign, (Format-Size -Bytes $delta))
    if ($After.BinKnown) {
        $text = $text + (' Recycle Bin on {0}: holds {1}.' -f $After.Letter, (Format-Size -Bytes ([double]$After.BinBytes)))
    }
    return $text
}

function Clear-TriageRecycleBin {
    <#
        The explicit "free the space now" step: asks Windows to empty the
        current user's Recycle Bin on ONE local fixed drive. This is permanent
        and covers everything in that bin, not only what this tool put there;
        the window says so and asks first. Returns a record with the free
        space measured before and after.
    #>
    param([string]$Letter, [string]$LogDirectory)

    if ($Letter -notmatch '^[A-Za-z]$') { throw "Refused: not a drive letter: $Letter" }
    $drive = $Letter.ToUpper()
    $facts = Get-DriveFacts -Letter $drive
    if ($null -eq $facts -or $facts.Type -ne 'Fixed') { throw "Refused: $drive is not a local fixed disk." }

    $before = Get-TriageSpaceSnapshot -Letter $drive
    if (-not $before.BinKnown) { throw "The Recycle Bin on $drive could not be read, so its contents are not known. Empty it from the desktop instead." }
    $logTarget = Resolve-ReportDirectory -Requested $LogDirectory

    $failure = ''
    if ($before.BinItems -gt 0) {
        try { Clear-RecycleBin -DriveLetter $drive -Force -ErrorAction Stop } catch { $failure = $_.Exception.Message }
    }
    $after = Get-TriageSpaceSnapshot -Letter $drive
    $space = Format-TriageSpaceChange -Before $before -After $after

    $action = 'Empty Recycle Bin'
    if ($after.BinItems -gt 0) { $action = 'Empty Recycle Bin (not completed)' }
    $record = [pscustomobject]@{
        When      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        Action    = $action
        Variable  = ''
        OldValue  = ('{0} item(s), {1}' -f $before.BinItems, (Format-Size -Bytes ([double]$before.BinBytes)))
        NewValue  = ('{0} item(s)' -f $after.BinItems)
        Detail    = ($failure + ' ' + $space).Trim()
        LogPath   = ''
        SizeBytes = [long]$before.BinBytes
        Before    = $before
        After     = $after
        Space     = $space
        Failure   = $failure
    }
    try { $record.LogPath = Write-TriageActionLog -Record $record -Directory $logTarget } catch { $record.LogPath = '' }
    return $record
}

function Copy-TriageVerifiedFile {
    <#
        Copies ONE file. The copy is written as a NEW file under a temporary
        name ($Partial), hashed while it is written, read back and compared
        with the original by SHA-256, and only then given its final name
        ($Destination, which must not exist). The original is held open, so
        nothing can change it, until the comparison is done. If anything
        fails or the user cancels, the temporary copy is deleted - the only
        file this script ever deletes permanently besides copies rolled back
        by Undo-TriageStoreCopy. Returns the SHA-256 of the file.
    #>
    param([string]$Source, [string]$Partial, [string]$Destination, [long]$Size, [datetime]$Stamp,
          [long]$BaseBytes, [long]$TotalBytes, [scriptblock]$OnProgress)

    $created    = $false
    $finished   = $false
    $sourceHash = ''
    $in = [System.IO.File]::OpenRead($Source)
    try {
        $sha    = [System.Security.Cryptography.SHA256]::Create()
        $buffer = New-Object byte[] 4194304
        $done   = [long]0
        $out    = New-Object System.IO.FileStream($partial, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $created = $true
        try {
            while ($true) {
                $read = $in.Read($buffer, 0, $buffer.Length)
                if ($read -le 0) { break }
                $out.Write($buffer, 0, $read)
                [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
                $done += $read
                if ($null -ne $OnProgress) { & $OnProgress 'Copying' ($BaseBytes + $done) $TotalBytes }
                if ($script:TriageCancel) { throw 'Cancelled. Nothing was removed.' }
            }
            $out.Flush($true)
        }
        finally { $out.Dispose() }
        [void]$sha.TransformFinalBlock($buffer, 0, 0)
        $sourceHash = [System.BitConverter]::ToString($sha.Hash)
        $sha.Dispose()

        if ($done -ne $Size -or $in.Length -ne $Size) { throw 'The file changed while it was being copied. Nothing was removed.' }
        # One file: show the read-back. Many files: keep the overall figure steady.
        $verifyProgress = $null
        if ($TotalBytes -eq $Size) { $verifyProgress = $OnProgress }
        $copyHash = Get-TriageFileHash -Path $partial -OnProgress $verifyProgress -Stage 'Verifying'
        if ($null -eq $copyHash) { throw 'Cancelled. Nothing was removed.' }
        if ($copyHash -cne $sourceHash) { throw 'The copy does not match the original. Nothing was removed.' }

        [System.IO.File]::SetLastWriteTimeUtc($partial, $Stamp)
        # Only a verified copy ever gets the real name. Move fails if the name is taken.
        [System.IO.File]::Move($partial, $destination)
        $finished = $true
    }
    finally {
        $in.Dispose()
        if ($created -and -not $finished) {
            # Never leave an unverified copy behind.
            try { [System.IO.File]::Delete($partial) } catch { Write-Warning "Could not remove the temporary copy: $partial" }
        }
    }
    return $sourceHash
}

function Get-TriageStoreInventory {
    <#
        Read-only. Every folder and file below a store folder, for copying.
        Throws when the store holds anything the tool will not copy blindly:
        a junction, symbolic link or cloud placeholder, or an entry that
        cannot be read.
    #>
    param([string]$Root)
    $folders = New-Object 'System.Collections.Generic.List[string]'
    $files   = New-Object 'System.Collections.Generic.List[object]'
    $bytes   = [long]0
    $newest  = [long]0
    $queue   = New-Object 'System.Collections.Generic.Queue[object]'
    $queue.Enqueue($Root)
    while ($queue.Count -gt 0) {
        if ($script:TriageCancel) { throw 'Cancelled. Nothing was changed.' }
        $info = New-Object System.IO.DirectoryInfo ([string]$queue.Dequeue())
        foreach ($entry in $info.EnumerateFileSystemInfos()) {
            # ReparsePoint, Offline, RecallOnDataAccess
            if (([int]$entry.Attributes -band 0x401400) -ne 0) { throw "it contains a link or a cloud placeholder ($($entry.FullName))" }
            if ($entry.Attributes -band [System.IO.FileAttributes]::Directory) {
                $folders.Add($entry.FullName)
                $queue.Enqueue($entry.FullName)
            } else {
                $files.Add([pscustomobject]@{ Path = $entry.FullName; Length = [long]$entry.Length; Stamp = $entry.LastWriteTimeUtc })
                $bytes = $bytes + [long]$entry.Length
                if ($entry.LastWriteTimeUtc.Ticks -gt $newest) { $newest = $entry.LastWriteTimeUtc.Ticks }
            }
        }
    }
    return [pscustomobject]@{ Folders = $folders; Files = $files; Bytes = $bytes; Newest = $newest }
}

function Undo-TriageStoreCopy {
    <#
        Rolls back a store copy that did not finish: deletes exactly the
        files the copy created (the caller's list) and then the folders it
        created, deepest first and only if they are empty. Everything must be
        below the one new folder for that store; the original is not touched.
    #>
    param([string]$Root, $Files, $Folders)
    if ($Root -notmatch '^[A-Za-z]:\\FromC\\Users\\[^\\]+\\[^\\]') { return }
    foreach ($created in @($Files)) {
        if (-not ([string]$created).StartsWith($Root + '\', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        try { [System.IO.File]::Delete($created) } catch { Write-Warning "Could not remove the unfinished copy: $created" }
    }
    foreach ($made in @($Folders | Sort-Object -Property Length -Descending)) {
        if (([string]$made) -ne $Root -and -not ([string]$made).StartsWith($Root + '\', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        # One argument: removes the folder only if it is empty.
        try { [System.IO.Directory]::Delete($made) } catch { Write-Verbose "Left in place (not empty): $made" }
    }
}

function Move-TriageStore {
    <#
        Redirect one store AND bring its existing contents along, so the
        space on the source drive really comes back:
          1. every file is copied to the new folder and verified by SHA-256
             (Copy-TriageVerifiedFile); nothing is overwritten;
          2. the old folder is listed again and must be unchanged;
          3. the user variable is set (Set-TriageRedirect), unless this tool
             already set it earlier;
          4. Windows is asked to put the old folder in the Recycle Bin.
        If anything fails before step 3, the copies made so far are removed
        again and nothing else has changed. Everything is re-validated here,
        so a stale or edited plan item cannot widen what happens.
    #>
    param([Parameter(Mandatory)] $Item, [string]$LogDirectory, [scriptblock]$OnProgress)

    if (-not (Test-TriageInteractive)) { throw 'Refused: there is no interactive desktop, so Windows could not use the Recycle Bin.' }

    $target = $script:TriageRedirectTargets | Where-Object { $_.Variable -ceq [string]$Item.Variable }
    if ($null -eq $target) { throw "Not a variable this tool manages: $($Item.Variable)" }

    $shown = [string]$Item.ProposedValue
    if ($shown -notmatch '^[A-Za-z]:\\') { throw "Refused: not a full local path: $shown" }
    $drive = $shown.Substring(0, 1)
    $value = Get-TriageRedirectFolder -Letter $drive -Target $target
    if ($shown -cne $value) { throw "Refused: the new folder must be exactly $value. Got: $shown" }
    $driveProblem = Test-TriageRedirectDrive -Letter $drive
    if ($driveProblem -ne '') { throw "Refused: $driveProblem" }
    if (Test-TriageLinkInPath -Path $value) { throw "Refused: the new folder would sit below a junction or symbolic link: $value" }

    # The old folder is never taken from the caller: it is the store's one usual place.
    $source = Join-Path ([string]$env:USERPROFILE) $target.RelativePath
    if ([string]::IsNullOrEmpty($env:USERPROFILE) -or [System.IO.Path]::GetFullPath($source) -cne $source) { throw 'Refused: your user profile folder could not be determined.' }
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw "Refused: the old folder no longer exists: $source" }
    if ($source.Substring(0, 1).ToUpper() -eq $drive.ToUpper()) { throw 'Refused: the old folder is already on the destination drive.' }
    if (Test-TriageLinkInPath -Path $source) { throw "Refused: the old folder is, or is below, a junction or symbolic link: $source" }
    $sourceFacts = Get-DriveFacts -Letter $source.Substring(0, 1)
    if ($null -eq $sourceFacts -or $sourceFacts.Type -ne 'Fixed') { throw "Refused: not on a local fixed disk: $source" }

    $machine = [string][Environment]::GetEnvironmentVariable($target.Variable, 'Machine')
    if (-not [string]::IsNullOrEmpty($machine)) { throw "Refused: $($target.Variable) is set for the whole computer. Nothing was changed." }
    $current = [string][Environment]::GetEnvironmentVariable($target.Variable, 'User')
    # Merge: the variable already points at the tool's folder (an earlier
    # setting-only redirect), so that folder is in use and may hold files.
    $merge = $false
    if (-not [string]::IsNullOrEmpty($current)) {
        if ($current.TrimEnd('\') -ine $value) { throw "Refused: $($target.Variable) is already set to $current, which is not the folder this tool would use. Nothing was changed." }
        $merge = $true
    } elseif (-not (Test-TriageFolderEmpty -Path $value)) {
        throw "Refused: the new folder already exists and is not empty: $value"
    }

    $script:TriageCancel = $false
    $inventory = $null
    try { $inventory = Get-TriageStoreInventory -Root $source } catch { throw "Refused: the old folder cannot be moved by the tool because $($_.Exception.Message)" }
    foreach ($file in $inventory.Files) {
        if (($value.Length + $file.Path.Length - $source.Length) -gt 240) { throw 'Refused: a path in the new folder would be too long for Windows.' }
    }
    $destFacts = Get-DriveFacts -Letter $drive
    if ($destFacts.FreeBytes -lt ($inventory.Bytes + 1GB)) { throw 'Refused: not enough free space on the destination.' }

    $logTarget = Resolve-ReportDirectory -Requested $LogDirectory
    Initialize-TriageRecycleBin
    $before = Get-TriageSpaceSnapshot -Letter $source.Substring(0, 1)

    $createdFiles   = New-Object 'System.Collections.Generic.List[string]'
    $createdFolders = New-Object 'System.Collections.Generic.List[string]'
    $copied = 0; $same = 0; $kept = 0
    $doneBytes = [long]0
    $ok = $false
    try {
        $wanted = New-Object 'System.Collections.Generic.List[string]'
        $wanted.Add($value)
        foreach ($sub in $inventory.Folders) { $wanted.Add($value + ([string]$sub).Substring($source.Length)) }
        foreach ($folder in $wanted) {
            if (Test-Path -LiteralPath $folder -PathType Leaf) { throw "A file is in the way of a folder: $folder" }
            if (Test-Path -LiteralPath $folder) {
                if ((Get-Item -LiteralPath $folder -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "A link is in the way in the new folder: $folder" }
                continue
            }
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
            $createdFolders.Add($folder)
        }

        foreach ($file in $inventory.Files) {
            if ($script:TriageCancel) { throw 'Cancelled. Nothing was removed.' }
            $destination = $value + $file.Path.Substring($source.Length)
            if (Test-Path -LiteralPath $destination) {
                # Possible only when merging into a folder that is already in use.
                $hashOld = Get-TriageFileHash -Path $file.Path -OnProgress $null -Stage ''
                $hashNew = Get-TriageFileHash -Path $destination -OnProgress $null -Stage ''
                if ($null -eq $hashOld -or $null -eq $hashNew) { throw 'Cancelled. Nothing was removed.' }
                if ($hashOld -ceq $hashNew) { $same = $same + 1 }
                elseif ($script:TriagePureCaches.ContainsKey($target.Variable)) { $kept = $kept + 1 }
                else { throw "The old and the new folder both hold '$($file.Path.Substring($source.Length + 1))' with different contents. Nothing was removed; decide which one to keep, then try again." }
            } else {
                $partial = $destination + '.triage-partial'
                if (Test-Path -LiteralPath $partial) { throw "A leftover from an interrupted copy exists. Delete it first: $partial" }
                [void](Copy-TriageVerifiedFile -Source $file.Path -Partial $partial -Destination $destination -Size $file.Length -Stamp $file.Stamp -BaseBytes $doneBytes -TotalBytes $inventory.Bytes -OnProgress $OnProgress)
                $createdFiles.Add($destination)
                $copied = $copied + 1
            }
            $doneBytes = $doneBytes + $file.Length
        }

        # The old folder must still be exactly what was copied.
        $again = Get-TriageStoreInventory -Root $source
        if ($again.Files.Count -ne $inventory.Files.Count -or $again.Bytes -ne $inventory.Bytes -or $again.Newest -ne $inventory.Newest) {
            throw 'The old folder changed while it was being copied. Close the application that uses it, then try again. Nothing was removed.'
        }

        if (-not $merge) { [void](Set-TriageRedirect -Item $Item -LogDirectory $logTarget -Populated) }
        $ok = $true
    }
    finally {
        # A fresh copy that did not finish is taken away again. When merging,
        # verified additions to a folder already in use are left: they are
        # complete files and a second run skips them.
        if (-not $ok -and -not $merge) { Undo-TriageStoreCopy -Root $value -Files $createdFiles -Folders $createdFolders }
    }

    $failure = ''
    try {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($source, [Microsoft.VisualBasic.FileIO.UIOption]::AllDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin, [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
    } catch { $failure = $_.Exception.Message }
    $recycled = -not (Test-Path -LiteralPath $source)

    $after  = Get-TriageSpaceSnapshot -Letter $source.Substring(0, 1)
    $space  = Format-TriageSpaceChange -Before $before -After $after
    $action = 'Move store'
    if (-not $recycled) { $action = 'Move store (old folder kept)' }
    $counts = ('{0} file(s) copied and verified, {1} already there, {2} kept as found in the new folder.' -f $copied, $same, $kept)
    $record = [pscustomobject]@{
        When     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        Action   = $action
        Variable = $target.Variable
        OldValue = $source
        NewValue = $value
        Detail   = ($counts + ' ' + $failure + ' ' + $space).Replace('  ', ' ').Trim()
        LogPath  = ''
        OriginalRecycled = [bool]$recycled
        Copied   = $copied
        Same     = $same
        Kept     = $kept
        SizeBytes = [long]$inventory.Bytes
        Before   = $before
        After    = $after
        Space    = $space
    }
    try { $record.LogPath = Write-TriageActionLog -Record $record -Directory $logTarget } catch { $record.LogPath = '' }
    return $record
}

function Get-TriageSessionSummary {
    <#
        Plain text for sharing or for a bug report: what was done in this
        session and what it did to the free space. Contains sizes and counts
        only - no file names, folder names, user name or computer name.
    #>
    param($Start, $Now, $Records)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Disk Space Triage ' + $script:TriageVersion + ' - session summary (no paths or names)')
    $lines.Add('Windows: ' + [string][Environment]::OSVersion.Version)
    if ($null -ne $Start -and $null -ne $Now -and $Start.FreeBytes -ge 0 -and $Now.FreeBytes -ge 0) {
        $lines.Add(('Drive {0}: free at start {1}, free now {2}' -f $Now.Letter, (Format-Size -Bytes ([double]$Start.FreeBytes)), (Format-Size -Bytes ([double]$Now.FreeBytes))))
        $lines.Add(('Recycle Bin on {0}: now {1} in {2} item(s) - not free until emptied' -f $Now.Letter, (Format-Size -Bytes ([double]$Now.BinBytes)), $Now.BinItems))
    }
    $n = 0
    foreach ($r in @($Records)) {
        $n = $n + 1
        $free = ''
        if ($null -ne $r.Before -and $null -ne $r.After) {
            $free = (' | free {0} -> {1}' -f (Format-Size -Bytes ([double]$r.Before.FreeBytes)), (Format-Size -Bytes ([double]$r.After.FreeBytes)))
        }
        $lines.Add(('{0}. {1} | {2}{3}' -f $n, [string]$r.Action, (Format-Size -Bytes ([double]$r.SizeBytes)), $free))
    }
    if ($n -eq 0) { $lines.Add('No action was carried out in this session.') }
    return ($lines -join "`r`n")
}
#endregion

#region HTML report -----------------------------------------------------------

function ConvertTo-TriageHtml {
    param([Parameter(Mandatory)] $Result)

    $template = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Disk space triage</title>
<style>
:root {
  color-scheme: light;
  --bg: #f4f4f1;
  --surface: #fcfcfb;
  --surface-2: #f0efeb;
  --ink: #161615;
  --ink-2: #52514e;
  --ink-3: #6f6e69;
  --rule: #dddcd6;
  --track: #e6e5df;
  --focus: #1c5cab;
  --b-Redirect: #2a78d6;
  --b-Delete: #eb6834;
  --b-Move: #1baf7a;
  --b-Review: #eda100;
  --b-Never: #e87ba4;
  --warn-bg: #fff4d6;
  --warn-ink: #5c4300;
  --st-CRITICAL: #b3261e;
  --st-LOW: #a8470f;
  --st-WARNING: #7a5a00;
  --st-HEALTHY: #1b6b3a;
  --st-UNKNOWN: #52514e;
  --mono: ui-monospace, "Cascadia Mono", Consolas, "SF Mono", Menlo, "Liberation Mono", monospace;
  --sans: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg: #121211;
    --surface: #1a1a19;
    --surface-2: #232321;
    --ink: #f0efec;
    --ink-2: #c3c2b7;
    --ink-3: #a09f96;
    --rule: #34332f;
    --track: #2e2d2a;
    --focus: #86b6ef;
    --b-Redirect: #3987e5;
    --b-Delete: #d95926;
    --b-Move: #199e70;
    --b-Review: #c98500;
    --b-Never: #d55181;
    --warn-bg: #3a2f10;
    --warn-ink: #f3dca0;
    --st-CRITICAL: #ff8a80;
    --st-LOW: #ffa56b;
    --st-WARNING: #f0c24a;
    --st-HEALTHY: #6fd196;
    --st-UNKNOWN: #c3c2b7;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font-family: var(--sans); font-size: 15px; line-height: 1.5;
  font-variant-numeric: tabular-nums;
}
.page { max-width: 1040px; margin: 0 auto; padding: 32px 20px 56px; }
h1 { font-size: 28px; line-height: 1.15; margin: 0 0 6px; font-weight: 650; letter-spacing: -0.01em; }
h2 { font-size: 18px; margin: 0 0 4px; font-weight: 650; }
.sub { color: var(--ink-2); margin: 0 0 14px; max-width: 70ch; font-size: 14px; }
.meta { display: flex; flex-wrap: wrap; gap: 4px 22px; color: var(--ink-2); font-size: 14px; margin: 0 0 10px; }
.meta b { color: var(--ink); font-weight: 600; }
.readonly { display: inline-block; margin: 4px 0 0; padding: 6px 12px; border: 1px solid var(--rule); border-left: 4px solid var(--b-Move); background: var(--surface); border-radius: 4px; font-size: 14px; }
.notice { margin: 16px 0 0; padding: 12px 14px; background: var(--warn-bg); color: var(--warn-ink); border: 1px solid var(--b-Review); border-left-width: 6px; border-radius: 4px; font-weight: 600; }
section { margin-top: 36px; }
.panel { background: var(--surface); border: 1px solid var(--rule); border-radius: 8px; padding: 18px 20px; }
.drives { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }
.drive-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.drive-name { font-weight: 650; font-size: 16px; }
.drive-name small { font-weight: 400; color: var(--ink-3); font-size: 13px; margin-left: 6px; }
.badge { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; font-weight: 700; letter-spacing: .02em; padding: 2px 9px; border: 1.5px solid currentColor; border-radius: 999px; }
.cap { display: flex; height: 18px; border-radius: 4px; overflow: hidden; background: var(--track); gap: 2px; }
.cap .used { background: var(--ink-2); }
.cap .free { background: var(--b-Move); }
.cap-legend { display: flex; justify-content: space-between; gap: 10px; flex-wrap: wrap; font-size: 13.5px; margin-top: 8px; color: var(--ink-2); }
.cap-legend b { color: var(--ink); }
.sw { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: baseline; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; }
.tile { background: var(--surface); border: 1px solid var(--rule); border-top: 5px solid var(--c); border-radius: 8px; padding: 14px 18px 16px; }
.tile .k { font-weight: 650; font-size: 15px; display: flex; align-items: center; gap: 8px; }
.tile .big { font-size: 34px; font-weight: 650; letter-spacing: -0.02em; line-height: 1.1; margin: 6px 0 2px; }
.tile .files { color: var(--ink-2); font-size: 13.5px; }
.tile .mean { margin: 8px 0 0; font-size: 14px; color: var(--ink); }
.stack { display: flex; height: 30px; gap: 2px; margin-top: 18px; }
.stack .seg { background: var(--c); border-radius: 3px; min-width: 3px; }
.legend { list-style: none; padding: 0; margin: 12px 0 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px 16px; }
.legend li { font-size: 13.5px; color: var(--ink-2); }
.legend li b { color: var(--ink); font-weight: 650; }
.legend .sw { background: var(--c); }
.legend .sub2 { display: block; padding-left: 16px; font-size: 12.5px; color: var(--ink-3); }
.tag { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 650; color: var(--ink); background: var(--surface-2); border: 1px solid var(--rule); border-radius: 4px; padding: 0 7px; line-height: 20px; white-space: nowrap; }
.tag::before { content: ""; width: 9px; height: 9px; border-radius: 2px; background: var(--c); }
.rank { list-style: none; padding: 0; margin: 14px 0 0; }
.row { display: grid; grid-template-columns: 26px minmax(0, 1fr) 90px; gap: 2px 12px; align-items: center; padding: 9px 0; border-top: 1px solid var(--rule); }
.row:first-child { border-top: 0; }
.row .n { color: var(--ink-3); font-size: 13px; text-align: right; }
.row .lbl { min-width: 0; }
.row .lbl .t { font-weight: 650; overflow-wrap: anywhere; }
.row .lbl .s { color: var(--ink-2); font-size: 13px; overflow-wrap: anywhere; }
.row .val { text-align: right; font-weight: 650; }
.row .val small { display: block; font-weight: 400; color: var(--ink-3); font-size: 12px; }
.row .barcell { grid-column: 2 / 4; display: flex; align-items: center; gap: 10px; }
.bar { flex: 1; height: 12px; background: var(--track); border-radius: 0 6px 6px 0; }
.bar i { display: block; height: 100%; background: var(--c); border-radius: 0 4px 4px 0; min-width: 2px; }
.folder .lbl .t { font-family: var(--mono); font-size: 13px; font-weight: 500; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 12px 0; }
.chip { font: inherit; font-size: 13.5px; color: var(--ink); background: var(--surface); border: 1px solid var(--rule); border-radius: 999px; padding: 4px 12px; cursor: pointer; }
.chip[aria-pressed="true"] { background: var(--ink); color: var(--surface); border-color: var(--ink); }
.chip .c { color: inherit; opacity: .75; margin-left: 4px; }
input[type="search"] { font: inherit; font-size: 14px; color: var(--ink); background: var(--surface); border: 1px solid var(--rule); border-radius: 6px; padding: 6px 10px; min-width: 220px; flex: 1 1 220px; max-width: 360px; }
button:focus-visible, input:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
.tablewrap { overflow-x: auto; border: 1px solid var(--rule); border-radius: 8px; background: var(--surface); }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--rule); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
th { background: var(--surface-2); font-weight: 650; white-space: nowrap; }
th button { font: inherit; font-weight: 650; color: inherit; background: none; border: 0; padding: 0; cursor: pointer; }
td.num, th.num { text-align: right; white-space: nowrap; }
td.path { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; min-width: 320px; }
td .note { display: block; color: var(--ink-2); font-size: 12.5px; }
.empty { padding: 18px; color: var(--ink-2); }
.count { color: var(--ink-3); font-size: 13px; margin: 8px 0 0; }
.checklist { display: grid; grid-template-columns: minmax(150px, 1fr) 2fr; margin: 12px 0 0; border: 1px solid var(--rule); border-radius: 8px; background: var(--surface); }
.checklist dt, .checklist dd { margin: 0; padding: 10px 14px; border-top: 1px solid var(--rule); }
.checklist dt { font-weight: 650; font-family: var(--mono); font-size: 13.5px; overflow-wrap: anywhere; }
.checklist dt:first-of-type, .checklist dt:first-of-type + dd { border-top: 0; }
.checklist dd { color: var(--ink-2); }
footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--rule); color: var(--ink-2); font-size: 13px; }
footer p { margin: 4px 0; }
footer .roots { display: flex; flex-wrap: wrap; gap: 4px 14px; margin: 4px 0 8px; }
footer code { font-family: var(--mono); font-size: 12.5px; color: var(--ink); overflow-wrap: anywhere; }
@media (max-width: 560px) {
  .page { padding: 20px 14px 40px; }
  h1 { font-size: 23px; }
  .row { grid-template-columns: 22px minmax(0, 1fr) 76px; gap: 2px 8px; }
  .panel { padding: 14px; }
  .tile .big { font-size: 28px; }
  .checklist { grid-template-columns: 1fr; }
  .checklist dd { border-top: 0; padding-top: 0; }
}
@media print {
  :root { color-scheme: light; --bg: #fff; --surface: #fff; --surface-2: #f0efeb; --ink: #000; --ink-2: #333; --ink-3: #555; --rule: #bbb; --track: #e6e5df;
    --b-Redirect: #2a78d6; --b-Delete: #eb6834; --b-Move: #1baf7a; --b-Review: #eda100; --b-Never: #e87ba4;
    --st-CRITICAL: #b3261e; --st-LOW: #a8470f; --st-WARNING: #7a5a00; --st-HEALTHY: #1b6b3a; --st-UNKNOWN: #52514e; --warn-bg: #fff4d6; --warn-ink: #5c4300; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { font-size: 11pt; }
  .page { max-width: none; padding: 0; }
  section { break-inside: avoid-page; margin-top: 22px; }
  .row, .tile, .panel { break-inside: avoid; }
  .toolbar { display: none; }
  .tablewrap { overflow: visible; }
  td.path { min-width: 0; }
  tr { break-inside: avoid; }
}
</style>
</head>
<body>
<div class="page" id="app">
  <noscript><p>This report needs JavaScript enabled to display its data.</p></noscript>
</div>
<script id="triage-data" type="application/json">__TRIAGE_DATA__</script>
<script>
(function () {
  'use strict';
  var R = JSON.parse(document.getElementById('triage-data').textContent);
  var app = document.getElementById('app');
  var BUCKETS = ['Redirect', 'Delete', 'Move', 'Review', 'Never'];

  function asArray(x) {
    if (x === null || x === undefined) { return []; }
    return Array.isArray(x) ? x : [x];
  }
  function num(x) { var n = Number(x); return isFinite(n) ? n : 0; }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }
  function add(parent) {
    for (var i = 1; i < arguments.length; i++) { parent.appendChild(arguments[i]); }
    return parent;
  }
  function setColor(node, bucket) { node.style.setProperty('--c', 'var(--b-' + bucket + ')'); return node; }
  function fmtSize(bytes) {
    var b = num(bytes);
    var units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    var i = 0;
    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
    if (i === 0) { return Math.round(b) + ' B'; }
    return (b >= 100 ? b.toFixed(0) : b.toFixed(1)) + ' ' + units[i];
  }
  function fmtInt(n) { return num(n).toLocaleString('en-US'); }
  function pct(a, b) { return b > 0 ? (a / b * 100) : 0; }
  function fmtPct(p) { return (p > 0 && p < 0.1 ? '<0.1' : p.toFixed(1)) + '%'; }
  function midTrunc(s, max) {
    s = String(s);
    if (s.length <= max) { return s; }
    var keep = max - 3;
    var head = Math.ceil(keep * 0.4), tail = keep - head;
    return s.slice(0, head) + '\u2026' + s.slice(s.length - tail);
  }
  function section(title, sub, id) {
    var s = el('section');
    if (id) { s.id = id; }
    s.appendChild(el('h2', null, title));
    if (sub) { s.appendChild(el('p', 'sub', sub)); }
    return s;
  }
  function tagFor(bucket) {
    return setColor(el('span', 'tag', bucket), bucket);
  }

  var buckets = asArray(R.Buckets);
  var byBucket = {};
  BUCKETS.forEach(function (b) { byBucket[b] = { Bucket: b, Files: 0, TotalBytes: 0 }; });
  buckets.forEach(function (b) { if (b && byBucket[b.Bucket]) { byBucket[b.Bucket] = b; } });
  var mechanisms = asArray(R.Mechanisms);
  var folders = asArray(R.Folders);
  var files = asArray(R.Files);
  var roots = asArray(R.Roots);
  var checklist = asArray(R.ElevatedChecklist);

  document.title = 'Disk space triage - drive ' + (R.Source ? R.Source.Letter : '') + ':';

  /* a. Header */
  var header = el('header');
  header.appendChild(el('h1', null, 'Disk space triage - drive ' + (R.Source ? R.Source.Letter : '?') + ':'));
  var meta = el('div', 'meta');
  [['Generated', R.GeneratedAt], ['User', R.UserName], ['Computer', R.ComputerName]].forEach(function (p) {
    var d = el('span');
    add(d, el('span', null, p[0] + ': '), el('b', null, p[1]));
    meta.appendChild(d);
  });
  header.appendChild(meta);
  header.appendChild(el('p', 'readonly', 'Read-only scan. Nothing was moved, deleted or changed.'));
  if (R.Cancelled === true) {
    var n = el('div', 'notice', 'Scan was cancelled - results are partial');
    n.setAttribute('role', 'alert');
    header.appendChild(n);
  }
  app.appendChild(header);

  /* b. Drive status */
  var STATUS_GLYPH = { CRITICAL: '\u25B2', LOW: '\u25BC', WARNING: '\u25C6', HEALTHY: '\u2713', UNKNOWN: '?' };
  function driveCard(d, role, status) {
    var card = el('div', 'panel');
    var head = el('div', 'drive-head');
    var name = el('div', 'drive-name', role + ': ' + d.Letter + ':');
    name.appendChild(el('small', null, [d.Label, d.Format, d.Type].filter(Boolean).join(' / ')));
    head.appendChild(name);
    if (status) {
      var st = String(status).toUpperCase();
      var badge = el('span', 'badge', (STATUS_GLYPH[st] || '?') + ' ' + st);
      badge.style.color = 'var(--st-' + (STATUS_GLYPH[st] ? st : 'UNKNOWN') + ')';
      badge.setAttribute('title', 'Status of the source drive: ' + st);
      head.appendChild(badge);
    }
    card.appendChild(head);
    var total = num(d.TotalBytes), used = num(d.UsedBytes), free = num(d.FreeBytes);
    var cap = el('div', 'cap');
    cap.setAttribute('role', 'img');
    cap.setAttribute('aria-label', fmtSize(used) + ' used, ' + fmtSize(free) + ' free of ' + fmtSize(total));
    var u = el('div', 'used'); u.style.width = pct(used, total) + '%';
    var f = el('div', 'free'); f.style.width = pct(free, total) + '%';
    add(cap, u, f);
    card.appendChild(cap);
    var lg = el('div', 'cap-legend');
    var l1 = el('span'); add(l1, el('span', 'sw'), el('b', null, fmtSize(used)), el('span', null, ' used'));
    l1.firstChild.style.background = 'var(--ink-2)';
    var l2 = el('span'); add(l2, el('span', 'sw'), el('b', null, fmtSize(free)), el('span', null, ' free (' + num(d.PercentFree).toFixed(1) + '%)'));
    l2.firstChild.style.background = 'var(--b-Move)';
    var l3 = el('span', null, 'Total ' + fmtSize(total));
    add(lg, l1, l2, l3);
    card.appendChild(lg);
    return card;
  }
  var ds = section('Drive status', null, 'drives');
  var dgrid = el('div', 'drives');
  dgrid.style.marginTop = '12px';
  if (R.Source) { dgrid.appendChild(driveCard(R.Source, 'Source', R.Status)); }
  if (R.Destination) { dgrid.appendChild(driveCard(R.Destination, 'Destination', null)); }
  ds.appendChild(dgrid);
  app.appendChild(ds);

  /* c. Headline */
  var hs = section('What is taking the space', 'Scanned ' + fmtSize(R.ScannedBytes) + ' in ' + fmtInt(R.ScannedFiles) + ' files.', 'headline');
  var tiles = el('div', 'tiles');
  var MEANING = {
    Redirect: 'Change one setting; stops growing on C: permanently',
    Delete: 'Regenerates; never copy it',
    Move: 'Copy, verify, then delete the original'
  };
  ['Redirect', 'Delete', 'Move'].forEach(function (b) {
    var t = setColor(el('div', 'tile'), b);
    var k = el('div', 'k'); k.appendChild(el('span', null, b));
    add(t, k, el('div', 'big', fmtSize(byBucket[b].TotalBytes)), el('div', 'files', fmtInt(byBucket[b].Files) + ' files'), el('p', 'mean', MEANING[b]));
    tiles.appendChild(t);
  });
  hs.appendChild(tiles);
  var sum = 0;
  BUCKETS.forEach(function (b) { sum += num(byBucket[b].TotalBytes); });
  var stack = el('div', 'stack');
  stack.setAttribute('role', 'img');
  stack.setAttribute('aria-label', 'Scanned space by bucket: ' + BUCKETS.map(function (b) { return b + ' ' + fmtSize(byBucket[b].TotalBytes); }).join(', '));
  var legend = el('ul', 'legend');
  BUCKETS.forEach(function (b) {
    var v = num(byBucket[b].TotalBytes);
    if (v > 0) {
      var seg = setColor(el('div', 'seg'), b);
      seg.style.flexGrow = String(v); seg.style.flexBasis = '0';
      seg.setAttribute('title', b + ': ' + fmtSize(v) + ' (' + fmtPct(pct(v, sum)) + ')');
      stack.appendChild(seg);
    }
    var li = setColor(el('li'), b);
    li.appendChild(el('span', 'sw'));
    add(li, el('b', null, b + ' '), el('span', null, fmtSize(v) + ' (' + fmtPct(pct(v, sum)) + ')'));
    li.appendChild(el('span', 'sub2', fmtInt(byBucket[b].Files) + ' files'));
    legend.appendChild(li);
  });
  hs.appendChild(stack);
  hs.appendChild(legend);
  app.appendChild(hs);

  /* d. Do these first */
  var ms = section('Do these first', 'The settings and actions that free the most space on C:, largest first. Redirect rows fix it permanently with one setting.', 'first');
  var mlist = el('ol', 'rank');
  var mtop = mechanisms.slice().sort(function (a, b) { return num(b.TotalBytes) - num(a.TotalBytes); }).slice(0, 12);
  var mmax = mtop.length ? num(mtop[0].TotalBytes) : 0;
  if (!mtop.length) { ms.appendChild(el('p', 'empty', 'No redirect, delete or move candidates were found.')); }
  mtop.forEach(function (m, i) {
    var li = setColor(el('li', 'row'), m.Bucket);
    li.setAttribute('title', m.Mechanism + ' - ' + (m.Note || '') + ' - ' + fmtSize(m.TotalBytes) + ', ' + fmtInt(m.Files) + ' files');
    var lbl = el('div', 'lbl');
    var t = el('div', 't'); t.appendChild(el('span', null, m.Mechanism + ' ')); t.appendChild(tagFor(m.Bucket));
    add(lbl, t, el('div', 's', m.Note || ''));
    var val = el('div', 'val', fmtSize(m.TotalBytes)); val.appendChild(el('small', null, fmtInt(m.Files) + ' files'));
    var bc = el('div', 'barcell'); var bar = el('div', 'bar'); var fill = el('i');
    fill.style.width = pct(num(m.TotalBytes), mmax) + '%';
    bar.appendChild(fill); bc.appendChild(bar);
    add(li, el('div', 'n', i + 1), lbl, val, bc);
    mlist.appendChild(li);
  });
  ms.appendChild(mlist);
  app.appendChild(ms);

  /* e. Largest folders */
  var fs = section('Largest folders', 'Top folders by total size. Hover a path to see it in full.', 'folders');
  var flist = el('ol', 'rank');
  var ftop = folders.slice().sort(function (a, b) { return num(b.TotalBytes) - num(a.TotalBytes); }).slice(0, 15);
  var fmax = ftop.length ? num(ftop[0].TotalBytes) : 0;
  if (!ftop.length) { fs.appendChild(el('p', 'empty', 'No folders to show.')); }
  ftop.forEach(function (f, i) {
    var li = el('li', 'row folder');
    li.style.setProperty('--c', 'var(--ink-2)');
    var lbl = el('div', 'lbl');
    var t = el('div', 't', midTrunc(f.Folder, 64));
    t.setAttribute('title', f.Folder);
    lbl.appendChild(t);
    var bc = el('div', 'barcell'); var bar = el('div', 'bar'); var fill = el('i');
    fill.style.width = pct(num(f.TotalBytes), fmax) + '%';
    bar.appendChild(fill); bc.appendChild(bar);
    add(li, el('div', 'n', i + 1), lbl, el('div', 'val', fmtSize(f.TotalBytes)), bc);
    flist.appendChild(li);
  });
  fs.appendChild(flist);
  app.appendChild(fs);

  /* f. Largest files */
  var ts = section('Largest files', 'Files of at least ' + fmtInt(R.MinSizeMB) + ' MB, largest first. Sort by size or idle days; filter by bucket or text.', 'files');
  var state = { bucket: 'All', text: '', key: 'SizeBytes', dir: -1 };
  var toolbar = el('div', 'toolbar');
  toolbar.setAttribute('role', 'group');
  toolbar.setAttribute('aria-label', 'Filter files by bucket');
  var chips = {};
  ['All'].concat(BUCKETS).forEach(function (b) {
    var c = b === 'All' ? files.length : files.filter(function (f) { return f.Bucket === b; }).length;
    var btn = el('button', 'chip'); btn.type = 'button';
    btn.appendChild(el('span', null, b)); btn.appendChild(el('span', 'c', '(' + c + ')'));
    btn.setAttribute('aria-pressed', b === 'All' ? 'true' : 'false');
    btn.addEventListener('click', function () { state.bucket = b; render(); });
    chips[b] = btn; toolbar.appendChild(btn);
  });
  var search = el('input'); search.type = 'search'; search.placeholder = 'Filter by path or action';
  search.setAttribute('aria-label', 'Filter files by path or action');
  search.addEventListener('input', function () { state.text = search.value.toLowerCase(); render(); });
  toolbar.appendChild(search);
  ts.appendChild(toolbar);
  var wrap = el('div', 'tablewrap');
  wrap.setAttribute('tabindex', '0');
  wrap.setAttribute('role', 'region');
  wrap.setAttribute('aria-label', 'Largest files table');
  var table = el('table');
  var thead = el('thead'); var hr = el('tr');
  var heads = [['Size', 'SizeBytes', 'num'], ['Bucket'], ['What to do'], ['Idle days', 'DaysIdle', 'num'], ['Path']];
  var sortBtns = {};
  heads.forEach(function (h) {
    var th = el('th', h[2] || '');
    th.setAttribute('scope', 'col');
    if (h[1]) {
      var b = el('button', null, h[0]); b.type = 'button';
      b.addEventListener('click', function () {
        if (state.key === h[1]) { state.dir = -state.dir; } else { state.key = h[1]; state.dir = -1; }
        render();
      });
      th.appendChild(b); sortBtns[h[1]] = th;
    } else { th.textContent = h[0]; }
    hr.appendChild(th);
  });
  thead.appendChild(hr);
  var tbody = el('tbody');
  add(table, thead, tbody);
  wrap.appendChild(table);
  ts.appendChild(wrap);
  var countP = el('p', 'count');
  ts.appendChild(countP);
  function render() {
    BUCKETS.concat(['All']).forEach(function (b) { chips[b].setAttribute('aria-pressed', state.bucket === b ? 'true' : 'false'); });
    Object.keys(sortBtns).forEach(function (k) {
      var th = sortBtns[k];
      var on = state.key === k;
      th.setAttribute('aria-sort', on ? (state.dir < 0 ? 'descending' : 'ascending') : 'none');
      var btn = th.firstChild;
      btn.textContent = (k === 'SizeBytes' ? 'Size' : 'Idle days') + (on ? (state.dir < 0 ? ' \u25BC' : ' \u25B2') : '');
    });
    var rows = files.filter(function (f) {
      if (state.bucket !== 'All' && f.Bucket !== state.bucket) { return false; }
      if (state.text) {
        var hay = (String(f.Path) + ' ' + String(f.Mechanism) + ' ' + String(f.Note)).toLowerCase();
        if (hay.indexOf(state.text) < 0) { return false; }
      }
      return true;
    }).sort(function (a, b) { return (num(a[state.key]) - num(b[state.key])) * state.dir; });
    while (tbody.firstChild) { tbody.removeChild(tbody.firstChild); }
    if (!rows.length) {
      var tr0 = el('tr'); var td0 = el('td', 'empty', 'No files match this filter.'); td0.colSpan = 5;
      tr0.appendChild(td0); tbody.appendChild(tr0);
    }
    rows.forEach(function (f) {
      var tr = el('tr');
      var tdm = el('td'); tdm.appendChild(document.createTextNode(f.Mechanism || ''));
      if (f.Note) { tdm.appendChild(el('span', 'note', f.Note)); }
      var tdb = el('td'); tdb.appendChild(tagFor(f.Bucket));
      var tdp = el('td', 'path', f.Path); tdp.setAttribute('title', f.Path);
      add(tr, el('td', 'num', fmtSize(f.SizeBytes)), tdb, tdm, el('td', 'num', fmtInt(f.DaysIdle)), tdp);
      tbody.appendChild(tr);
    });
    countP.textContent = 'Showing ' + rows.length + ' of ' + files.length + ' listed files.';
  }
  render();
  if (!files.length) { wrap.style.display = 'none'; toolbar.style.display = 'none'; countP.textContent = 'No files at or above the size threshold.'; }
  app.appendChild(ts);

  /* g. Elevated checklist */
  var es = section('Not measured here - requires administrator', 'These are often large. This scan does not read them; check each yourself.', 'elevated');
  if (!checklist.length) { es.appendChild(el('p', 'empty', 'Nothing listed.')); }
  else {
    var dl = el('dl', 'checklist');
    checklist.forEach(function (c) { add(dl, el('dt', null, c.Item), el('dd', null, c.Action)); });
    es.appendChild(dl);
  }
  app.appendChild(es);

  /* h. Footer */
  var foot = el('footer');
  foot.appendChild(el('p', null, 'Roots scanned:'));
  var rl = el('div', 'roots');
  roots.forEach(function (r) { rl.appendChild(el('code', null, r)); });
  if (!roots.length) { rl.appendChild(el('span', null, 'none')); }
  foot.appendChild(rl);
  foot.appendChild(el('p', null, 'Unreadable locations skipped: ' + fmtInt(R.DeniedCount) + ' (no privilege escalation attempted).'));
  foot.appendChild(el('p', null, 'Junctions and symbolic links not followed: ' + fmtInt(R.LinkFoldersSkipped || 0) + '. Folders beyond the depth limit, not scanned: ' + fmtInt(R.DepthLimitedFolders || 0) + '.'));
  foot.appendChild(el('p', null, 'Minimum file size listed: ' + fmtInt(R.MinSizeMB) + ' MB.'));
  foot.appendChild(el('p', null, 'Disk space triage tool, version ' + R.ToolVersion + '.'));
  app.appendChild(foot);
})();
</script>
</body>
</html>
'@

    $json = $Result | ConvertTo-Json -Depth 6 -Compress
    $json = $json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
    return $template.Replace('__TRIAGE_DATA__', $json)
}
#endregion

#region Window ----------------------------------------------------------------

$script:TriageXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Disk Space Triage"
        Width="1100" Height="700" MinWidth="960" MinHeight="600"
        WindowStartupLocation="CenterScreen"
        Background="@Bg@" Foreground="@Ink@"
        FontFamily="Segoe UI Variable Text, Segoe UI" FontSize="13"
        TextOptions.TextFormattingMode="Display"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <SolidColorBrush x:Key="BgBrush" Color="@Bg@"/>
    <SolidColorBrush x:Key="SurfaceBrush" Color="@Surface@"/>
    <SolidColorBrush x:Key="SubtleBrush" Color="@Subtle@"/>
    <SolidColorBrush x:Key="InkBrush" Color="@Ink@"/>
    <SolidColorBrush x:Key="MutedBrush" Color="@Muted@"/>
    <SolidColorBrush x:Key="LineBrush" Color="@Line@"/>
    <SolidColorBrush x:Key="ControlBrush" Color="@Control@"/>
    <SolidColorBrush x:Key="ControlLineBrush" Color="@ControlLine@"/>
    <SolidColorBrush x:Key="HoverBrush" Color="@Hover@"/>
    <SolidColorBrush x:Key="SelectedBrush" Color="@Selected@"/>
    <SolidColorBrush x:Key="SelectedInkBrush" Color="@SelectedInk@"/>
    <SolidColorBrush x:Key="TrackBrush" Color="@Track@"/>
    <SolidColorBrush x:Key="AccentBrush" Color="@Accent@"/>
    <SolidColorBrush x:Key="AccentHoverBrush" Color="@AccentHover@"/>
    <SolidColorBrush x:Key="OnAccentBrush" Color="@OnAccent@"/>
    <SolidColorBrush x:Key="DisabledBrush" Color="@Disabled@"/>
    <SolidColorBrush x:Key="DisabledInkBrush" Color="@DisabledInk@"/>
    <SolidColorBrush x:Key="NoticeBrush" Color="@Notice@"/>
    <SolidColorBrush x:Key="NoticeLineBrush" Color="@NoticeLine@"/>
    <SolidColorBrush x:Key="ScrollBrush" Color="@Scroll@"/>
    <SolidColorBrush x:Key="CriticalBrush" Color="@Critical@"/>
    <SolidColorBrush x:Key="LowBrush" Color="@Low@"/>
    <SolidColorBrush x:Key="WarningBrush" Color="@Warning@"/>
    <SolidColorBrush x:Key="HealthyBrush" Color="@Healthy@"/>

    <Style x:Key="FocusRing">
      <Setter Property="Control.Template">
        <Setter.Value>
          <ControlTemplate>
            <Rectangle Margin="-3" RadiusX="6" RadiusY="6" StrokeThickness="2" Stroke="{StaticResource InkBrush}" SnapsToDevicePixels="True"/>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="FieldLabel" TargetType="TextBlock">
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="Margin" Value="0,0,0,4"/>
    </Style>

    <Style x:Key="FieldBox" TargetType="TextBox">
      <Setter Property="Height" Value="32"/>
      <Setter Property="Padding" Value="8,0,8,0"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Background" Value="{StaticResource ControlBrush}"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
      <Setter Property="CaretBrush" Value="{StaticResource InkBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource ControlLineBrush}"/>
      <Setter Property="FocusVisualStyle" Value="{StaticResource FocusRing}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Edge" Background="{TemplateBinding Background}" BorderBrush="{StaticResource LineBrush}" BorderThickness="1" CornerRadius="4">
              <Border x:Name="Under" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="0,0,0,1" CornerRadius="4">
                <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
              </Border>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="Under" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                <Setter TargetName="Under" Property="BorderThickness" Value="0,0,0,2"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="ButtonBase" TargetType="Button">
      <Setter Property="Height" Value="32"/>
      <Setter Property="MinWidth" Value="88"/>
      <Setter Property="Padding" Value="12,0,12,0"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="FocusVisualStyle" Value="{StaticResource FocusRing}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" RecognizesAccessKey="True"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="PlainButton" TargetType="Button" BasedOn="{StaticResource ButtonBase}">
      <Setter Property="Background" Value="{StaticResource ControlBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{StaticResource HoverBrush}"/>
        </Trigger>
        <Trigger Property="IsEnabled" Value="False">
          <Setter Property="Background" Value="{StaticResource DisabledBrush}"/>
          <Setter Property="Foreground" Value="{StaticResource DisabledInkBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource ButtonBase}">
      <Setter Property="Background" Value="{StaticResource AccentBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
      <Setter Property="Foreground" Value="{StaticResource OnAccentBrush}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{StaticResource AccentHoverBrush}"/>
          <Setter Property="BorderBrush" Value="{StaticResource AccentHoverBrush}"/>
        </Trigger>
        <Trigger Property="IsEnabled" Value="False">
          <Setter Property="Background" Value="{StaticResource DisabledBrush}"/>
          <Setter Property="BorderBrush" Value="{StaticResource DisabledBrush}"/>
          <Setter Property="Foreground" Value="{StaticResource DisabledInkBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="{StaticResource SurfaceBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="8"/>
    </Style>

    <Style x:Key="TabIntro" TargetType="TextBlock">
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Margin" Value="16,12,16,12"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
    </Style>

    <Style x:Key="ActionMessage" TargetType="TextBlock">
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
    </Style>

    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Width" Value="12"/>
      <Setter Property="MinWidth" Value="12"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Grid Background="Transparent">
              <Track x:Name="PART_Track" IsDirectionReversed="True">
                <Track.Thumb>
                  <Thumb>
                    <Thumb.Template>
                      <ControlTemplate TargetType="Thumb">
                        <Border Margin="3,2,3,2" CornerRadius="3" Background="{StaticResource ScrollBrush}"/>
                      </ControlTemplate>
                    </Thumb.Template>
                  </Thumb>
                </Track.Thumb>
              </Track>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Width" Value="Auto"/>
          <Setter Property="MinWidth" Value="0"/>
          <Setter Property="Height" Value="12"/>
          <Setter Property="MinHeight" Value="12"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="ScrollBar">
                <Grid Background="Transparent">
                  <Track x:Name="PART_Track" IsDirectionReversed="False">
                    <Track.Thumb>
                      <Thumb>
                        <Thumb.Template>
                          <ControlTemplate TargetType="Thumb">
                            <Border Margin="2,3,2,3" CornerRadius="3" Background="{StaticResource ScrollBrush}"/>
                          </ControlTemplate>
                        </Thumb.Template>
                      </Thumb>
                    </Track.Thumb>
                  </Track>
                </Grid>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="CleanTabs" TargetType="TabControl">
      <Setter Property="Background" Value="{StaticResource SurfaceBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabControl">
            <Grid KeyboardNavigation.TabNavigation="Local">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <TabPanel Grid.Row="0" IsItemsHost="True" Background="Transparent" Margin="0,0,0,8"/>
              <Border Grid.Row="1" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8">
                <ContentPresenter Content="{TemplateBinding SelectedContent}" ContentTemplate="{TemplateBinding SelectedContentTemplate}"/>
              </Border>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="CleanTab" TargetType="TabItem">
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="FontSize" Value="13.5"/>
      <Setter Property="Padding" Value="12,6,12,4"/>
      <Setter Property="Margin" Value="0,0,2,0"/>
      <Setter Property="FocusVisualStyle" Value="{StaticResource FocusRing}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Back" Background="Transparent" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <StackPanel>
                <ContentPresenter Content="{TemplateBinding Header}" ContentTemplate="{TemplateBinding HeaderTemplate}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                <Border x:Name="Pill" Height="3" Width="20" Margin="0,4,0,0" CornerRadius="1.5" Background="Transparent" HorizontalAlignment="Center"/>
              </StackPanel>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Back" Property="Background" Value="{StaticResource HoverBrush}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Pill" Property="Background" Value="{StaticResource AccentBrush}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
        </Trigger>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
          <Setter Property="FontWeight" Value="SemiBold"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="FilterItem" TargetType="ListBoxItem">
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
      <Setter Property="Margin" Value="0,0,4,0"/>
      <Setter Property="FocusVisualStyle" Value="{StaticResource FocusRing}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListBoxItem">
            <Border x:Name="Back" Background="{StaticResource ControlBrush}" BorderBrush="{StaticResource LineBrush}" BorderThickness="1" CornerRadius="14" Padding="12,4,12,5">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Back" Property="Background" Value="{StaticResource HoverBrush}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Back" Property="Background" Value="{StaticResource AccentBrush}"/>
                <Setter TargetName="Back" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                <Setter Property="Foreground" Value="{StaticResource OnAccentBrush}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="HeaderBase" TargetType="DataGridColumnHeader">
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridColumnHeader">
            <Border Background="{StaticResource SubtleBrush}" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,0,0,1" Padding="12,0,12,0">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="HeaderRight" TargetType="DataGridColumnHeader" BasedOn="{StaticResource HeaderBase}">
      <Setter Property="HorizontalContentAlignment" Value="Right"/>
    </Style>

    <Style x:Key="CellText" TargetType="TextBlock">
      <Setter Property="Margin" Value="12,0,12,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="CellBold" TargetType="TextBlock" BasedOn="{StaticResource CellText}">
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="CellRight" TargetType="TextBlock" BasedOn="{StaticResource CellText}">
      <Setter Property="TextAlignment" Value="Right"/>
    </Style>
    <Style x:Key="CellWrap" TargetType="TextBlock" BasedOn="{StaticResource CellText}">
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Margin" Value="12,6,12,6"/>
    </Style>
    <Style x:Key="CellTrim" TargetType="TextBlock" BasedOn="{StaticResource CellText}">
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
    </Style>

    <Style x:Key="GridRow" TargetType="DataGridRow">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{StaticResource HoverBrush}"/>
        </Trigger>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="{StaticResource SelectedBrush}"/>
          <Setter Property="Foreground" Value="{StaticResource SelectedInkBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="GridCell" TargetType="DataGridCell">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="Transparent">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Foreground" Value="{StaticResource SelectedInkBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="GridStyle" TargetType="DataGrid">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="RowBackground" Value="Transparent"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="HorizontalGridLinesBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="SelectionMode" Value="Single"/>
      <Setter Property="SelectionUnit" Value="FullRow"/>
      <Setter Property="MinRowHeight" Value="36"/>
      <Setter Property="ColumnHeaderHeight" Value="32"/>
      <Setter Property="CanUserResizeRows" Value="False"/>
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="ColumnHeaderStyle" Value="{StaticResource HeaderBase}"/>
      <Setter Property="RowStyle" Value="{StaticResource GridRow}"/>
      <Setter Property="CellStyle" Value="{StaticResource GridCell}"/>
    </Style>
  </Window.Resources>

  <Grid Background="{StaticResource BgBrush}">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Row 0: title and the two drive gauges -->
    <Grid Grid.Row="0" Margin="24,16,24,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0" VerticalAlignment="Center" Margin="0,0,16,0">
        <TextBlock Text="Disk Space Triage" FontFamily="Segoe UI Variable Display, Segoe UI" FontSize="24" FontWeight="SemiBold" Foreground="{StaticResource InkBrush}"/>
        <TextBlock Text="Scan, then move or remove what fills the drive. Scanning only reads sizes; every change asks first." Margin="0,2,0,0" TextWrapping="Wrap" Foreground="{StaticResource MutedBrush}"/>
      </StackPanel>
      <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
        <Border Width="268" Margin="0,0,8,0" Padding="12,8,12,10" Style="{StaticResource Card}">
          <StackPanel>
            <Grid>
              <TextBlock Text="Drive to free up" FontSize="12" Foreground="{StaticResource MutedBrush}"/>
              <TextBlock x:Name="SourceDriveStatus" Text="-" FontSize="12" HorizontalAlignment="Right" FontWeight="SemiBold" Foreground="{StaticResource MutedBrush}"/>
            </Grid>
            <TextBlock x:Name="SourceDriveLabel" Text="-" Margin="0,4,0,0" FontWeight="SemiBold" TextTrimming="CharacterEllipsis" Foreground="{StaticResource InkBrush}"/>
            <ProgressBar x:Name="SourceDriveBar" Minimum="0" Maximum="100" Value="0" Height="4" Margin="0,8,0,0" BorderThickness="0" Background="{StaticResource TrackBrush}" Foreground="{StaticResource AccentBrush}" AutomationProperties.Name="Used space on the drive to free up"/>
          </StackPanel>
        </Border>
        <Border Width="268" Padding="12,8,12,10" Style="{StaticResource Card}">
          <StackPanel>
            <Grid>
              <TextBlock Text="Drive to move things to" FontSize="12" Foreground="{StaticResource MutedBrush}"/>
              <TextBlock x:Name="DestDriveStatus" Text="-" FontSize="12" HorizontalAlignment="Right" FontWeight="SemiBold" Foreground="{StaticResource MutedBrush}"/>
            </Grid>
            <TextBlock x:Name="DestDriveLabel" Text="-" Margin="0,4,0,0" FontWeight="SemiBold" TextTrimming="CharacterEllipsis" Foreground="{StaticResource InkBrush}"/>
            <ProgressBar x:Name="DestDriveBar" Minimum="0" Maximum="100" Value="0" Height="4" Margin="0,8,0,0" BorderThickness="0" Background="{StaticResource TrackBrush}" Foreground="{StaticResource AccentBrush}" AutomationProperties.Name="Used space on the drive to move things to"/>
          </StackPanel>
        </Border>
      </StackPanel>
    </Grid>

    <!-- Row 1: scan controls -->
    <Grid Grid.Row="1" Margin="24,12,24,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Bottom">
        <StackPanel Margin="0,0,8,0">
          <TextBlock Text="Free up" Style="{StaticResource FieldLabel}"/>
          <TextBox x:Name="SourceBox" Text="C" MaxLength="1" CharacterCasing="Upper" Width="56" TextAlignment="Center" Style="{StaticResource FieldBox}" AutomationProperties.Name="Letter of the drive to free up"/>
        </StackPanel>
        <StackPanel Margin="0,0,8,0">
          <TextBlock Text="Move to" Style="{StaticResource FieldLabel}"/>
          <TextBox x:Name="DestBox" Text="D" MaxLength="1" CharacterCasing="Upper" Width="56" TextAlignment="Center" Style="{StaticResource FieldBox}" AutomationProperties.Name="Letter of the drive to move things to"/>
        </StackPanel>
        <StackPanel Margin="0,0,8,0">
          <TextBlock Text="List files over (MB)" Style="{StaticResource FieldLabel}"/>
          <TextBox x:Name="MinSizeBox" Text="100" Width="104" TextAlignment="Right" Style="{StaticResource FieldBox}" AutomationProperties.Name="Smallest file size to list, in megabytes"/>
        </StackPanel>
      </StackPanel>
      <StackPanel Grid.Column="1" VerticalAlignment="Bottom" Margin="0,0,16,0">
        <TextBlock Text="Extra folders to scan (optional; full paths separated by ;)" Style="{StaticResource FieldLabel}" TextTrimming="CharacterEllipsis"/>
        <TextBox x:Name="ExtraRootsBox" Style="{StaticResource FieldBox}" AutomationProperties.Name="Extra folders to scan"/>
      </StackPanel>
      <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Bottom">
        <Button x:Name="ScanButton" Content="_Scan" MinWidth="104" Style="{StaticResource PrimaryButton}"/>
        <Button x:Name="CancelButton" Content="Cancel" IsEnabled="False" Style="{StaticResource PlainButton}"/>
        <Button x:Name="ExportButton" Content="Save _report" Style="{StaticResource PlainButton}" Margin="0"/>
      </StackPanel>
    </Grid>

    <!-- Row 2: what is happening now -->
    <StackPanel Grid.Row="2" Margin="24,12,24,0">
      <TextBlock x:Name="ProgressText" Text="Choose Scan to see what is filling the drive. Scanning changes nothing." FontWeight="SemiBold" TextTrimming="CharacterEllipsis" Foreground="{StaticResource InkBrush}"/>
      <ProgressBar x:Name="BusyBar" Minimum="0" Maximum="100" Value="0" Height="4" Margin="0,6,0,0" BorderThickness="0" Visibility="Hidden" Background="{StaticResource TrackBrush}" Foreground="{StaticResource AccentBrush}" AutomationProperties.Name="Progress of the current task"/>
    </StackPanel>

    <!-- Row 3: free space and the Recycle Bin -->
    <Border Grid.Row="3" Margin="24,8,24,0" Padding="16,8,8,8" Background="{StaticResource NoticeBrush}" BorderBrush="{StaticResource NoticeLineBrush}" BorderThickness="1" CornerRadius="8">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Grid.Column="0" VerticalAlignment="Center" Margin="0,0,16,0">
          <TextBlock x:Name="RecycleText" Text="Recycle Bin: not checked yet." FontWeight="SemiBold" TextWrapping="Wrap" Foreground="{StaticResource InkBrush}"/>
          <TextBlock x:Name="SessionText" Text="Space freed in this session: none yet." Margin="0,2,0,0" TextWrapping="Wrap" Foreground="{StaticResource InkBrush}"/>
        </StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
          <Button x:Name="EmptyBinButton" Content="_Empty Recycle Bin..." Style="{StaticResource PrimaryButton}"/>
          <Button x:Name="SummaryButton" Content="Copy summary" ToolTip="Copies what was done and the free space before and after. Contains no file or folder names." Style="{StaticResource PlainButton}"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Row 4: tabs -->
    <TabControl x:Name="MainTabs" Grid.Row="4" Margin="24,12,24,0" Style="{StaticResource CleanTabs}" ItemContainerStyle="{StaticResource CleanTab}">
      <TabItem Header="Overview">
        <DataGrid x:Name="MechanismsGrid" Style="{StaticResource GridStyle}" AutomationProperties.Name="What uses the space, largest first">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Size" Binding="{Binding SizeText, Mode=OneWay}" SortMemberPath="TotalBytes" Width="104" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
            <DataGridTextColumn Header="Kind" Binding="{Binding Bucket, Mode=OneWay}" Width="88" ElementStyle="{StaticResource CellBold}"/>
            <DataGridTextColumn Header="What to do" Binding="{Binding Mechanism, Mode=OneWay}" Width="2*" MinWidth="240" ElementStyle="{StaticResource CellWrap}"/>
            <DataGridTextColumn Header="What it is" Binding="{Binding Note, Mode=OneWay}" Width="2*" MinWidth="240" ElementStyle="{StaticResource CellWrap}"/>
            <DataGridTextColumn Header="Files" Binding="{Binding FilesText, Mode=OneWay}" SortMemberPath="Files" Width="88" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>

      <TabItem x:Name="RedirectTab" Header="Move caches">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Style="{StaticResource TabIntro}" Text="Download caches and model stores of Python, Hugging Face, Ollama, npm and similar tools. Moving one copies every file to the other drive, checks each copy, tells the tool to use the new folder from now on, and then removes the old folder. Close the tool that owns the store first."/>
          <Border Grid.Row="1" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,1,0,1">
            <DataGrid x:Name="RedirectGrid" Style="{StaticResource GridStyle}" AutomationProperties.Name="Caches and model stores that can move">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Size now" Binding="{Binding SizeText, Mode=OneWay}" SortMemberPath="SizeBytes" Width="96" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
                <DataGridTextColumn Header="Store (setting)" Binding="{Binding Variable, Mode=OneWay}" Width="152" ElementStyle="{StaticResource CellBold}"/>
                <DataGridTextColumn Header="Status" Binding="{Binding StatusText, Mode=OneWay}" Width="232" ElementStyle="{StaticResource CellWrap}"/>
                <DataGridTextColumn Header="New folder" Binding="{Binding ProposedValue, Mode=OneWay}" Width="2*" MinWidth="240" ElementStyle="{StaticResource CellWrap}"/>
                <DataGridTextColumn Header="Good to know" Binding="{Binding Effect, Mode=OneWay}" Width="2*" MinWidth="240" ElementStyle="{StaticResource CellWrap}"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
          <Grid Grid.Row="2" Margin="16,12,16,12">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <StackPanel Grid.Row="0" Orientation="Horizontal">
              <Button x:Name="MoveStoreButton" Content="_Move to the other drive..." Style="{StaticResource PrimaryButton}"/>
              <Button x:Name="ApplyRedirectButton" Content="Only change the setting..." ToolTip="New downloads go to the other drive. The files that are on this drive now stay, so no space is freed." Style="{StaticResource PlainButton}"/>
              <Button x:Name="UndoRedirectButton" Content="Undo last setting change" Style="{StaticResource PlainButton}"/>
            </StackPanel>
            <TextBlock x:Name="RedirectMessage" Grid.Row="1" Margin="0,8,0,0" Style="{StaticResource ActionMessage}"/>
          </Grid>
        </Grid>
      </TabItem>

      <TabItem x:Name="DeleteTab" Header="Delete">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Style="{StaticResource TabIntro}" Text="Folders that rebuild or refill by themselves: package folders with a lockfile, shader and browser caches, crash dumps. Deleting sends the whole folder to the Recycle Bin, so you can still restore it. The space is free only after you empty the Recycle Bin (button above). Close the application that owns a cache first."/>
          <Border Grid.Row="1" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,1,0,1">
            <DataGrid x:Name="DeleteGrid" Style="{StaticResource GridStyle}" AutomationProperties.Name="Folders that can be deleted">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Size" Binding="{Binding SizeText, Mode=OneWay}" SortMemberPath="SizeBytes" Width="96" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
                <DataGridTextColumn Header="What it is" Binding="{Binding Note, Mode=OneWay}" Width="216" ElementStyle="{StaticResource CellWrap}"/>
                <DataGridTextColumn Header="Status" Binding="{Binding StatusText, Mode=OneWay}" Width="232" ElementStyle="{StaticResource CellWrap}"/>
                <DataGridTextColumn Header="Folder" Binding="{Binding Path, Mode=OneWay}" Width="*" MinWidth="280" ElementStyle="{StaticResource CellWrap}"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
          <Grid Grid.Row="2" Margin="16,12,16,12">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <StackPanel Grid.Row="0" Orientation="Horizontal">
              <Button x:Name="DeleteStoreButton" Content="_Delete (to Recycle Bin)..." Style="{StaticResource PrimaryButton}"/>
            </StackPanel>
            <TextBlock x:Name="DeleteMessage" Grid.Row="1" Margin="0,8,0,0" Style="{StaticResource ActionMessage}"/>
          </Grid>
        </Grid>
      </TabItem>

      <TabItem x:Name="MoveTab" Header="Move files">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Style="{StaticResource TabIntro}" Text="Large data files: downloads, datasets, videos, archives, model weights. Moving copies the file to the other drive under FromC with the same folder names, checks the copy against the original, and then sends the original to the Recycle Bin. Nothing is overwritten. The space is free only after you empty the Recycle Bin (button above)."/>
          <Border Grid.Row="1" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,1,0,1">
            <DataGrid x:Name="MoveGrid" Style="{StaticResource GridStyle}" AutomationProperties.Name="Files that can be moved">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Size" Binding="{Binding SizeText, Mode=OneWay}" SortMemberPath="SizeBytes" Width="96" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
                <DataGridTextColumn Header="Idle days" Binding="{Binding DaysIdle, Mode=OneWay}" Width="80" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
                <DataGridTextColumn Header="Status" Binding="{Binding StatusText, Mode=OneWay}" Width="200" ElementStyle="{StaticResource CellWrap}"/>
                <DataGridTextColumn Header="File" Binding="{Binding Path, Mode=OneWay}" Width="*" MinWidth="224" ElementStyle="{StaticResource CellWrap}"/>
                <DataGridTextColumn Header="New place" Binding="{Binding Target, Mode=OneWay}" Width="*" MinWidth="224" ElementStyle="{StaticResource CellWrap}"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
          <Grid Grid.Row="2" Margin="16,12,16,12">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <StackPanel Grid.Row="0" Orientation="Horizontal">
              <Button x:Name="MoveFileButton" Content="_Move this file..." Style="{StaticResource PrimaryButton}"/>
            </StackPanel>
            <TextBlock x:Name="MoveMessage" Grid.Row="1" Margin="0,8,0,0" Style="{StaticResource ActionMessage}"/>
          </Grid>
        </Grid>
      </TabItem>

      <TabItem Header="Largest files">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="16,12,16,12">
            <TextBlock Text="Show" VerticalAlignment="Center" Margin="0,0,12,0" Foreground="{StaticResource MutedBrush}"/>
            <ListBox x:Name="BucketFilter" SelectedIndex="0" Background="Transparent" BorderThickness="0" ItemContainerStyle="{StaticResource FilterItem}" ScrollViewer.HorizontalScrollBarVisibility="Disabled" AutomationProperties.Name="Kind of file to show">
              <ListBox.ItemsPanel>
                <ItemsPanelTemplate>
                  <StackPanel Orientation="Horizontal"/>
                </ItemsPanelTemplate>
              </ListBox.ItemsPanel>
              <ListBoxItem Content="All"/>
              <ListBoxItem Content="Redirect"/>
              <ListBoxItem Content="Delete"/>
              <ListBoxItem Content="Move"/>
              <ListBoxItem Content="Review"/>
              <ListBoxItem Content="Never"/>
            </ListBox>
            <TextBlock x:Name="FilesCountText" Text="" VerticalAlignment="Center" Margin="12,0,0,0" Foreground="{StaticResource MutedBrush}"/>
          </StackPanel>
          <Border Grid.Row="1" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,1,0,0">
            <DataGrid x:Name="FilesGrid" Style="{StaticResource GridStyle}" AutomationProperties.Name="Largest files">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Size" Binding="{Binding SizeText, Mode=OneWay}" SortMemberPath="SizeBytes" Width="96" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
                <DataGridTextColumn Header="Kind" Binding="{Binding Bucket, Mode=OneWay}" Width="80" ElementStyle="{StaticResource CellBold}"/>
                <DataGridTextColumn Header="What to do" Binding="{Binding Mechanism, Mode=OneWay}" Width="192" ElementStyle="{StaticResource CellTrim}"/>
                <DataGridTextColumn Header="Idle days" Binding="{Binding DaysIdle, Mode=OneWay}" Width="80" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
                <DataGridTextColumn Header="Last write" Binding="{Binding LastWrite, Mode=OneWay}" Width="104" ElementStyle="{StaticResource CellText}"/>
                <DataGridTextColumn Header="Path" Binding="{Binding Path, Mode=OneWay}" Width="*" MinWidth="240" ElementStyle="{StaticResource CellTrim}"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
        </Grid>
      </TabItem>

      <TabItem Header="Largest folders">
        <DataGrid x:Name="FoldersGrid" Style="{StaticResource GridStyle}" AutomationProperties.Name="Largest folders">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Size" Binding="{Binding SizeText, Mode=OneWay}" SortMemberPath="TotalBytes" Width="120" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
            <DataGridTextColumn Header="Folder" Binding="{Binding Folder, Mode=OneWay}" Width="*" MinWidth="240" ElementStyle="{StaticResource CellTrim}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>

      <TabItem Header="Needs administrator">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Style="{StaticResource TabIntro}" Text="This tool does not measure these items because they need administrator rights. Check each one yourself."/>
          <Border Grid.Row="1" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,1,0,0">
            <DataGrid x:Name="ElevatedGrid" Style="{StaticResource GridStyle}" AutomationProperties.Name="Items that need administrator rights">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Item" Binding="{Binding Item, Mode=OneWay}" Width="224" ElementStyle="{StaticResource CellWrap}"/>
                <DataGridTextColumn Header="Where to change it" Binding="{Binding Action, Mode=OneWay}" Width="*" MinWidth="240" ElementStyle="{StaticResource CellWrap}"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
        </Grid>
      </TabItem>
    </TabControl>

    <!-- Row 5: status bar -->
    <Grid Grid.Row="5" Margin="24,8,24,12">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBlock x:Name="RootsText" Grid.Column="0" Text="Scanned roots: 0" VerticalAlignment="Center" Margin="0,0,24,0" FontSize="12" Foreground="{StaticResource MutedBrush}"/>
      <TextBlock x:Name="DeniedText" Grid.Column="1" Text="Skipped: 0" VerticalAlignment="Center" Margin="0,0,24,0" FontSize="12" Foreground="{StaticResource MutedBrush}"/>
      <TextBlock Grid.Column="2" Text="Last report" VerticalAlignment="Center" Margin="0,0,8,0" FontSize="12" Foreground="{StaticResource MutedBrush}"/>
      <TextBox x:Name="ExportPathBox" Grid.Column="3" IsReadOnly="True" Height="28" FontSize="12" Style="{StaticResource FieldBox}" Margin="0,0,8,0" AutomationProperties.Name="Where the last report was saved"/>
      <Button x:Name="CopyPathButton" Grid.Column="4" Content="Copy path" Style="{StaticResource PlainButton}" Height="28" MinWidth="80" Margin="0"/>
    </Grid>
  </Grid>
</Window>
'@

function Get-TriageStatusBrush {
    param($Window, [string]$Status)
    $key = 'MutedBrush'
    if ($Status -eq 'CRITICAL') { $key = 'CriticalBrush' }
    elseif ($Status -eq 'LOW') { $key = 'LowBrush' }
    elseif ($Status -eq 'WARNING') { $key = 'WarningBrush' }
    elseif ($Status -eq 'HEALTHY') { $key = 'HealthyBrush' }
    return $Window.FindResource($key)
}

function Get-TriageStatusWords {
    param([string]$Status)
    if ($Status -eq 'CRITICAL') { return 'CRITICAL - almost full' }
    if ($Status -eq 'LOW') { return 'LOW - little free space' }
    if ($Status -eq 'WARNING') { return 'WARNING - filling up' }
    if ($Status -eq 'HEALTHY') { return 'HEALTHY - plenty of room' }
    return $Status
}

function Set-TriageDriveBlock {
    param($Window, $LabelCtl, $BarCtl, $StatusCtl, $Facts, [string]$Status, [string]$MissingText)
    if ($null -eq $Facts) {
        $LabelCtl.Text = $MissingText
        $BarCtl.Value = 0
        $StatusCtl.Text = 'NOT AVAILABLE'
        $StatusCtl.Foreground = $Window.FindResource('MutedBrush')
        return
    }
    $LabelCtl.Text = ('{0}:  {1} free of {2} ({3}%)' -f $Facts.Letter, (Format-Size -Bytes ([double]$Facts.FreeBytes)), (Format-Size -Bytes ([double]$Facts.TotalBytes)), $Facts.PercentFree)
    $used = 100.0 - [double]$Facts.PercentFree
    if ($used -lt 0.0) { $used = 0.0 }
    if ($used -gt 100.0) { $used = 100.0 }
    $BarCtl.Value = $used
    $StatusCtl.Text = (Get-TriageStatusWords -Status $Status)
    $brush = Get-TriageStatusBrush -Window $Window -Status $Status
    $StatusCtl.Foreground = $brush
    $BarCtl.Foreground = $brush
}

function Get-TriageSelectedBucket {
    param([hashtable]$Ui)
    $item = $Ui.Controls['BucketFilter'].SelectedItem
    if ($null -eq $item) { return 'All' }
    return [string]$item.Content
}

function Set-TriageFilesGrid {
    param([hashtable]$Ui, $Result, [string]$Bucket)
    $rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    $total = 0
    foreach ($f in @($Result.Files)) {
        $total = $total + 1
        if ($Bucket -ne 'All' -and [string]$f.Bucket -ne $Bucket) { continue }
        $rows.Add([pscustomobject]@{
            SizeText  = (Format-Size -Bytes ([double]$f.SizeBytes))
            SizeBytes = [long]$f.SizeBytes
            Bucket    = [string]$f.Bucket
            Mechanism = [string]$f.Mechanism
            DaysIdle  = [int]$f.DaysIdle
            LastWrite = [string]$f.LastWrite
            Path      = [string]$f.Path
        })
    }
    $Ui.Controls['FilesGrid'].ItemsSource = $rows
    $Ui.Controls['FilesCountText'].Text = ('Showing {0:N0} of {1:N0} files' -f $rows.Count, $total)
}

function Set-TriageDeleteRows {
    param([Parameter(Mandatory = $true)][hashtable]$Ui)
    $rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    foreach ($p in @($script:TriageDeletePlan)) {
        $state = [string]$p.State
        $reason = [string]$p.Reason
        $status = $state
        if ($state -eq 'Ready') {
            $status = 'Ready'
            if ($reason.Length -gt 0) { $status = 'Ready (' + $reason + ')' }
        }
        elseif ($state -eq 'Blocked') {
            $status = 'Not possible: ' + $reason
        }
        $rows.Add([pscustomobject]@{
            Path       = [string]$p.Path
            Note       = [string]$p.Note
            SizeText   = (Format-Size -Bytes ([double]$p.SizeBytes))
            SizeBytes  = [long]$p.SizeBytes
            State      = $state
            Reason     = $reason
            StatusText = $status
        })
    }
    $Ui.Controls['DeleteGrid'].ItemsSource = $rows
}

function Set-TriageMoveRows {
    param([Parameter(Mandatory = $true)][hashtable]$Ui)
    $rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    foreach ($p in @($script:TriageMovePlan)) {
        $state = [string]$p.State
        $reason = [string]$p.Reason
        $status = $state
        if ($state -eq 'Ready') {
            $status = 'Ready'
            if ($reason.Length -gt 0) { $status = 'Ready (' + $reason + ')' }
        }
        elseif ($state -eq 'Blocked') {
            $status = 'Not possible: ' + $reason
        }
        $rows.Add([pscustomobject]@{
            Path       = [string]$p.Path
            Target     = [string]$p.Target
            SizeText   = (Format-Size -Bytes ([double]$p.SizeBytes))
            SizeBytes  = [long]$p.SizeBytes
            DaysIdle   = [int]$p.DaysIdle
            State      = $state
            Reason     = $reason
            StatusText = $status
        })
    }
    $Ui.Controls['MoveGrid'].ItemsSource = $rows
}

function Invoke-TriageGuiScan {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    $src = ([string]$c['SourceBox'].Text).Trim()
    $dst = ([string]$c['DestBox'].Text).Trim()
    $minText = ([string]$c['MinSizeBox'].Text).Trim()

    if ($script:TriageBusy) {
        $c['ProgressText'].Text = 'Wait until the current action has finished.'
        return
    }

    if ($src -notmatch '^[A-Za-z]$') {
        [void][System.Windows.MessageBox]::Show('The drive to free up must be a single letter, for example C.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    if ($dst -notmatch '^[A-Za-z]$') {
        [void][System.Windows.MessageBox]::Show('The drive to move things to must be a single letter, for example D.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    if ($src.ToUpper() -eq $dst.ToUpper()) {
        [void][System.Windows.MessageBox]::Show('The two drives must be different.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    if ($minText -notmatch '^[0-9]{1,7}$' -or [int]$minText -lt 1 -or [int]$minText -gt 1048576) {
        [void][System.Windows.MessageBox]::Show('The smallest file size to list must be a whole number of megabytes between 1 and 1048576.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    $minMb = [int]$minText

    $extraRoots = @()
    foreach ($part in (([string]$c['ExtraRootsBox'].Text) -split ';')) {
        $trimmed = ([string]$part).Trim().Trim('"').Trim()
        if ($trimmed.Length -gt 0) { $extraRoots += $trimmed }
    }
    foreach ($folder in $extraRoots) {
        if (-not $folder.StartsWith($src + ':\', [System.StringComparison]::OrdinalIgnoreCase)) {
            [void][System.Windows.MessageBox]::Show(('Extra folders must be full paths on the source drive, for example ' + $src.ToUpper() + ':\ComfyUI. Not valid: ' + $folder), $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
    }
    $scanRoots = @()
    foreach ($root in @($script:TriageGuiRoots)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$root)) { $scanRoots += [string]$root }
    }
    $scanRoots = @($scanRoots + $extraRoots)
    $srcLetter = [char]$src.ToUpper()
    $dstLetter = [char]$dst.ToUpper()

    $script:TriageCancel = $false
    # Nothing else may be started while the scan runs.
    $script:TriageScanning = $true
    Update-TriageAllActionButtons -Ui $ui
    $c['ProgressText'].Text = 'Scanning (read-only). The other buttons are paused until this has finished.'

    $onProgress = {
        param($dirsScanned, $bytesSeen, $currentPath)
        if (($dirsScanned % 50) -eq 0) {
            $p = [string]$currentPath
            if ($p.Length -gt 70) { $p = '...' + $p.Substring($p.Length - 67) }
            $t = ('Scanning: {0:N0} folders, {1} seen. {2}' -f $dirsScanned, (Format-Size -Bytes ([double]$bytesSeen)), $p)
            $script:TriageUi.Controls['ProgressText'].Text = $t
            $script:TriageUi.Window.Dispatcher.Invoke([System.Action]{ }, [System.Windows.Threading.DispatcherPriority]::Background)
        }
    }

    try {
        $result = Invoke-TriageScan -SourceDrive $srcLetter -DestinationDrive $dstLetter -MinSizeMB $minMb -OnProgress $onProgress `
            -AdditionalRoot $scanRoots -SkipDefaultRoots:$script:TriageGuiSkipDefault
        $script:TriageLastResult = $result
        Update-TriageWindow -Ui $ui -Result $result
        Update-TriageSpaceBar -Ui $ui
        if ($result.Cancelled) {
            $c['ProgressText'].Text = 'Cancelled. Showing partial results. Scan again to see everything.'
        }
        else {
            $c['ProgressText'].Text = ('Done. {0:N0} files scanned, {1} seen. Nothing was changed. Next: open Move caches, Delete or Move files, select a row and choose its button.' -f [long]$result.ScannedFiles, (Format-Size -Bytes ([double]$result.ScannedBytes)))
        }
    }
    catch {
        $msg = $_.Exception.Message
        $c['ProgressText'].Text = 'Scan failed.'
        [void][System.Windows.MessageBox]::Show(('The scan failed: ' + $msg), $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    finally {
        $script:TriageScanning = $false
        Update-TriageAllActionButtons -Ui $ui
    }
}

function Invoke-TriageGuiExport {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    if ($null -eq $script:TriageLastResult) {
        [void][System.Windows.MessageBox]::Show('Nothing to save yet: choose Scan first, then Save report.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }
    try {
        $exported = Export-TriageReport -Result $script:TriageLastResult -Directory $script:TriageGuiReportDir
        $c['ExportPathBox'].Text = [string]$exported.Html
        $c['ProgressText'].Text = 'Report saved. Open the HTML file shown at the bottom of the window.'
    }
    catch {
        $msg = $_.Exception.Message
        [void][System.Windows.MessageBox]::Show(('Export failed: ' + $msg), $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Invoke-TriageGuiCopyPath {
    $ui = $script:TriageUi
    $text = [string]$ui.Controls['ExportPathBox'].Text
    if ($text.Length -eq 0) { return }
    try {
        [System.Windows.Clipboard]::SetText($text)
    }
    catch {
        $msg = $_.Exception.Message
        [void][System.Windows.MessageBox]::Show(('Could not copy to the clipboard: ' + $msg), 'Disk Space Triage', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    }
}

function Save-TriageWindowPng {
    # Self-test only: the one place a file stream is created.
    param($Root, [string]$Path)
    $bmp = New-Object System.Windows.Media.Imaging.RenderTargetBitmap -ArgumentList @(1100, 700, 96.0, 96.0, [System.Windows.Media.PixelFormats]::Pbgra32)
    $bmp.Render($Root)
    $encoder = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bmp))
    $stream = [System.IO.File]::Create($Path)
    try {
        $encoder.Save($stream)
    }
    finally {
        $stream.Dispose()
    }
}

function Initialize-TriageGui {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
}

function Get-TriageControlNames {
    return @(
        'SourceDriveLabel', 'SourceDriveBar', 'SourceDriveStatus',
        'DestDriveLabel', 'DestDriveBar', 'DestDriveStatus',
        'SourceBox', 'DestBox', 'MinSizeBox', 'ExtraRootsBox',
        'ScanButton', 'CancelButton', 'ExportButton', 'ProgressText', 'BusyBar',
        'RecycleText', 'SessionText', 'EmptyBinButton', 'SummaryButton',
        'MainTabs', 'MechanismsGrid', 'BucketFilter', 'FilesCountText', 'FilesGrid', 'FoldersGrid', 'ElevatedGrid',
        'RootsText', 'DeniedText', 'ExportPathBox', 'CopyPathButton',
        'RedirectTab', 'RedirectGrid', 'MoveStoreButton', 'ApplyRedirectButton', 'UndoRedirectButton', 'RedirectMessage',
        'DeleteTab', 'DeleteGrid', 'DeleteStoreButton', 'DeleteMessage',
        'MoveTab', 'MoveGrid', 'MoveFileButton', 'MoveMessage'
    )
}

function Get-TriageTheme {
    # 'Light', 'Dark' or 'Contrast', following Windows. Reads one per-user
    # setting (the only registry value this script ever reads) and changes
    # nothing.
    try {
        if ([System.Windows.SystemParameters]::HighContrast) { return 'Contrast' }
    } catch { Write-Verbose ('High-contrast state unavailable: ' + $_.Exception.Message) }
    try {
        $light = [Microsoft.Win32.Registry]::GetValue('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize', 'AppsUseLightTheme', 1)
        if ($null -ne $light -and [int]$light -eq 0) { return 'Dark' }
    } catch { Write-Verbose ('App theme unavailable: ' + $_.Exception.Message) }
    return 'Light'
}

function Get-TriagePalette {
    # Colour values for the tokens in the window definition.
    param([string]$Theme)
    if ($Theme -eq 'Dark') {
        return @{
            Bg = '#202020'; Surface = '#2B2B2B'; Subtle = '#323232'; Ink = '#FFFFFF'; Muted = '#C8C8C8'; Line = '#3D3D3D'
            Control = '#373737'; ControlLine = '#9A9A9A'; Hover = '#3A3A3A'; Selected = '#17405F'; SelectedInk = '#FFFFFF'
            Track = '#4A4A4A'; Accent = '#60CDFF'; AccentHover = '#8AD9FF'; OnAccent = '#000000'
            Disabled = '#343434'; DisabledInk = '#8C8C8C'; Notice = '#433519'; NoticeLine = '#6B5521'; Scroll = '#8A8A8A'
            Critical = '#FF99A4'; Low = '#FFB37A'; Warning = '#FCE100'; Healthy = '#6CCB5F'
        }
    }
    if ($Theme -eq 'Contrast') {
        $window = [System.Windows.SystemColors]::WindowColor.ToString()
        $text   = [System.Windows.SystemColors]::WindowTextColor.ToString()
        $high   = [System.Windows.SystemColors]::HighlightColor.ToString()
        $onHigh = [System.Windows.SystemColors]::HighlightTextColor.ToString()
        $gray   = [System.Windows.SystemColors]::GrayTextColor.ToString()
        return @{
            Bg = $window; Surface = $window; Subtle = $window; Ink = $text; Muted = $text; Line = $text
            Control = $window; ControlLine = $text; Hover = $window; Selected = $high; SelectedInk = $onHigh
            Track = $window; Accent = $high; AccentHover = $high; OnAccent = $onHigh
            Disabled = $window; DisabledInk = $gray; Notice = $window; NoticeLine = $text; Scroll = $text
            Critical = $text; Low = $text; Warning = $text; Healthy = $text
        }
    }
    return @{
        Bg = '#F3F3F3'; Surface = '#FFFFFF'; Subtle = '#FAFAFA'; Ink = '#1B1B1B'; Muted = '#5C5C5C'; Line = '#E0E0E0'
        Control = '#FFFFFF'; ControlLine = '#868686'; Hover = '#EDEDED'; Selected = '#DCEBF8'; SelectedInk = '#1B1B1B'
        Track = '#DADADA'; Accent = '#005FB8'; AccentHover = '#1A70C2'; OnAccent = '#FFFFFF'
        Disabled = '#EAEAEA'; DisabledInk = '#767676'; Notice = '#FFF4CE'; NoticeLine = '#E6C877'; Scroll = '#8A8A8A'
        Critical = '#C42B1C'; Low = '#A8480B'; Warning = '#7A5C00'; Healthy = '#0F7B0F'
    }
}

function New-TriageWindow {
    param([string]$Theme)
    if ([string]::IsNullOrEmpty($Theme)) { $Theme = Get-TriageTheme }
    $palette = Get-TriagePalette -Theme $Theme
    $xaml = $script:TriageXaml
    foreach ($key in @($palette.Keys)) {
        $colour = [string]$palette[$key]
        if ($colour -notmatch '^#[0-9A-Fa-f]{6,8}$') { throw "Not a colour value for ${key}: $colour" }
        $xaml = $xaml.Replace('@' + $key + '@', $colour)
    }
    $window = [System.Windows.Markup.XamlReader]::Parse($xaml)
    $controls = @{}
    foreach ($name in (Get-TriageControlNames)) {
        $controls[$name] = $window.FindName($name)
    }
    return @{ Window = $window; Controls = $controls; Theme = $Theme }
}

function Get-TriageBucketBytes {
    param($Result, [string]$Bucket)
    foreach ($b in @($Result.Buckets)) {
        if ([string]$b.Bucket -eq $Bucket) { return [double]$b.TotalBytes }
    }
    return 0.0
}

function Get-TriageRowStatus {
    # The words shown in a Status column.
    param([string]$State, [string]$Reason, [string]$Current)
    if ($State -eq 'Ready') {
        if ($Reason.Length -gt 0) { return 'Ready (' + $Reason + ')' }
        return 'Ready'
    }
    if ($State -eq 'AlreadySet') { return 'Setting already points to ' + $Current }
    if ($State -eq 'Blocked') { return 'Not possible: ' + $Reason }
    return $State
}

function Update-TriageAllActionButtons {
    # No button is ever switched off because of what is selected: a button
    # that cannot act says why when it is chosen. Buttons pause only while a
    # scan or an action is running, and the status line says so.
    param([Parameter(Mandatory = $true)][hashtable]$Ui)
    $c = $Ui.Controls
    $idle = (-not $script:TriageScanning) -and (-not $script:TriageBusy)
    foreach ($name in @('ScanButton', 'ExportButton', 'EmptyBinButton', 'SummaryButton', 'MoveStoreButton', 'ApplyRedirectButton', 'UndoRedirectButton', 'DeleteStoreButton', 'MoveFileButton')) {
        $c[$name].IsEnabled = $idle
    }
    $c['CancelButton'].IsEnabled = (-not $idle)
}

function Set-TriageBusy {
    # Marks the start or the end of an action that blocks the other buttons.
    param([Parameter(Mandatory = $true)][hashtable]$Ui, [bool]$Busy, [string]$Text)
    $script:TriageBusy = $Busy
    $c = $Ui.Controls
    $c['BusyBar'].Value = 0
    if ($Busy) {
        $c['BusyBar'].Visibility = 'Visible'
        $c['ProgressText'].Text = $Text + ' The other buttons are paused until this has finished.'
    } else {
        $c['BusyBar'].Visibility = 'Hidden'
        if ($Text.Length -gt 0) { $c['ProgressText'].Text = $Text }
    }
    Update-TriageAllActionButtons -Ui $Ui
    $Ui.Window.Dispatcher.Invoke([System.Action]{ }, [System.Windows.Threading.DispatcherPriority]::Background)
}

function Get-TriageSourceLetter {
    # The drive the window is working on: the scanned one, else the box.
    param([Parameter(Mandatory = $true)][hashtable]$Ui)
    if ($null -ne $script:TriageLastResult -and $null -ne $script:TriageLastResult.Source) { return [string]$script:TriageLastResult.Source.Letter }
    $text = ([string]$Ui.Controls['SourceBox'].Text).Trim()
    if ($text -match '^[A-Za-z]$') { return $text.ToUpper() }
    return ''
}

function Update-TriageSpaceBar {
    # Free space, Recycle Bin contents and the change since the window opened.
    param([Parameter(Mandatory = $true)][hashtable]$Ui)
    $c = $Ui.Controls
    $letter = Get-TriageSourceLetter -Ui $Ui
    if ($letter -eq '') {
        $c['RecycleText'].Text = 'Recycle Bin: enter a drive letter first.'
        return
    }
    $now = Get-TriageSpaceSnapshot -Letter $letter
    if ($null -eq $script:TriageSessionStart -or [string]$script:TriageSessionStart.Letter -ne $letter) { $script:TriageSessionStart = $now }
    $script:TriageSpaceNow = $now

    if ($now.FreeBytes -lt 0) {
        $c['RecycleText'].Text = ('Drive {0}: is not available.' -f $letter)
    } elseif (-not $now.BinKnown) {
        $c['RecycleText'].Text = ('The Recycle Bin on {0}: could not be read. Deleted items still take space until it is emptied.' -f $letter)
    } elseif ($now.BinItems -le 0) {
        $c['RecycleText'].Text = ('The Recycle Bin on {0}: is empty. Nothing is waiting to be freed.' -f $letter)
    } else {
        $c['RecycleText'].Text = ('The Recycle Bin on {0}: holds {1} in {2:N0} item(s). That space is NOT free until you empty it.' -f $letter, (Format-Size -Bytes ([double]$now.BinBytes)), $now.BinItems)
    }

    $start = $script:TriageSessionStart
    if ($start.FreeBytes -ge 0 -and $now.FreeBytes -ge 0) {
        $delta = [double]($now.FreeBytes - $start.FreeBytes)
        $sign = '+'
        if ($delta -lt 0) { $sign = '-'; $delta = -$delta }
        $c['SessionText'].Text = ('Free on {0}: {1} when this window opened, {2} now ({3}{4}).' -f $letter, (Format-Size -Bytes ([double]$start.FreeBytes)), (Format-Size -Bytes ([double]$now.FreeBytes)), $sign, (Format-Size -Bytes $delta))
    }

    # Keep the gauge at the top in step with the real figure.
    $facts = Get-DriveFacts -Letter $letter
    if ($null -ne $facts) {
        Set-TriageDriveBlock -Window $Ui.Window -LabelCtl $c['SourceDriveLabel'] -BarCtl $c['SourceDriveBar'] -StatusCtl $c['SourceDriveStatus'] -Facts $facts -Status ([string](Get-PressureStatus -Facts $facts)) -MissingText 'Drive not found'
    }
    $destText = ([string]$c['DestBox'].Text).Trim()
    if ($destText -match '^[A-Za-z]$') {
        $destFacts = Get-DriveFacts -Letter $destText.ToUpper()
        $destStatus = 'UNKNOWN'
        if ($null -ne $destFacts) { $destStatus = [string](Get-PressureStatus -Facts $destFacts) }
        Set-TriageDriveBlock -Window $Ui.Window -LabelCtl $c['DestDriveLabel'] -BarCtl $c['DestDriveBar'] -StatusCtl $c['DestDriveStatus'] -Facts $destFacts -Status $destStatus -MissingText 'Drive not found'
    }
}

function Add-TriageSessionRecord {
    # Remembers one finished action for the summary (sizes only, no paths).
    param($Record, [string]$Action)
    $before = $null; $after = $null; $size = [long]0
    $names = @($Record.PSObject.Properties.Name)
    if ($names -contains 'Before') { $before = $Record.Before }
    if ($names -contains 'After')  { $after  = $Record.After }
    if ($names -contains 'SizeBytes') { $size = [long]$Record.SizeBytes }
    $script:TriageSession.Add([pscustomobject]@{ Action = $Action; SizeBytes = $size; Before = $before; After = $after })
}

function Get-TriageOutcomeTail {
    # What every action message ends with: the measured free space, what is
    # still waiting in the Recycle Bin, and where the change was logged.
    param($Record)
    $tail = ''
    $names = @($Record.PSObject.Properties.Name)
    if ($names -contains 'Space' -and ([string]$Record.Space).Length -gt 0) { $tail = ' ' + [string]$Record.Space }
    if ($names -contains 'After' -and $null -ne $Record.After -and $Record.After.BinKnown -and $Record.After.BinBytes -gt 0) {
        $tail = $tail + ' To really free that space, choose Empty Recycle Bin above.'
    }
    if (([string]$Record.LogPath).Length -gt 0) {
        $tail = $tail + ' Logged in ' + [string]$Record.LogPath
    } else {
        $tail = $tail + ' Note: this could NOT be written to the change log (is the file open in another program?).'
    }
    return $tail
}

function Update-TriageRedirectGrid {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Ui,
        [Parameter(Mandatory = $true)]$Result
    )
    $c = $Ui.Controls
    $plan = @()
    $problem = ''
    try {
        $plan = @(Get-TriageRedirectPlan -Result $Result)
    }
    catch {
        $plan = @()
        $problem = $_.Exception.Message
    }
    $script:TriageRedirectPlan = $plan

    $rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    foreach ($p in $plan) {
        # The Status column answers "can this store move?", which is what frees space.
        $status = Get-TriageRowStatus -State ([string]$p.MoveState) -Reason ([string]$p.MoveReason) -Current ([string]$p.CurrentValue)
        if ([string]$p.MoveState -ne 'Ready' -and [string]$p.State -eq 'AlreadySet') {
            $status = 'Setting already points to ' + [string]$p.CurrentValue + '. ' + [string]$p.MoveReason
        }
        $rows.Add([pscustomobject]@{
            Variable      = [string]$p.Variable
            SizeText      = (Format-Size -Bytes ([double]$p.SizeBytes))
            SizeBytes     = [long]$p.SizeBytes
            ProposedValue = [string]$p.ProposedValue
            Effect        = [string]$p.Effect
            StatusText    = $status
        })
    }
    $c['RedirectGrid'].ItemsSource = $rows
    if ($plan.Count -eq 0) {
        if ($problem.Length -gt 0) {
            $c['RedirectMessage'].Text = ('Could not work out which stores can move: ' + $problem)
        }
        else {
            $c['RedirectMessage'].Text = 'The scan found no cache or model store that this tool can move.'
        }
    }
    elseif (([string]$c['RedirectMessage'].Text).Length -eq 0) {
        $c['RedirectMessage'].Text = 'Select a row marked Ready, then choose Move to the other drive. You are asked to confirm before anything happens.'
    }
}

function Update-TriageDeleteGrid {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Ui,
        [Parameter(Mandatory = $true)]$Result
    )
    $c = $Ui.Controls
    $plan = @()
    $problem = ''
    try {
        $plan = @(Get-TriageDeletePlan -Result $Result)
    }
    catch {
        $plan = @()
        $problem = $_.Exception.Message
    }
    $script:TriageDeletePlan = $plan
    Set-TriageDeleteRows -Ui $Ui
    if ($plan.Count -eq 0) {
        if ($problem.Length -gt 0) {
            $c['DeleteMessage'].Text = ('Could not work out which folders can be deleted: ' + $problem)
        }
        else {
            $c['DeleteMessage'].Text = 'The scan found no folder the tool can delete safely.'
        }
    }
    elseif (([string]$c['DeleteMessage'].Text).Length -eq 0) {
        $c['DeleteMessage'].Text = 'Select a row marked Ready, then choose Delete. You are asked to confirm before anything happens.'
    }
}

function Update-TriageMoveGrid {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Ui,
        [Parameter(Mandatory = $true)]$Result
    )
    $c = $Ui.Controls
    $plan = @()
    $problem = ''
    try {
        $plan = @(Get-TriageMovePlan -Result $Result)
    }
    catch {
        $plan = @()
        $problem = $_.Exception.Message
    }
    $script:TriageMovePlan = $plan
    Set-TriageMoveRows -Ui $Ui
    if ($plan.Count -eq 0) {
        if ($problem.Length -gt 0) {
            $c['MoveMessage'].Text = ('Could not work out which files can be moved: ' + $problem)
        }
        else {
            $c['MoveMessage'].Text = 'The scan found no file the tool can move.'
        }
    }
    elseif (([string]$c['MoveMessage'].Text).Length -eq 0) {
        $c['MoveMessage'].Text = 'Select a row marked Ready, then choose Move this file. You are asked to confirm before anything happens.'
    }
}

function Update-TriageWindow {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Ui,
        [Parameter(Mandatory = $true)]$Result
    )
    $c = $Ui.Controls
    $w = $Ui.Window

    # Drive status
    Set-TriageDriveBlock -Window $w -LabelCtl $c['SourceDriveLabel'] -BarCtl $c['SourceDriveBar'] -StatusCtl $c['SourceDriveStatus'] -Facts $Result.Source -Status ([string]$Result.Status) -MissingText 'Drive not found'
    $dest = $Result.Destination
    $destStatus = 'UNKNOWN'
    if ($null -ne $dest) { $destStatus = [string](Get-PressureStatus -Facts $dest) }
    Set-TriageDriveBlock -Window $w -LabelCtl $c['DestDriveLabel'] -BarCtl $c['DestDriveBar'] -StatusCtl $c['DestDriveStatus'] -Facts $dest -Status $destStatus -MissingText 'Drive not found'

    # The three action tabs carry their totals in the tab name.
    $c['RedirectTab'].Header = ('Move caches ({0})' -f (Format-Size -Bytes (Get-TriageBucketBytes -Result $Result -Bucket 'Redirect')))
    $c['DeleteTab'].Header   = ('Delete ({0})' -f (Format-Size -Bytes (Get-TriageBucketBytes -Result $Result -Bucket 'Delete')))
    $c['MoveTab'].Header     = ('Move files ({0})' -f (Format-Size -Bytes (Get-TriageBucketBytes -Result $Result -Bucket 'Move')))

    # Overview
    $mech = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    foreach ($m in @($Result.Mechanisms)) {
        $mech.Add([pscustomobject]@{
            SizeText   = (Format-Size -Bytes ([double]$m.TotalBytes))
            TotalBytes = [long]$m.TotalBytes
            Bucket     = [string]$m.Bucket
            Mechanism  = [string]$m.Mechanism
            Note       = [string]$m.Note
            FilesText  = ('{0:N0}' -f [long]$m.Files)
            Files      = [long]$m.Files
        })
    }
    $c['MechanismsGrid'].ItemsSource = $mech

    # Action tabs
    $c['RedirectMessage'].Text = ''
    Update-TriageRedirectGrid -Ui $Ui -Result $Result
    $c['DeleteMessage'].Text = ''
    Update-TriageDeleteGrid -Ui $Ui -Result $Result
    $c['MoveMessage'].Text = ''
    Update-TriageMoveGrid -Ui $Ui -Result $Result

    # Files (honours the current filter)
    Set-TriageFilesGrid -Ui $Ui -Result $Result -Bucket (Get-TriageSelectedBucket -Ui $Ui)

    # Folders
    $folders = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    foreach ($f in @($Result.Folders)) {
        $folders.Add([pscustomobject]@{
            SizeText   = (Format-Size -Bytes ([double]$f.TotalBytes))
            TotalBytes = [long]$f.TotalBytes
            Folder     = [string]$f.Folder
        })
    }
    $c['FoldersGrid'].ItemsSource = $folders

    # Elevated checklist
    $elev = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    foreach ($e in @($Result.ElevatedChecklist)) {
        $elev.Add([pscustomobject]@{
            Item   = [string]$e.Item
            Action = [string]$e.Action
        })
    }
    $c['ElevatedGrid'].ItemsSource = $elev

    # Status bar
    $roots = @($Result.Roots)
    $rootText = ('Scanned roots: {0}' -f $roots.Count)
    if ($Result.Cancelled) { $rootText = $rootText + ' (partial, scan was cancelled)' }
    $c['RootsText'].Text = $rootText
    $c['RootsText'].ToolTip = ($roots -join "`n")
    $c['DeniedText'].Text = ('Skipped: {0:N0} unreadable, {1:N0} links, {2:N0} too deep' -f [long]$Result.DeniedCount, [long]$Result.LinkFoldersSkipped, [long]$Result.DepthLimitedFolders)
}

function Get-TriagePlanItem {
    # The plan entry behind the selected grid row, or the reason there is none.
    param($Grid, $Plan, [string]$Key, [string]$What)
    if ($null -eq $script:TriageLastResult) { return [pscustomobject]@{ Item = $null; Why = 'Nothing to act on yet: choose Scan first.' } }
    $selected = $Grid.SelectedItem
    if ($null -eq $selected) { return [pscustomobject]@{ Item = $null; Why = ('Select a ' + $What + ' in the list first (click its row), then choose the button again.') } }
    foreach ($p in @($Plan)) {
        if ([string]$p.$Key -ceq [string]$selected.$Key) { return [pscustomobject]@{ Item = $p; Why = '' } }
    }
    return [pscustomobject]@{ Item = $null; Why = 'That row is out of date. Choose Scan again.' }
}

function Invoke-TriageGuiApplyRedirect {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    $pick = Get-TriagePlanItem -Grid $c['RedirectGrid'] -Plan $script:TriageRedirectPlan -Key 'Variable' -What 'store'
    if ($null -eq $pick.Item) { $c['RedirectMessage'].Text = $pick.Why; return }
    $planItem = $pick.Item
    if ([string]$planItem.State -ne 'Ready') {
        $why = [string]$planItem.Reason
        if ([string]$planItem.State -eq 'AlreadySet') { $why = 'the setting already points to ' + [string]$planItem.CurrentValue + '.' }
        $c['RedirectMessage'].Text = ('Not changed: ' + $why)
        return
    }

    $lines = @(
        ('Setting: ' + [string]$planItem.Variable),
        ('New folder: ' + [string]$planItem.ProposedValue),
        ('Old folder (stays as it is): ' + [string]$planItem.SourceFolder),
        '',
        'This changes only where NEW downloads go. Nothing is moved or deleted, so NO space is freed now. To free space, choose No and use "Move to the other drive" instead.',
        [string]$planItem.Effect,
        '',
        'The new folder is outside your user profile. On a shared computer, other users of this PC may be able to read or change it. If the drive is external, keep it connected.',
        '',
        "You can undo this with 'Undo last setting change' until you close this window.",
        '',
        'Change only the setting?'
    )
    $answer = [System.Windows.MessageBox]::Show(($lines -join "`n"), $caption, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question, [System.Windows.MessageBoxResult]::No)
    if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
        $c['RedirectMessage'].Text = 'Not changed: you chose No.'
        return
    }
    $record = $null
    $failure = ''
    try {
        $record = Set-TriageRedirect -Item $planItem -LogDirectory $script:TriageGuiReportDir
        $script:TriageRedirectHistory.Add($record)
    }
    catch {
        $failure = $_.Exception.Message
    }
    if ($failure.Length -gt 0) {
        $c['RedirectMessage'].Text = ('Not changed: ' + $failure)
        return
    }
    Add-TriageSessionRecord -Record $record -Action 'Setting changed (nothing moved)'

    $message = ('{0} now points to {1}. Close and reopen your terminals and apps (or sign out and in) so they see it. No space was freed: the old folder is still at {2}. {3}' -f [string]$record.Variable, [string]$record.NewValue, [string]$planItem.SourceFolder, [string]$planItem.OldFolder)
    $c['RedirectMessage'].Text = $message + (Get-TriageOutcomeTail -Record $record)
    if ($null -ne $script:TriageLastResult) { Update-TriageRedirectGrid -Ui $ui -Result $script:TriageLastResult }
}

function Invoke-TriageGuiMoveStore {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    $pick = Get-TriagePlanItem -Grid $c['RedirectGrid'] -Plan $script:TriageRedirectPlan -Key 'Variable' -What 'store'
    if ($null -eq $pick.Item) { $c['RedirectMessage'].Text = $pick.Why; return }
    $planItem = $pick.Item
    if ([string]$planItem.MoveState -ne 'Ready') {
        $c['RedirectMessage'].Text = ('Not moved: ' + [string]$planItem.MoveReason)
        return
    }

    $lines = @(
        ('Store: ' + [string]$planItem.Variable + '  (' + (Format-Size -Bytes ([double]$planItem.SizeBytes)) + ')'),
        ('From: ' + [string]$planItem.SourceFolder),
        ('To: ' + [string]$planItem.ProposedValue),
        '',
        '1. Every file is copied to the new folder and checked against the original. Nothing is overwritten.',
        ('2. ' + [string]$planItem.Variable + ' is set for your account, so the tool uses the new folder from now on.'),
        '3. Windows is asked to put the old folder in the Recycle Bin. If it is too large for the Recycle Bin, Windows asks whether to delete it permanently; by then the checked copy exists, so you can answer Yes.',
        '',
        'First close the application that uses this store (for example Python, Ollama, your editor). A large store can take a long time; you can cancel, and nothing is removed before every file has been checked.',
        'The new folder is outside your user profile. On a shared computer, other users of this PC may be able to read it. If the drive is external, keep it connected.',
        '',
        'Move this store?'
    )
    $answer = [System.Windows.MessageBox]::Show(($lines -join "`n"), $caption, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question, [System.Windows.MessageBoxResult]::No)
    if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
        $c['RedirectMessage'].Text = 'Not moved: you chose No.'
        return
    }

    $script:TriageCancel = $false
    $script:TriageMoveTicks = 0
    Set-TriageBusy -Ui $ui -Busy $true -Text ('Moving ' + [string]$planItem.Variable + '...')
    $c['RedirectMessage'].Text = 'Listing the files to copy...'

    $onProgress = {
        param($stage, $done, $total)
        $script:TriageMoveTicks = $script:TriageMoveTicks + 1
        if (($script:TriageMoveTicks % 8) -ne 0) { return }
        $percent = 0.0
        if ([double]$total -gt 0) { $percent = 100.0 * [double]$done / [double]$total }
        $script:TriageUi.Controls['BusyBar'].Value = $percent
        $script:TriageUi.Controls['RedirectMessage'].Text = ('Copying and checking: {0} of {1}. Choose Cancel (top right) to stop; nothing has been removed.' -f (Format-Size -Bytes ([double]$done)), (Format-Size -Bytes ([double]$total)))
        $script:TriageUi.Window.Dispatcher.Invoke([System.Action]{ }, [System.Windows.Threading.DispatcherPriority]::Background)
    }

    $record = $null
    $failure = ''
    $failed = $false
    try {
        $record = Move-TriageStore -Item $planItem -LogDirectory $script:TriageGuiReportDir -OnProgress $onProgress
    }
    catch {
        $failed = $true
        $failure = $_.Exception.Message
    }
    finally {
        Set-TriageBusy -Ui $ui -Busy $false -Text 'Ready.'
    }
    Update-TriageSpaceBar -Ui $ui
    if ($failed) {
        $c['RedirectMessage'].Text = ('Not moved: ' + $failure)
        return
    }
    Add-TriageSessionRecord -Record $record -Action ([string]$record.Action)

    if ($record.OriginalRecycled -eq $true) {
        $message = ('Moved: {0:N0} file(s) copied and checked ({1}); {2} now points to the new folder and the old folder was removed. Reopen your terminals and apps so they see the new setting.' -f [int]$record.Copied, (Format-Size -Bytes ([double]$record.SizeBytes)), [string]$record.Variable)
    } else {
        $message = ('Copied and checked ({0}), and {1} now points to the new folder - but the old folder could NOT be removed and still takes space. Close the application that uses it, then delete it yourself: {2}' -f (Format-Size -Bytes ([double]$record.SizeBytes)), [string]$record.Variable, [string]$record.OldValue)
    }
    if ([int]$record.Kept -gt 0) { $message = $message + (' {0:N0} file(s) already in the new folder were kept as they are.' -f [int]$record.Kept) }
    $c['RedirectMessage'].Text = $message + (Get-TriageOutcomeTail -Record $record)
    if ($null -ne $script:TriageLastResult) { Update-TriageRedirectGrid -Ui $ui -Result $script:TriageLastResult }
}

function Invoke-TriageGuiUndoRedirect {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    $count = $script:TriageRedirectHistory.Count
    if ($count -le 0) {
        $c['RedirectMessage'].Text = 'Nothing to undo: no setting was changed with "Only change the setting" since this window opened.'
        return
    }
    $record = $script:TriageRedirectHistory[$count - 1]
    $lines = @(
        ('Undo the change to ' + [string]$record.Variable + '?'),
        '',
        ('The setting will be removed again. The folder ' + [string]$record.NewValue + ' stays where it is; anything downloaded into it since stays there too.'),
        '',
        'Undo this change?'
    )
    $answer = [System.Windows.MessageBox]::Show(($lines -join "`n"), $caption, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question, [System.Windows.MessageBoxResult]::No)
    if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
        $c['RedirectMessage'].Text = 'Not undone: you chose No.'
        return
    }

    $undo = $null
    $failure = ''
    try {
        $undo = Undo-TriageRedirect -Record $record -LogDirectory $script:TriageGuiReportDir
    }
    catch {
        $failure = $_.Exception.Message
    }
    # A record that can no longer be undone must not block the ones before it.
    $script:TriageRedirectHistory.RemoveAt($count - 1)
    if ($failure.Length -gt 0) {
        $c['RedirectMessage'].Text = ('Not undone: ' + $failure + ' To remove it yourself: Settings > System > About > Advanced system settings > Environment Variables, under User variables.')
        return
    }
    Add-TriageSessionRecord -Record $undo -Action 'Setting change undone'

    $message = ('{0} is no longer set. Close and reopen your terminals and apps so they see it. The folder {1} was left in place.' -f [string]$record.Variable, [string]$record.NewValue)
    $c['RedirectMessage'].Text = $message + (Get-TriageOutcomeTail -Record $undo)
    if ($null -ne $script:TriageLastResult) { Update-TriageRedirectGrid -Ui $ui -Result $script:TriageLastResult }
}

function Invoke-TriageGuiDeleteStore {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    $pick = Get-TriagePlanItem -Grid $c['DeleteGrid'] -Plan $script:TriageDeletePlan -Key 'Path' -What 'folder'
    if ($null -eq $pick.Item) { $c['DeleteMessage'].Text = $pick.Why; return }
    $planItem = $pick.Item
    if ([string]$planItem.State -ne 'Ready') {
        $c['DeleteMessage'].Text = ('Not deleted: ' + [string]$planItem.Reason)
        return
    }

    $lines = @(
        ('Folder: ' + [string]$planItem.Path),
        ('Size: ' + (Format-Size -Bytes ([double]$planItem.SizeBytes))),
        ('What it is: ' + [string]$planItem.Note),
        '',
        'Windows will be asked to put the whole folder in the Recycle Bin, where you can restore it.',
        'If Windows instead asks whether to delete it PERMANENTLY, answer No: that would not be recoverable.',
        '',
        'The space becomes free when you empty the Recycle Bin afterwards.',
        '',
        'Send this folder to the Recycle Bin?'
    )
    $answer = [System.Windows.MessageBox]::Show(($lines -join "`n"), $caption, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question, [System.Windows.MessageBoxResult]::No)
    if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
        $c['DeleteMessage'].Text = 'Not deleted: you chose No.'
        return
    }
    $record = $null
    $failure = ''
    $failed = $false
    # Nothing else may start while Windows shows its own dialogs.
    Set-TriageBusy -Ui $ui -Busy $true -Text 'Sending the folder to the Recycle Bin...'
    try {
        $record = Remove-TriageStore -Item $planItem -LogDirectory $script:TriageGuiReportDir
    }
    catch {
        $failed = $true
        $failure = $_.Exception.Message
    }
    finally {
        Set-TriageBusy -Ui $ui -Busy $false -Text 'Ready.'
    }
    Update-TriageSpaceBar -Ui $ui
    if ($failed) {
        $c['DeleteMessage'].Text = ('Not deleted: ' + $failure)
        return
    }
    if ($record.StillExists -eq $true) {
        $c['DeleteMessage'].Text = ('Not completely deleted: {0}. {1} Close the application that uses it and look at the folder before trying again.' -f [string]$planItem.Path, [string]$record.Detail)
        return
    }
    Add-TriageSessionRecord -Record $record -Action 'Folder sent to Recycle Bin'

    $remaining = @()
    foreach ($p in @($script:TriageDeletePlan)) {
        if ([string]$p.Path -cne [string]$planItem.Path) { $remaining += $p }
    }
    $script:TriageDeletePlan = $remaining
    Set-TriageDeleteRows -Ui $ui

    $message = ('Sent to the Recycle Bin: {0} ({1}).' -f [string]$planItem.Path, (Format-Size -Bytes ([double]$planItem.SizeBytes)))
    $c['DeleteMessage'].Text = $message + (Get-TriageOutcomeTail -Record $record)
}

function Invoke-TriageGuiMoveFile {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    $pick = Get-TriagePlanItem -Grid $c['MoveGrid'] -Plan $script:TriageMovePlan -Key 'Path' -What 'file'
    if ($null -eq $pick.Item) { $c['MoveMessage'].Text = $pick.Why; return }
    $planItem = $pick.Item
    if ([string]$planItem.State -ne 'Ready') {
        $c['MoveMessage'].Text = ('Not moved: ' + [string]$planItem.Reason)
        return
    }

    $lines = @(
        ('File: ' + [string]$planItem.Path),
        ('Size: ' + (Format-Size -Bytes ([double]$planItem.SizeBytes))),
        ('New place: ' + [string]$planItem.Target),
        '',
        'The file is copied, the copy is read back and compared with the original, and only then is Windows asked to put the original in the Recycle Bin. This can take several minutes for a large file; the window shows progress and you can cancel.',
        'The space becomes free when you empty the Recycle Bin afterwards.',
        '',
        'Please note: the copy gets the permissions of the new folder, so on a shared computer other users may be able to read it. A downloaded file also loses its "came from the internet" mark.',
        '',
        'Move this file?'
    )
    $answer = [System.Windows.MessageBox]::Show(($lines -join "`n"), $caption, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question, [System.Windows.MessageBoxResult]::No)
    if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
        $c['MoveMessage'].Text = 'Not moved: you chose No.'
        return
    }

    $script:TriageCancel = $false
    $script:TriageMoveTicks = 0
    Set-TriageBusy -Ui $ui -Busy $true -Text 'Moving one file...'
    $c['MoveMessage'].Text = 'Starting...'

    $onProgress = {
        param($stage, $done, $total)
        $script:TriageMoveTicks = $script:TriageMoveTicks + 1
        if (($script:TriageMoveTicks % 16) -ne 0) { return }
        $percent = 0.0
        if ([double]$total -gt 0) { $percent = 100.0 * [double]$done / [double]$total }
        $script:TriageUi.Controls['BusyBar'].Value = $percent
        $script:TriageUi.Controls['MoveMessage'].Text = ('{0}: {1} of {2}. Choose Cancel (top right) to stop; nothing has been removed.' -f [string]$stage, (Format-Size -Bytes ([double]$done)), (Format-Size -Bytes ([double]$total)))
        $script:TriageUi.Window.Dispatcher.Invoke([System.Action]{ }, [System.Windows.Threading.DispatcherPriority]::Background)
    }

    $record = $null
    $failure = ''
    $failed = $false
    try {
        $record = Move-TriageFile -Item $planItem -LogDirectory $script:TriageGuiReportDir -OnProgress $onProgress
    }
    catch {
        $failed = $true
        $failure = $_.Exception.Message
    }
    finally {
        Set-TriageBusy -Ui $ui -Busy $false -Text 'Ready.'
    }
    Update-TriageSpaceBar -Ui $ui
    if ($failed) {
        $c['MoveMessage'].Text = ('Not moved: ' + $failure)
        return
    }
    Add-TriageSessionRecord -Record $record -Action ([string]$record.Action)

    $remaining = @()
    foreach ($p in @($script:TriageMovePlan)) {
        if ([string]$p.Path -cne [string]$planItem.Path) { $remaining += $p }
    }
    $script:TriageMovePlan = $remaining
    Set-TriageMoveRows -Ui $ui

    if ($record.OriginalRecycled -eq $true) {
        $message = ('Moved and checked: {0}. The original went to the Recycle Bin.' -f [string]$record.NewValue)
    } else {
        $message = ('Copied and checked: {0}. The original could NOT be sent to the Recycle Bin and is still at {1}; delete it yourself.' -f [string]$record.NewValue, [string]$record.OldValue)
    }
    $c['MoveMessage'].Text = $message + (Get-TriageOutcomeTail -Record $record)
}

function Invoke-TriageGuiEmptyBin {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    $letter = Get-TriageSourceLetter -Ui $ui
    if ($letter -eq '') {
        $c['ProgressText'].Text = 'Not emptied: enter the letter of the drive to free up first.'
        return
    }
    $now = Get-TriageSpaceSnapshot -Letter $letter
    if (-not $now.BinKnown) {
        $c['ProgressText'].Text = ('Not emptied: the Recycle Bin on {0}: could not be read. Empty it from the desktop instead (right-click the Recycle Bin).' -f $letter)
        return
    }
    if ($now.BinItems -le 0) {
        $c['ProgressText'].Text = ('Nothing to empty: the Recycle Bin on {0}: is already empty.' -f $letter)
        Update-TriageSpaceBar -Ui $ui
        return
    }

    $lines = @(
        ('Empty the Recycle Bin on {0}:?' -f $letter),
        '',
        ('It holds {0:N0} item(s), {1}.' -f $now.BinItems, (Format-Size -Bytes ([double]$now.BinBytes))),
        '',
        'This PERMANENTLY deletes everything in your Recycle Bin on this drive - also things you put there yourself, not only what this tool sent there. It cannot be undone.',
        'If you are not sure, choose No and look inside the Recycle Bin first.',
        '',
        'Permanently delete these items?'
    )
    $answer = [System.Windows.MessageBox]::Show(($lines -join "`n"), $caption, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning, [System.Windows.MessageBoxResult]::No)
    if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
        $c['ProgressText'].Text = 'Not emptied: you chose No.'
        return
    }

    $record = $null
    $failure = ''
    Set-TriageBusy -Ui $ui -Busy $true -Text 'Emptying the Recycle Bin...'
    try {
        $record = Clear-TriageRecycleBin -Letter $letter -LogDirectory $script:TriageGuiReportDir
    }
    catch {
        $failure = $_.Exception.Message
    }
    finally {
        Set-TriageBusy -Ui $ui -Busy $false -Text 'Ready.'
    }
    Update-TriageSpaceBar -Ui $ui
    if ($null -eq $record) {
        $c['ProgressText'].Text = ('Not emptied: ' + $failure)
        return
    }
    Add-TriageSessionRecord -Record $record -Action ([string]$record.Action)
    if ($record.After.BinItems -gt 0) {
        $c['ProgressText'].Text = ('Not completely emptied. {0} {1}' -f [string]$record.Failure, [string]$record.Space)
    } else {
        $c['ProgressText'].Text = ('Recycle Bin emptied. ' + [string]$record.Space)
    }
}

function Invoke-TriageGuiCopySummary {
    $ui = $script:TriageUi
    $c = $ui.Controls
    Update-TriageSpaceBar -Ui $ui
    $text = Get-TriageSessionSummary -Start $script:TriageSessionStart -Now $script:TriageSpaceNow -Records $script:TriageSession
    try {
        [System.Windows.Clipboard]::SetText($text)
        $c['ProgressText'].Text = 'Summary copied. It holds sizes and counts only - no file, folder, user or computer names. Paste it where you need it.'
    }
    catch {
        $c['ProgressText'].Text = ('Could not copy to the clipboard: ' + $_.Exception.Message)
    }
}

function Show-TriageWindow {
    param(
        [char]$SourceDrive = 'C',
        [char]$DestinationDrive = 'D'
    )
    Initialize-TriageGui
    $ui = New-TriageWindow
    $script:TriageUi = $ui
    $script:TriageLastResult = $null
    $script:TriageCancel = $false
    $script:TriageRedirectPlan = @()
    $script:TriageDeletePlan = @()
    $script:TriageMovePlan = @()
    $script:TriageBusy = $false
    $script:TriageScanning = $false
    $script:TriageMoveTicks = 0
    $script:TriageSessionStart = $null
    $script:TriageSpaceNow = $null
    $script:TriageSession = New-Object 'System.Collections.Generic.List[object]'
    $script:TriageRedirectHistory = New-Object 'System.Collections.Generic.List[object]'
    $c = $ui.Controls

    $c['SourceBox'].Text = [string]$SourceDrive
    $c['DestBox'].Text = [string]$DestinationDrive

    # Drive status and Recycle Bin contents before any scan
    try {
        Update-TriageSpaceBar -Ui $ui
    }
    catch {
        Write-Verbose ('Initial drive status unavailable: ' + $_.Exception.Message)
    }

    $c['ScanButton'].Add_Click({ Invoke-TriageGuiScan })
    $c['CancelButton'].Add_Click({
        $script:TriageCancel = $true
        $script:TriageUi.Controls['ProgressText'].Text = 'Cancelling...'
    })
    $c['ExportButton'].Add_Click({ Invoke-TriageGuiExport })
    $c['CopyPathButton'].Add_Click({ Invoke-TriageGuiCopyPath })
    $c['EmptyBinButton'].Add_Click({ Invoke-TriageGuiEmptyBin })
    $c['SummaryButton'].Add_Click({ Invoke-TriageGuiCopySummary })
    $c['BucketFilter'].Add_SelectionChanged({
        if ($null -ne $script:TriageLastResult) {
            Set-TriageFilesGrid -Ui $script:TriageUi -Result $script:TriageLastResult -Bucket (Get-TriageSelectedBucket -Ui $script:TriageUi)
        }
    })
    $c['MoveStoreButton'].Add_Click({ Invoke-TriageGuiMoveStore })
    $c['ApplyRedirectButton'].Add_Click({ Invoke-TriageGuiApplyRedirect })
    $c['UndoRedirectButton'].Add_Click({ Invoke-TriageGuiUndoRedirect })
    $c['DeleteStoreButton'].Add_Click({ Invoke-TriageGuiDeleteStore })
    $c['MoveFileButton'].Add_Click({ Invoke-TriageGuiMoveFile })
    Update-TriageAllActionButtons -Ui $ui
    $ui.Window.Add_Closing({ $script:TriageCancel = $true })

    [void]$ui.Window.ShowDialog()
}

function Test-TriageGui {
    # Self-test: builds the window in each theme, fills it with sample data
    # and renders it off-screen. Nothing is shown and no handler is attached.
    param([Parameter(Mandatory = $true)][string]$OutputPath)
    Initialize-TriageGui
    $script:TriageRedirectPlan = @()
    $script:TriageDeletePlan = @()
    $script:TriageMovePlan = @()
    $script:TriageBusy = $false
    $script:TriageScanning = $false
    $script:TriageMoveTicks = 0
    $script:TriageSessionStart = $null
    $script:TriageSpaceNow = $null
    $script:TriageSession = New-Object 'System.Collections.Generic.List[object]'
    $script:TriageRedirectHistory = New-Object 'System.Collections.Generic.List[object]'

    $stem = $OutputPath
    if ($OutputPath.EndsWith('.png', [System.StringComparison]::OrdinalIgnoreCase)) {
        $stem = $OutputPath.Substring(0, $OutputPath.Length - 4)
    }
    $size = New-Object System.Windows.Size -ArgumentList @(1100.0, 700.0)
    $rect = New-Object System.Windows.Rect -ArgumentList @(0.0, 0.0, 1100.0, 700.0)

    foreach ($theme in @('Light', 'Dark', 'Contrast')) {
        $ui = New-TriageWindow -Theme $theme
        foreach ($name in (Get-TriageControlNames)) {
            if (-not $ui.Controls.ContainsKey($name) -or $null -eq $ui.Controls[$name]) {
                throw ('GUI self-test: control not found in XAML: ' + $name)
            }
        }
        $sample = Get-SampleTriageResult
        $script:TriageLastResult = $sample
        Update-TriageWindow -Ui $ui -Result $sample
        Update-TriageSpaceBar -Ui $ui
        Update-TriageAllActionButtons -Ui $ui
        $script:TriageLastResult = $null

        foreach ($grid in @('MechanismsGrid', 'FilesGrid', 'RedirectGrid', 'DeleteGrid', 'MoveGrid')) {
            if ($ui.Controls[$grid].Items.Count -le 0) { throw ('GUI self-test: ' + $grid + ' has no items.') }
        }
        # Nothing may be switched off while the window is idle.
        foreach ($button in @('ScanButton', 'ExportButton', 'EmptyBinButton', 'SummaryButton', 'MoveStoreButton', 'ApplyRedirectButton', 'UndoRedirectButton', 'DeleteStoreButton', 'MoveFileButton')) {
            if (-not $ui.Controls[$button].IsEnabled) { throw ('GUI self-test: ' + $button + ' is disabled in an idle window.') }
        }
        if (([string]$ui.Controls['RedirectTab'].Header) -notmatch '\(') { throw 'GUI self-test: the tab headers carry no totals.' }
        if ($theme -eq 'Contrast') { continue }

        $w = $ui.Window
        $w.Measure($size)
        $w.Arrange($rect)
        $w.UpdateLayout()
        $root = $w.Content

        $suffix = ''
        if ($theme -eq 'Dark') { $suffix = '-dark' }
        $shots = @(
            [pscustomobject]@{ Tab = 0; Path = ($stem + $suffix + '.png') }
            [pscustomobject]@{ Tab = 1; Path = ($stem + $suffix + '-fix.png') }
            [pscustomobject]@{ Tab = 2; Path = ($stem + $suffix + '-delete.png') }
            [pscustomobject]@{ Tab = 3; Path = ($stem + $suffix + '-move.png') }
        )
        foreach ($shot in $shots) {
            if ($theme -eq 'Dark' -and $shot.Tab -gt 1) { continue }
            $ui.Controls['MainTabs'].SelectedIndex = $shot.Tab
            # Give the content root the full bitmap area so the PNG has no empty margin.
            $root.Measure($size)
            $root.Arrange($rect)
            $root.UpdateLayout()
            # Star-sized grid columns are resolved by queued dispatcher work; let it
            # run, then lay out once more so the picture matches a shown window.
            $w.Dispatcher.Invoke([System.Action]{ }, [System.Windows.Threading.DispatcherPriority]::ApplicationIdle)
            $root.Measure($size)
            $root.Arrange($rect)
            $root.UpdateLayout()
            Save-TriageWindowPng -Root $root -Path $shot.Path
        }
    }
    return $true
}
#endregion

#region Main -----------------------------------------------------------------

function Write-TriageSummary {
    param([Parameter(Mandatory)] $Result)

    Write-Host ''
    Write-Host 'Disk space triage  (read-only, standard privileges)' -ForegroundColor Cyan
    Write-Host ('-' * 64)
    $s = $Result.Source
    Write-Host ("Source      {0}:  {1} free of {2}  ({3}% free)  [{4}]" -f $s.Letter, (Format-Size $s.FreeBytes), (Format-Size $s.TotalBytes), $s.PercentFree, $Result.Status)
    if ($null -ne $Result.Destination) {
        $d = $Result.Destination
        Write-Host ("Destination {0}:  {1} free of {2}  ({3}% free)" -f $d.Letter, (Format-Size $d.FreeBytes), (Format-Size $d.TotalBytes), $d.PercentFree)
    }
    Write-Host ''
    Write-Host 'Space by bucket' -ForegroundColor Cyan
    @($Result.Buckets) | ForEach-Object {
        [pscustomobject]@{ Bucket = $_.Bucket; Files = $_.Files; Size = Format-Size $_.TotalBytes }
    } | Format-Table -AutoSize | Out-Host

    Write-Host 'Do these first' -ForegroundColor Cyan
    @($Result.Mechanisms) | Select-Object -First 15 | ForEach-Object {
        [pscustomobject]@{ Size = Format-Size $_.TotalBytes; Bucket = $_.Bucket; 'What to do' = $_.Mechanism; Why = $_.Note }
    } | Format-Table -AutoSize | Out-Host

    if ($Result.DepthLimitedFolders -gt 0) {
        Write-Host "$($Result.DepthLimitedFolders) folder(s) were deeper than the depth limit and not scanned. Raise -MaxDepth to include them." -ForegroundColor DarkGray
    }
    if ($Result.DeniedCount -gt 0) {
        Write-Host "$($Result.DeniedCount) location(s) were unreadable and skipped. Expected; nothing was escalated." -ForegroundColor DarkGray
    }
    if ($Result.Cancelled) { Write-Warning 'The scan was cancelled. Results are partial.' }
}

function Invoke-TriageSelfTest {
    <#
        Built-in checks used by CI. Builds the rule table, classifies a few
        known paths, renders the HTML report from sample data, and renders the
        window off-screen to a PNG. Writes only into the report directory.
    #>
    param([string]$Directory)

    $target = Resolve-ReportDirectory -Requested $Directory
    Initialize-TriageRules

    $expect = @{
        'C:\Windows\System32\kernel32.dll'                          = 'Never'
        'C:\Users\a\.cache\huggingface\hub\blob'                    = 'Redirect'
        'C:\Users\a\AppData\Local\Temp\x.tmp'                       = 'Delete'
        'C:\Users\a\Downloads\image.iso'                            = 'Move'
        'C:\Users\a\AppData\Local\Microsoft\Windows\INetCache\x'    = 'Delete'
        'C:\Users\a\unknown\thing.xyz'                              = 'Review'
    }
    foreach ($path in $expect.Keys) {
        $got = (Get-TriageClassification -Path $path).Bucket
        if ($got -ne $expect[$path]) { throw "Self-test: $path classified as $got, expected $($expect[$path])." }
    }
    Write-Host 'Self-test: classification ok'

    $sample = Get-SampleTriageResult
    $html   = ConvertTo-TriageHtml -Result $sample
    if ($html.Contains('__TRIAGE_DATA__')) { throw 'Self-test: the HTML placeholder was not replaced.' }
    if (-not $html.Contains('Content-Security-Policy')) { throw 'Self-test: the HTML report has no Content-Security-Policy.' }
    $htmlPath = Join-Path $target 'selftest-report.html'
    $html | Out-File -LiteralPath $htmlPath -Encoding UTF8
    Write-Host "Self-test: report ok  ($htmlPath)"

    $pngPath = Join-Path $target 'selftest-window.png'
    [void](Test-TriageGui -OutputPath $pngPath)
    Write-Host "Self-test: window ok  ($pngPath)"
}

if ($ImportOnly) { return }

if ($ShowRules) {
    $script:TriageRules | Format-Table Bucket, Match, Mechanism, Note -AutoSize -Wrap
    Write-Host "File-type fallback (Move): $($script:TriageMoveExtensions -join ' ')"
    return
}

if ((Test-IsElevated) -and -not $AllowElevated) {
    $message = 'This session is running as administrator. Disk Space Triage needs no administrator rights and refuses to run with them, so a read-only diagnostic can never inherit admin reach. Start it again as your normal user. If this account is always an administrator, start it with -AllowElevated.'
    if ($Mode -eq 'Gui') {
        Initialize-TriageGui
        [void][System.Windows.MessageBox]::Show($message, 'Disk Space Triage')
    } else {
        Write-Warning $message
    }
    exit 2
}

if ($Mode -eq 'SelfTest') {
    Invoke-TriageSelfTest -Directory $ReportDirectory
    Write-Host 'Self-test passed.'
    return
}

if ($Mode -eq 'Console') {
    # Check the report folder first, not after minutes of scanning.
    $reportTarget = Resolve-ReportDirectory -Requested $ReportDirectory
    $progress = {
        param($dirs, $bytes, $path)
        if (($dirs % 500) -eq 0) { Write-Host ("  {0} folders, {1} so far ..." -f $dirs, (Format-Size $bytes)) }
    }
    $result = Invoke-TriageScan -SourceDrive $SourceDrive -DestinationDrive $DestinationDrive -MinSizeMB $MinSizeMB `
        -MaxDepth $MaxDepth -TopCount $TopCount -AdditionalRoot $AdditionalRoot -SkipDefaultRoots:$SkipDefaultRoots -OnProgress $progress
    Write-TriageSummary -Result $result
    $report = Export-TriageReport -Result $result -Directory $reportTarget
    Write-Host ''
    Write-Host 'Reports written:' -ForegroundColor Cyan
    Write-Host "  $($report.Html)"
    Write-Host "  $($report.Markdown)"
    Write-Host "  $($report.Csv)"
    Write-Host ''
    $space = Get-TriageSpaceSnapshot -Letter $SourceDrive
    if ($space.BinKnown -and $space.BinItems -gt 0) {
        Write-Host ("The Recycle Bin on {0}: holds {1} in {2} item(s). That space is not free until it is emptied." -f $space.Letter, (Format-Size $space.BinBytes), $space.BinItems) -ForegroundColor Yellow
    }
    Write-Host 'No changes were made to your system. To act on the findings, start the tool without -Mode Console.' -ForegroundColor Yellow
    return
}

Show-TriageWindow -SourceDrive $SourceDrive -DestinationDrive $DestinationDrive
#endregion
