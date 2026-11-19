#requires -Version 5.1
<#
.SYNOPSIS
    Disk Space Triage - shows what is filling a Windows system drive and how
    each item can leave it safely. The scan is read-only; the tool never moves
    or deletes anything.

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
      2. NEVER MOVES OR DELETES. The scan is read-only. The one change the
         tool can make, and only after you tick a box and confirm each time,
         is to set a user environment variable from a fixed list (HF_HOME,
         PIP_CACHE_DIR ...) and create the empty folder it points to. That
         change is logged and can be undone.
      3. METADATA ONLY. File contents are never opened. Only names, sizes,
         timestamps and attributes are read.
      4. NO NETWORK. No download, upload, telemetry or remoting. The HTML
         report is self-contained and carries a Content-Security-Policy that
         blocks every external request.
      5. NO HIDDEN CODE. No Invoke-Expression, no compiled C#, no reflection,
         no COM, no external processes. The single Add-Type call only loads
         the WPF assemblies that ship with Windows.
      6. CONTAINED WRITES. The only files created are the reports and the
         action log, in one folder on a local fixed disk, plus empty folders
         below <drive>:\FromC for confirmed redirects. UNC paths, network
         drives and junctions are refused.
      7. NO LINK TRAVERSAL. Junctions and symbolic links are never followed.
      8. NO PERSISTENCE. No services, scheduled tasks or start-up entries.
         It runs when you start it. The only lasting traces are the reports
         and any user variable you chose to set.

.PARAMETER Mode
    Gui (default) opens the window. Console prints a summary and writes the
    reports. SelfTest runs the built-in checks used by CI.

.PARAMETER SourceDrive
    Drive letter to analyse. Default C.

.PARAMETER DestinationDrive
    Drive letter you intend to relocate to. The scan only checks its capacity;
    confirmed redirects create empty folders below <drive>:\FromC on it.

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

$script:TriageVersion = '1.0.0'
$script:TriageCancel  = $false
$script:TriageUi      = $null
$script:TriageLastResult = $null
$script:TriageRedirectPlan    = @()
$script:TriageRedirectHistory = $null
$script:TriageScanning        = $false
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

    $script:TriageFallbackMove   = [pscustomobject]@{ Bucket = 'Move';   Mechanism = 'Explorer move'; Note = 'Self-contained data file with no registry dependency' }
    $script:TriageFallbackReview = [pscustomobject]@{ Bucket = 'Review'; Mechanism = 'Confirm owner'; Note = 'No rule matched' }
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
    $queue.Enqueue([pscustomobject]@{ Path = $Root; Depth = 0; Subtree = $Root })

    while ($queue.Count -gt 0) {
        if ($script:TriageCancel) { $State.Cancelled = $true; return }
        $node = $queue.Dequeue()

        $dir = $null
        try { $dir = New-Object System.IO.DirectoryInfo $node.Path } catch { $State.DeniedCount++; continue }
        try {
            if (-not $dir.Exists) { continue }
            if (($dir.Attributes -band $reparse) -and (Test-TriageLink -Path $dir.FullName)) { $State.LinkCount++; continue }
        } catch { $State.DeniedCount++; continue }

        $dirKey = $dir.FullName
        if (-not $dirKey.EndsWith('\')) { $dirKey += '\' }
        $dirClass      = Get-TriageClassification -Path $dirKey
        $dirIsFallback = [object]::ReferenceEquals($dirClass, $script:TriageFallbackReview)

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
                    }
                    elseif ($dirIsFallback -and $script:TriageExtensionSet.ContainsKey($file.Extension.ToLowerInvariant())) {
                        $moveBytes += $length; $moveCount++
                    }
                    else {
                        $smallBytes += $length; $smallCount++
                    }
                    $dirBytes += $length
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
                $queue.Enqueue([pscustomobject]@{ Path = $child.FullName; Depth = $node.Depth + 1; Subtree = $subtree })
            }
        }
        catch [System.UnauthorizedAccessException]      { $State.DeniedCount++ }
        catch [System.Security.SecurityException]       { $State.DeniedCount++ }
        catch [System.IO.IOException]                   { $State.DeniedCount++ }
        catch                                           { $State.DeniedCount++ }
    }
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
    $state = [pscustomobject]@{
        BucketBytes    = @{}
        BucketFiles    = @{}
        Mechanisms     = @{}
        Folders        = @{}
        Files          = New-Object System.Collections.Generic.List[object]
        DeniedCount    = 0
        LinkCount      = 0
        DepthLimited   = 0
        CloudOnlyFiles = [long]0
        ScannedBytes   = [long]0
        DirCount       = 0
        Cancelled      = $false
    }
    foreach ($name in $bucketNames) { $state.BucketBytes[$name] = [long]0; $state.BucketFiles[$name] = [long]0 }
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
# The ONLY changes this tool can make to a machine, and only after the user
# enables actions and confirms each one:
#   1. create an empty folder on the destination drive, and
#   2. set (or restore) a user-level environment variable from the list below.
# Nothing is moved or deleted. The old folder stays where it is until the user
# removes it. Every change is written to an action log so it can be undone.

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
        }
    }
    return @($plan)
}

function Write-TriageActionLog {
    param([Parameter(Mandatory)] $Record, [string]$Directory)
    $target = Resolve-ReportDirectory -Requested $Directory
    $path   = Join-Path $target 'DiskTriage_actions.csv'
    $Record | Select-Object When, Action, Variable, OldValue, NewValue | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -Append
    return $path
}

function Set-TriageRedirect {
    <#
        Applies one plan item: creates the empty folder and sets the user
        variable. Re-validates everything first; a stale or edited plan item
        cannot widen what this function does. Returns the record needed to
        undo the change.
    #>
    param([Parameter(Mandatory)] $Item, [string]$LogDirectory)

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
    if (-not (Test-TriageFolderEmpty -Path $value)) { throw "Refused: the new folder already exists and is not empty: $value" }

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
        Width="1100" Height="700" MinWidth="940" MinHeight="560"
        WindowStartupLocation="CenterScreen"
        Background="#EDF1F3"
        FontFamily="Segoe UI" FontSize="13"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <SolidColorBrush x:Key="BgBrush" Color="#EDF1F3"/>
    <SolidColorBrush x:Key="SurfaceBrush" Color="#FFFFFF"/>
    <SolidColorBrush x:Key="InkBrush" Color="#17262F"/>
    <SolidColorBrush x:Key="MutedBrush" Color="#4F5D68"/>
    <SolidColorBrush x:Key="LineBrush" Color="#D3DBE0"/>
    <SolidColorBrush x:Key="HeaderBrush" Color="#EAEFF2"/>
    <SolidColorBrush x:Key="TrackBrush" Color="#DDE4E8"/>
    <SolidColorBrush x:Key="BandBrush" Color="#12303B"/>
    <SolidColorBrush x:Key="AccentBrush" Color="#0E6B7C"/>
    <SolidColorBrush x:Key="RedirectBrush" Color="#0E6B7C"/>
    <SolidColorBrush x:Key="DeleteBrush" Color="#B4452F"/>
    <SolidColorBrush x:Key="MoveBrush" Color="#5B4FB0"/>
    <SolidColorBrush x:Key="CriticalBrush" Color="#A32626"/>
    <SolidColorBrush x:Key="LowBrush" Color="#B35310"/>
    <SolidColorBrush x:Key="WarningBrush" Color="#85680A"/>
    <SolidColorBrush x:Key="HealthyBrush" Color="#2B6B49"/>

    <Style x:Key="FieldLabel" TargetType="TextBlock">
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="Margin" Value="0,0,0,4"/>
    </Style>

    <Style x:Key="FieldBox" TargetType="TextBox">
      <Setter Property="Height" Value="32"/>
      <Setter Property="Padding" Value="6,0,6,0"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="BorderBrush" Value="#AEB9C1"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
    </Style>

    <Style x:Key="ButtonBase" TargetType="Button">
      <Setter Property="Height" Value="32"/>
      <Setter Property="MinWidth" Value="96"/>
      <Setter Property="Padding" Value="16,0,16,0"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="PlainButton" TargetType="Button" BasedOn="{StaticResource ButtonBase}">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="BorderBrush" Value="#AEB9C1"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#E6EEF1"/>
        </Trigger>
        <Trigger Property="IsEnabled" Value="False">
          <Setter Property="Background" Value="#F1F4F6"/>
          <Setter Property="BorderBrush" Value="#D3DBE0"/>
          <Setter Property="Foreground" Value="#6B7782"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource ButtonBase}">
      <Setter Property="Background" Value="{StaticResource AccentBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
      <Setter Property="Foreground" Value="#FFFFFF"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#0A5563"/>
          <Setter Property="BorderBrush" Value="#0A5563"/>
        </Trigger>
        <Trigger Property="IsEnabled" Value="False">
          <Setter Property="Background" Value="#9DB9C0"/>
          <Setter Property="BorderBrush" Value="#9DB9C0"/>
          <Setter Property="Foreground" Value="#F4F8F9"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="ScanButtonStyle" TargetType="Button" BasedOn="{StaticResource PrimaryButton}">
      <Setter Property="Height" Value="36"/>
      <Setter Property="MinWidth" Value="110"/>
      <Setter Property="FontSize" Value="15"/>
    </Style>

    <Style x:Key="CleanTabs" TargetType="TabControl">
      <Setter Property="Background" Value="{StaticResource SurfaceBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabControl">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6">
              <Grid KeyboardNavigation.TabNavigation="Local">
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <Border Grid.Row="0" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,0,0,1" Padding="8,0,8,0">
                  <TabPanel IsItemsHost="True" Background="Transparent"/>
                </Border>
                <ContentPresenter Grid.Row="1" Content="{TemplateBinding SelectedContent}" ContentTemplate="{TemplateBinding SelectedContentTemplate}"/>
              </Grid>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="CleanTab" TargetType="TabItem">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderBrush" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0,0,0,3"/>
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="14,8,14,7"/>
      <Setter Property="Margin" Value="0,0,4,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" Padding="{TemplateBinding Padding}">
              <ContentPresenter Content="{TemplateBinding Header}" ContentTemplate="{TemplateBinding HeaderTemplate}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
        </Trigger>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
          <Setter Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="HeaderBase" TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="{StaticResource HeaderBrush}"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="10,6,10,6"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
    <Style x:Key="HeaderRight" TargetType="DataGridColumnHeader" BasedOn="{StaticResource HeaderBase}">
      <Setter Property="HorizontalContentAlignment" Value="Right"/>
    </Style>

    <Style x:Key="CellText" TargetType="TextBlock">
      <Setter Property="Margin" Value="10,0,10,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
    </Style>
    <Style x:Key="CellBold" TargetType="TextBlock" BasedOn="{StaticResource CellText}">
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="CellRight" TargetType="TextBlock" BasedOn="{StaticResource CellText}">
      <Setter Property="TextAlignment" Value="Right"/>
    </Style>
    <Style x:Key="CellWrap" TargetType="TextBlock" BasedOn="{StaticResource CellText}">
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Margin" Value="10,5,10,5"/>
    </Style>
    <Style x:Key="CellTrim" TargetType="TextBlock" BasedOn="{StaticResource CellText}">
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
    </Style>

    <Style x:Key="GridRow" TargetType="DataGridRow">
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#F0F5F7"/>
        </Trigger>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#D6EBEF"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="GridCell" TargetType="DataGridCell">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="Transparent"/>
          <Setter Property="BorderBrush" Value="Transparent"/>
          <Setter Property="Foreground" Value="{StaticResource InkBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="GridStyle" TargetType="DataGrid">
      <Setter Property="Background" Value="{StaticResource SurfaceBrush}"/>
      <Setter Property="RowBackground" Value="{StaticResource SurfaceBrush}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#E3E8EC"/>
      <Setter Property="SelectionMode" Value="Single"/>
      <Setter Property="SelectionUnit" Value="FullRow"/>
      <Setter Property="MinRowHeight" Value="36"/>
      <Setter Property="ColumnHeaderHeight" Value="36"/>
      <Setter Property="CanUserResizeRows" Value="False"/>
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
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Row 0: header band with the promise and the two drive gauges -->
    <Border Grid.Row="0" Background="{StaticResource BandBrush}" Padding="24,12,24,12">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Grid.Column="0" VerticalAlignment="Center" Margin="0,0,16,0">
          <TextBlock Text="Disk Space Triage" FontSize="24" FontWeight="SemiBold" Foreground="#FFFFFF"/>
          <TextBlock Text="Find. Understand. Fix." FontSize="14" Margin="0,1,0,0" Foreground="#A9DCE6"/>
          <TextBlock Text="Scanning only reads folder sizes. Nothing changes unless you allow it in the Fix tab." FontSize="11.5" Margin="0,3,0,0" TextWrapping="Wrap" Foreground="#C9D9DF"/>
        </StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
          <Border Width="290" Margin="0,0,12,0" Padding="12,8,12,9" Background="{StaticResource SurfaceBrush}" CornerRadius="6">
            <StackPanel>
              <Grid>
                <TextBlock Text="Source drive" FontSize="12" Margin="0" Foreground="{StaticResource MutedBrush}"/>
                <TextBlock x:Name="SourceDriveStatus" Text="-" FontSize="12" HorizontalAlignment="Right" FontWeight="SemiBold" Foreground="{StaticResource MutedBrush}"/>
              </Grid>
              <TextBlock x:Name="SourceDriveLabel" Text="-" Margin="0,3,0,0" FontSize="12.5" Foreground="{StaticResource InkBrush}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
              <ProgressBar x:Name="SourceDriveBar" Minimum="0" Maximum="100" Value="0" Height="8" Margin="0,6,0,0" BorderThickness="0" Background="{StaticResource TrackBrush}" Foreground="{StaticResource AccentBrush}"/>
            </StackPanel>
          </Border>
          <Border Width="290" Padding="12,8,12,9" Background="{StaticResource SurfaceBrush}" CornerRadius="6">
            <StackPanel>
              <Grid>
                <TextBlock Text="Destination drive" FontSize="12" Margin="0" Foreground="{StaticResource MutedBrush}"/>
                <TextBlock x:Name="DestDriveStatus" Text="-" FontSize="12" HorizontalAlignment="Right" FontWeight="SemiBold" Foreground="{StaticResource MutedBrush}"/>
              </Grid>
              <TextBlock x:Name="DestDriveLabel" Text="-" Margin="0,3,0,0" FontSize="12.5" Foreground="{StaticResource InkBrush}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
              <ProgressBar x:Name="DestDriveBar" Minimum="0" Maximum="100" Value="0" Height="8" Margin="0,6,0,0" BorderThickness="0" Background="{StaticResource TrackBrush}" Foreground="{StaticResource AccentBrush}"/>
            </StackPanel>
          </Border>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Row 1: controls -->
    <Grid Grid.Row="1" Margin="24,14,24,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
      </Grid.RowDefinitions>
      <StackPanel Grid.Row="0" Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Bottom">
        <StackPanel Margin="0,0,12,0">
          <TextBlock Text="Source drive" Style="{StaticResource FieldLabel}"/>
          <TextBox x:Name="SourceBox" Text="C" MaxLength="1" CharacterCasing="Upper" Width="56" TextAlignment="Center" Style="{StaticResource FieldBox}"/>
        </StackPanel>
        <StackPanel Margin="0,0,12,0">
          <TextBlock Text="Destination drive" Style="{StaticResource FieldLabel}"/>
          <TextBox x:Name="DestBox" Text="D" MaxLength="1" CharacterCasing="Upper" Width="56" TextAlignment="Center" Style="{StaticResource FieldBox}"/>
        </StackPanel>
        <StackPanel Margin="0,0,12,0">
          <TextBlock Text="Min file size (MB)" Style="{StaticResource FieldLabel}"/>
          <TextBox x:Name="MinSizeBox" Text="100" Width="84" TextAlignment="Right" Style="{StaticResource FieldBox}"/>
        </StackPanel>
      </StackPanel>
      <StackPanel Grid.Row="0" Grid.Column="1" VerticalAlignment="Bottom" Margin="0,0,16,0">
        <TextBlock Text="Extra folders to scan (optional, full paths, separated by ;)" Style="{StaticResource FieldLabel}" TextTrimming="CharacterEllipsis"/>
        <TextBox x:Name="ExtraRootsBox" Style="{StaticResource FieldBox}"/>
      </StackPanel>
      <StackPanel Grid.Row="0" Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Bottom">
        <Button x:Name="ScanButton" Content="Scan" Style="{StaticResource ScanButtonStyle}"/>
        <Button x:Name="CancelButton" Content="Cancel" IsEnabled="False" Style="{StaticResource PlainButton}" Height="36" MinWidth="84"/>
        <Button x:Name="ExportButton" Content="Export report" IsEnabled="False" Style="{StaticResource PlainButton}" Height="36" Margin="0"/>
      </StackPanel>
      <TextBlock x:Name="ProgressText" Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="3" Text="Pick your drives, then select Scan. Scanning only reads folder sizes." Margin="0,8,0,0" FontSize="13" FontWeight="SemiBold" Foreground="{StaticResource InkBrush}" TextTrimming="CharacterEllipsis"/>
    </Grid>

    <!-- Row 2: summary cards -->
    <Grid Grid.Row="2" Margin="24,14,24,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Border Grid.Column="0" Margin="0,0,8,0" Background="{StaticResource SurfaceBrush}" BorderBrush="{StaticResource LineBrush}" BorderThickness="1" CornerRadius="6">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Height="4" Background="{StaticResource RedirectBrush}" CornerRadius="5,5,0,0"/>
          <StackPanel Grid.Row="1" Margin="16,8,16,10">
            <TextBlock Text="Redirect" FontWeight="SemiBold" FontSize="14" Foreground="{StaticResource RedirectBrush}"/>
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="RedirectSize" Text="-" FontSize="24" FontWeight="SemiBold" Foreground="{StaticResource InkBrush}"/>
              <TextBlock x:Name="RedirectFiles" Text="0 files" VerticalAlignment="Bottom" Margin="10,0,0,4" Foreground="{StaticResource MutedBrush}"/>
            </StackPanel>
            <TextBlock Text="One setting stops it growing again." Margin="0,2,0,0" FontSize="12.5" TextTrimming="CharacterEllipsis" Foreground="{StaticResource InkBrush}"/>
          </StackPanel>
        </Grid>
      </Border>
      <Border Grid.Column="1" Margin="4,0,4,0" Background="{StaticResource SurfaceBrush}" BorderBrush="{StaticResource LineBrush}" BorderThickness="1" CornerRadius="6">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Height="4" Background="{StaticResource DeleteBrush}" CornerRadius="5,5,0,0"/>
          <StackPanel Grid.Row="1" Margin="16,8,16,10">
            <TextBlock Text="Delete" FontWeight="SemiBold" FontSize="14" Foreground="{StaticResource DeleteBrush}"/>
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="DeleteSize" Text="-" FontSize="24" FontWeight="SemiBold" Foreground="{StaticResource InkBrush}"/>
              <TextBlock x:Name="DeleteFiles" Text="0 files" VerticalAlignment="Bottom" Margin="10,0,0,4" Foreground="{StaticResource MutedBrush}"/>
            </StackPanel>
            <TextBlock Text="Rebuilds itself. Delete it, never copy it." Margin="0,2,0,0" FontSize="12.5" TextTrimming="CharacterEllipsis" Foreground="{StaticResource InkBrush}"/>
          </StackPanel>
        </Grid>
      </Border>
      <Border Grid.Column="2" Margin="8,0,0,0" Background="{StaticResource SurfaceBrush}" BorderBrush="{StaticResource LineBrush}" BorderThickness="1" CornerRadius="6">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Height="4" Background="{StaticResource MoveBrush}" CornerRadius="5,5,0,0"/>
          <StackPanel Grid.Row="1" Margin="16,8,16,10">
            <TextBlock Text="Move" FontWeight="SemiBold" FontSize="14" Foreground="{StaticResource MoveBrush}"/>
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="MoveSize" Text="-" FontSize="24" FontWeight="SemiBold" Foreground="{StaticResource InkBrush}"/>
              <TextBlock x:Name="MoveFiles" Text="0 files" VerticalAlignment="Bottom" Margin="10,0,0,4" Foreground="{StaticResource MutedBrush}"/>
            </StackPanel>
            <TextBlock Text="Copy, check, then delete the original." Margin="0,2,0,0" FontSize="12.5" TextTrimming="CharacterEllipsis" Foreground="{StaticResource InkBrush}"/>
          </StackPanel>
        </Grid>
      </Border>
    </Grid>

    <!-- Row 3: tabs -->
    <TabControl x:Name="MainTabs" Grid.Row="3" Margin="24,14,24,0" Style="{StaticResource CleanTabs}" ItemContainerStyle="{StaticResource CleanTab}">
      <TabItem Header="Do these first">
        <DataGrid x:Name="MechanismsGrid" Style="{StaticResource GridStyle}" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" HeadersVisibility="Column" GridLinesVisibility="Horizontal">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Size" Binding="{Binding SizeText, Mode=OneWay}" SortMemberPath="TotalBytes" Width="110" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
            <DataGridTextColumn Header="Type" Binding="{Binding Bucket, Mode=OneWay}" Width="90" ElementStyle="{StaticResource CellBold}"/>
            <DataGridTextColumn Header="What to do" Binding="{Binding Mechanism, Mode=OneWay}" Width="2*" MinWidth="240" ElementStyle="{StaticResource CellWrap}"/>
            <DataGridTextColumn Header="What it is" Binding="{Binding Note, Mode=OneWay}" Width="2*" MinWidth="240" ElementStyle="{StaticResource CellWrap}"/>
            <DataGridTextColumn Header="Files" Binding="{Binding FilesText, Mode=OneWay}" SortMemberPath="Files" Width="90" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>

      <TabItem Header="Fix with one setting">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Margin="12,12,12,10" Padding="14,8,14,8" Background="#FFF3D1" BorderBrush="#C8962B" BorderThickness="4,1,1,1" CornerRadius="6">
            <StackPanel>
              <TextBlock TextWrapping="Wrap" FontSize="12.5" Foreground="{StaticResource InkBrush}" Text="The tool can set a user environment variable so a cache is stored on the other drive from now on. It creates an empty folder there and sets the variable. It does not move or delete anything: the old folder stays where it is, and the tool tells you what to do with it. Each change asks for confirmation and can be undone until you close this window."/>
              <CheckBox x:Name="EnableActionsBox" Content="Allow this tool to make these changes" IsChecked="False" Margin="0,8,0,0" FontWeight="SemiBold" Foreground="{StaticResource InkBrush}"/>
            </StackPanel>
          </Border>
          <DataGrid x:Name="RedirectGrid" Grid.Row="1" Style="{StaticResource GridStyle}" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" HeadersVisibility="Column" GridLinesVisibility="Horizontal" SelectionMode="Single">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Size now" Binding="{Binding SizeText, Mode=OneWay}" SortMemberPath="SizeBytes" Width="100" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
              <DataGridTextColumn Header="Variable" Binding="{Binding Variable, Mode=OneWay}" Width="150" ElementStyle="{StaticResource CellBold}"/>
              <DataGridTextColumn Header="New folder" Binding="{Binding ProposedValue, Mode=OneWay}" Width="3*" MinWidth="300" ElementStyle="{StaticResource CellWrap}"/>
              <DataGridTextColumn Header="Status" Binding="{Binding StatusText, Mode=OneWay}" Width="120" ElementStyle="{StaticResource CellWrap}"/>
              <DataGridTextColumn Header="What happens" Binding="{Binding Effect, Mode=OneWay}" Width="2*" MinWidth="260" ElementStyle="{StaticResource CellWrap}"/>
            </DataGrid.Columns>
          </DataGrid>
          <Grid Grid.Row="2" Margin="12,10,12,10">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="300"/>
            </Grid.ColumnDefinitions>
            <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Top">
              <Button x:Name="ApplyRedirectButton" Content="Apply selected..." IsEnabled="False" Style="{StaticResource PrimaryButton}"/>
              <Button x:Name="UndoRedirectButton" Content="Undo last change" IsEnabled="False" Style="{StaticResource PlainButton}" Margin="0,0,16,0"/>
            </StackPanel>
            <TextBlock x:Name="RedirectMessage" Grid.Column="1" TextWrapping="Wrap" VerticalAlignment="Center" FontSize="12.5" Foreground="{StaticResource InkBrush}"/>
          </Grid>
        </Grid>
      </TabItem>

      <TabItem Header="Largest files">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="12,10,12,10">
            <TextBlock Text="Show type" VerticalAlignment="Center" Margin="0,0,10,0" Foreground="{StaticResource MutedBrush}"/>
            <ComboBox x:Name="BucketFilter" Width="140" Height="28" SelectedIndex="0">
              <ComboBoxItem Content="All"/>
              <ComboBoxItem Content="Redirect"/>
              <ComboBoxItem Content="Delete"/>
              <ComboBoxItem Content="Move"/>
              <ComboBoxItem Content="Review"/>
              <ComboBoxItem Content="Never"/>
            </ComboBox>
            <TextBlock x:Name="FilesCountText" Text="" VerticalAlignment="Center" Margin="16,0,0,0" Foreground="{StaticResource MutedBrush}"/>
          </StackPanel>
          <DataGrid x:Name="FilesGrid" Grid.Row="1" Style="{StaticResource GridStyle}" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" HeadersVisibility="Column" GridLinesVisibility="Horizontal">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Size" Binding="{Binding SizeText, Mode=OneWay}" SortMemberPath="SizeBytes" Width="100" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
              <DataGridTextColumn Header="Type" Binding="{Binding Bucket, Mode=OneWay}" Width="80" ElementStyle="{StaticResource CellBold}"/>
              <DataGridTextColumn Header="What to do" Binding="{Binding Mechanism, Mode=OneWay}" Width="190" ElementStyle="{StaticResource CellTrim}"/>
              <DataGridTextColumn Header="Idle days" Binding="{Binding DaysIdle, Mode=OneWay}" Width="80" ElementStyle="{StaticResource CellRight}" HeaderStyle="{StaticResource HeaderRight}"/>
              <DataGridTextColumn Header="Last write" Binding="{Binding LastWrite, Mode=OneWay}" Width="100" ElementStyle="{StaticResource CellText}"/>
              <DataGridTextColumn Header="Path" Binding="{Binding Path, Mode=OneWay}" Width="*" MinWidth="240" ElementStyle="{StaticResource CellTrim}"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>

      <TabItem Header="Largest folders">
        <DataGrid x:Name="FoldersGrid" Style="{StaticResource GridStyle}" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" HeadersVisibility="Column" GridLinesVisibility="Horizontal">
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
          <TextBlock Grid.Row="0" Margin="12,10,12,10" TextWrapping="Wrap" Foreground="{StaticResource MutedBrush}" Text="This tool does not measure these items because they need administrator rights. Check each one yourself."/>
          <DataGrid x:Name="ElevatedGrid" Grid.Row="1" Style="{StaticResource GridStyle}" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" HeadersVisibility="Column" GridLinesVisibility="Horizontal">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Item" Binding="{Binding Item, Mode=OneWay}" Width="220" ElementStyle="{StaticResource CellWrap}"/>
              <DataGridTextColumn Header="Action" Binding="{Binding Action, Mode=OneWay}" Width="*" MinWidth="240" ElementStyle="{StaticResource CellWrap}"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
    </TabControl>

    <!-- Row 4: status bar -->
    <Border Grid.Row="4" Margin="0,12,0,0" Background="{StaticResource SurfaceBrush}" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,1,0,0" Padding="24,6,24,6">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock x:Name="RootsText" Grid.Column="0" Text="Scanned roots: 0" VerticalAlignment="Center" Margin="0,0,24,0" FontSize="12" Foreground="{StaticResource MutedBrush}"/>
        <TextBlock x:Name="DeniedText" Grid.Column="1" Text="Unreadable locations skipped: 0" VerticalAlignment="Center" Margin="0,0,24,0" FontSize="12" Foreground="{StaticResource MutedBrush}"/>
        <TextBlock Grid.Column="2" Text="Last export" VerticalAlignment="Center" Margin="0,0,8,0" FontSize="12" Foreground="{StaticResource MutedBrush}"/>
        <TextBox x:Name="ExportPathBox" Grid.Column="3" IsReadOnly="True" Height="26" VerticalContentAlignment="Center" BorderBrush="{StaticResource LineBrush}" Background="#F6F8F9" Margin="0,0,8,0"/>
        <Button x:Name="CopyPathButton" Grid.Column="4" Content="Copy path" Style="{StaticResource PlainButton}" Height="26" MinWidth="84" Margin="0" Padding="12,0,12,0"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

function Initialize-TriageGui {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
}

function Get-TriageControlNames {
    return @(
        'SourceDriveLabel', 'SourceDriveBar', 'SourceDriveStatus',
        'DestDriveLabel', 'DestDriveBar', 'DestDriveStatus',
        'SourceBox', 'DestBox', 'MinSizeBox',
        'ScanButton', 'CancelButton', 'ExportButton', 'ProgressText',
        'RedirectSize', 'RedirectFiles', 'DeleteSize', 'DeleteFiles', 'MoveSize', 'MoveFiles',
        'MainTabs', 'MechanismsGrid', 'BucketFilter', 'FilesCountText', 'FilesGrid', 'FoldersGrid', 'ElevatedGrid',
        'RootsText', 'DeniedText', 'ExportPathBox', 'CopyPathButton',
        'ExtraRootsBox', 'EnableActionsBox', 'RedirectGrid', 'ApplyRedirectButton', 'UndoRedirectButton', 'RedirectMessage'
    )
}

function New-TriageWindow {
    $window = [System.Windows.Markup.XamlReader]::Parse($script:TriageXaml)
    $controls = @{}
    foreach ($name in (Get-TriageControlNames)) {
        $controls[$name] = $window.FindName($name)
    }
    return @{ Window = $window; Controls = $controls }
}

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

function Set-TriageCard {
    param($Result, [string]$Bucket, $SizeCtl, $FilesCtl)
    $entry = $null
    foreach ($b in @($Result.Buckets)) {
        if ([string]$b.Bucket -eq $Bucket) { $entry = $b }
    }
    if ($null -eq $entry) {
        $SizeCtl.Text = Format-Size -Bytes 0.0
        $FilesCtl.Text = '0 files'
        return
    }
    $SizeCtl.Text = Format-Size -Bytes ([double]$entry.TotalBytes)
    $FilesCtl.Text = ('{0:N0} files' -f [long]$entry.Files)
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

function Update-TriageRedirectButtons {
    param([Parameter(Mandatory = $true)][hashtable]$Ui)
    $c = $Ui.Controls
    $on = ($c['EnableActionsBox'].IsChecked -eq $true) -and (-not $script:TriageScanning)
    $canApply = $false
    $selected = $c['RedirectGrid'].SelectedItem
    if ($on -and $null -ne $selected) {
        if ([string]$selected.State -eq 'Ready') { $canApply = $true }
    }
    $canUndo = $false
    if ($on -and $null -ne $script:TriageRedirectHistory -and $script:TriageRedirectHistory.Count -gt 0) { $canUndo = $true }
    $c['ApplyRedirectButton'].IsEnabled = $canApply
    $c['UndoRedirectButton'].IsEnabled = $canUndo
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
        $state = [string]$p.State
        $reason = [string]$p.Reason
        $status = $state
        if ($state -eq 'Ready') {
            $status = 'Ready'
            if ($reason.Length -gt 0) { $status = 'Ready (' + $reason + ')' }
        }
        elseif ($state -eq 'AlreadySet') {
            $status = 'Already set: ' + [string]$p.CurrentValue
        }
        elseif ($state -eq 'Blocked') {
            $status = 'Not possible: ' + $reason
        }
        $rows.Add([pscustomobject]@{
            Variable      = [string]$p.Variable
            SizeText      = (Format-Size -Bytes ([double]$p.SizeBytes))
            SizeBytes     = [long]$p.SizeBytes
            ProposedValue = [string]$p.ProposedValue
            Effect        = [string]$p.Effect
            OldFolder     = [string]$p.OldFolder
            SourceFolder  = [string]$p.SourceFolder
            State         = $state
            StatusText    = $status
            Reason        = $reason
            CurrentValue  = [string]$p.CurrentValue
        })
    }
    $c['RedirectGrid'].ItemsSource = $rows
    if ($plan.Count -eq 0) {
        if ($problem.Length -gt 0) {
            $c['RedirectMessage'].Text = ('Could not work out the possible fixes: ' + $problem)
        }
        else {
            $c['RedirectMessage'].Text = 'The scan found no cache that one setting can redirect.'
        }
    }
    Update-TriageRedirectButtons -Ui $Ui
}

function Update-TriageWindow {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Ui,
        [Parameter(Mandatory = $true)]$Result
    )
    $c = $Ui.Controls
    $w = $Ui.Window

    # Drive status
    Set-TriageDriveBlock -Window $w -LabelCtl $c['SourceDriveLabel'] -BarCtl $c['SourceDriveBar'] -StatusCtl $c['SourceDriveStatus'] -Facts $Result.Source -Status ([string]$Result.Status) -MissingText 'Source drive not found'
    $dest = $Result.Destination
    $destStatus = 'UNKNOWN'
    if ($null -ne $dest) { $destStatus = [string](Get-PressureStatus -Facts $dest) }
    Set-TriageDriveBlock -Window $w -LabelCtl $c['DestDriveLabel'] -BarCtl $c['DestDriveBar'] -StatusCtl $c['DestDriveStatus'] -Facts $dest -Status $destStatus -MissingText 'Destination drive not found'

    # Summary cards
    Set-TriageCard -Result $Result -Bucket 'Redirect' -SizeCtl $c['RedirectSize'] -FilesCtl $c['RedirectFiles']
    Set-TriageCard -Result $Result -Bucket 'Delete' -SizeCtl $c['DeleteSize'] -FilesCtl $c['DeleteFiles']
    Set-TriageCard -Result $Result -Bucket 'Move' -SizeCtl $c['MoveSize'] -FilesCtl $c['MoveFiles']

    # Mechanisms
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

    # Fix with one setting
    $c['RedirectMessage'].Text = ''
    Update-TriageRedirectGrid -Ui $Ui -Result $Result

    # Files (honours the current bucket filter)
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

function Invoke-TriageGuiScan {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    $src = ([string]$c['SourceBox'].Text).Trim()
    $dst = ([string]$c['DestBox'].Text).Trim()
    $minText = ([string]$c['MinSizeBox'].Text).Trim()

    if ($src -notmatch '^[A-Za-z]$') {
        [void][System.Windows.MessageBox]::Show('Source drive must be a single letter, for example C.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    if ($dst -notmatch '^[A-Za-z]$') {
        [void][System.Windows.MessageBox]::Show('Destination drive must be a single letter, for example D.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    if ($src.ToUpper() -eq $dst.ToUpper()) {
        [void][System.Windows.MessageBox]::Show('Source and destination must be different drives.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    if ($minText -notmatch '^[0-9]{1,7}$' -or [int]$minText -lt 1 -or [int]$minText -gt 1048576) {
        [void][System.Windows.MessageBox]::Show('Min file size must be a whole number of megabytes between 1 and 1048576.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
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
    $c['ScanButton'].IsEnabled = $false
    $c['CancelButton'].IsEnabled = $true
    # Nothing else may be started while the scan runs.
    $c['ExportButton'].IsEnabled = $false
    $c['ApplyRedirectButton'].IsEnabled = $false
    $c['UndoRedirectButton'].IsEnabled = $false
    $script:TriageScanning = $true
    $c['ProgressText'].Text = 'Starting scan...'

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
        $c['ExportButton'].IsEnabled = $true
        if ($result.Cancelled) {
            $c['ProgressText'].Text = 'Cancelled. Showing partial results. Scan again to see everything.'
        }
        else {
            $c['ProgressText'].Text = ('Done. {0:N0} files scanned, {1} seen. Start with the first row of "Do these first", then choose Export report.' -f [long]$result.ScannedFiles, (Format-Size -Bytes ([double]$result.ScannedBytes)))
        }
    }
    catch {
        $msg = $_.Exception.Message
        $c['ProgressText'].Text = 'Scan failed.'
        [void][System.Windows.MessageBox]::Show(('The scan failed: ' + $msg), $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    finally {
        $script:TriageScanning = $false
        $c['ScanButton'].IsEnabled = $true
        $c['CancelButton'].IsEnabled = $false
        if ($null -ne $script:TriageLastResult) { $c['ExportButton'].IsEnabled = $true }
        Update-TriageRedirectButtons -Ui $ui
    }
}

function Invoke-TriageGuiExport {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    if ($null -eq $script:TriageLastResult) {
        [void][System.Windows.MessageBox]::Show('Run a scan first, then export the report.', $caption, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
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

function Invoke-TriageGuiApplyRedirect {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    if ($c['EnableActionsBox'].IsChecked -ne $true) {
        $c['RedirectMessage'].Text = 'Not changed: tick "Allow this tool to make these changes" first.'
        return
    }
    $selected = $c['RedirectGrid'].SelectedItem
    if ($null -eq $selected) {
        $c['RedirectMessage'].Text = 'Not changed: select a row first.'
        return
    }
    $planItem = $null
    foreach ($p in @($script:TriageRedirectPlan)) {
        if ([string]$p.Variable -ceq [string]$selected.Variable) { $planItem = $p }
    }
    if ($null -eq $planItem) {
        $c['RedirectMessage'].Text = 'Not changed: that row is no longer in the plan. Scan again.'
        return
    }
    if ([string]$planItem.State -ne 'Ready') {
        $c['RedirectMessage'].Text = 'Not changed: this one cannot be set right now. See the Status column.'
        return
    }

    $lines = @(
        ('Variable: ' + [string]$planItem.Variable),
        ('New folder: ' + [string]$planItem.ProposedValue),
        ('Old folder (stays as it is): ' + [string]$planItem.SourceFolder),
        '',
        'Nothing will be moved or deleted.',
        [string]$planItem.Effect,
        '',
        'The new folder is outside your user profile. On a shared computer, other users of this PC may be able to read or change it. If the drive is external, keep it connected.',
        '',
        "You can undo this with 'Undo last change' until you close this window.",
        '',
        'Make this change?'
    )
    $text = ($lines -join "`n")
    $answer = [System.Windows.MessageBox]::Show($text, $caption, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question, [System.Windows.MessageBoxResult]::No)
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

    if ($null -ne $script:TriageLastResult) {
        Update-TriageRedirectGrid -Ui $ui -Result $script:TriageLastResult
    }
    $message = ('{0} now points to {1}. Close and reopen your terminals and apps (or sign out and in) so they see it. The old folder is still at {2}. {3}' -f [string]$record.Variable, [string]$record.NewValue, [string]$planItem.SourceFolder, [string]$planItem.OldFolder)
    if (([string]$record.LogPath).Length -gt 0) {
        $message = $message + ' Change log: ' + [string]$record.LogPath
    } else {
        $message = $message + ' Note: this change could NOT be written to the change log (is the file open in another program?).'
    }
    $c['RedirectMessage'].Text = $message
    Update-TriageRedirectButtons -Ui $ui
}

function Invoke-TriageGuiUndoRedirect {
    $ui = $script:TriageUi
    $c = $ui.Controls
    $caption = 'Disk Space Triage'
    $count = $script:TriageRedirectHistory.Count
    if ($count -le 0) {
        $c['RedirectMessage'].Text = 'There is nothing to undo in this session.'
        return
    }
    $record = $script:TriageRedirectHistory[$count - 1]
    $lines = @(
        ('Undo the change to ' + [string]$record.Variable + '?'),
        '',
        ('The variable will be removed again. The folder ' + [string]$record.NewValue + ' stays where it is; anything downloaded into it since stays there too.'),
        '',
        'Undo this change?'
    )
    $text = ($lines -join "`n")
    $answer = [System.Windows.MessageBox]::Show($text, $caption, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question, [System.Windows.MessageBoxResult]::No)
    if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
        $c['RedirectMessage'].Text = 'Not undone: you chose No.'
        return
    }

    $undo = $null
    $failure = ''
    try {
        $undo = Undo-TriageRedirect -Record $record -LogDirectory $script:TriageGuiReportDir
        $script:TriageRedirectHistory.RemoveAt($count - 1)
    }
    catch {
        $failure = $_.Exception.Message
    }
    if ($failure.Length -gt 0) {
        # A record that can no longer be undone must not block the ones before it.
        $script:TriageRedirectHistory.RemoveAt($count - 1)
        $c['RedirectMessage'].Text = ('Not undone: ' + $failure + ' To remove it yourself: Settings > System > About > Advanced system settings > Environment Variables, under User variables.')
        Update-TriageRedirectButtons -Ui $ui
        return
    }

    if ($null -ne $script:TriageLastResult) {
        Update-TriageRedirectGrid -Ui $ui -Result $script:TriageLastResult
    }
    $message = ('{0} is no longer set. Close and reopen your terminals and apps so they see it. The folder {1} was left in place.' -f [string]$record.Variable, [string]$record.NewValue)
    if (([string]$undo.LogPath).Length -gt 0) { $message = $message + ' Change log: ' + [string]$undo.LogPath }
    $c['RedirectMessage'].Text = $message
    Update-TriageRedirectButtons -Ui $ui
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
    $script:TriageRedirectHistory = New-Object 'System.Collections.Generic.List[object]'
    $c = $ui.Controls

    $c['SourceBox'].Text = [string]$SourceDrive
    $c['DestBox'].Text = [string]$DestinationDrive

    # Initial drive status before any scan
    try {
        $srcFacts = Get-DriveFacts -Letter $SourceDrive
        $srcStatus = 'UNKNOWN'
        if ($null -ne $srcFacts) { $srcStatus = [string](Get-PressureStatus -Facts $srcFacts) }
        Set-TriageDriveBlock -Window $ui.Window -LabelCtl $c['SourceDriveLabel'] -BarCtl $c['SourceDriveBar'] -StatusCtl $c['SourceDriveStatus'] -Facts $srcFacts -Status $srcStatus -MissingText 'Source drive not found'
        $dstFacts = Get-DriveFacts -Letter $DestinationDrive
        $dstStatus = 'UNKNOWN'
        if ($null -ne $dstFacts) { $dstStatus = [string](Get-PressureStatus -Facts $dstFacts) }
        Set-TriageDriveBlock -Window $ui.Window -LabelCtl $c['DestDriveLabel'] -BarCtl $c['DestDriveBar'] -StatusCtl $c['DestDriveStatus'] -Facts $dstFacts -Status $dstStatus -MissingText 'Destination drive not found'
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
    $c['BucketFilter'].Add_SelectionChanged({
        if ($null -ne $script:TriageLastResult) {
            Set-TriageFilesGrid -Ui $script:TriageUi -Result $script:TriageLastResult -Bucket (Get-TriageSelectedBucket -Ui $script:TriageUi)
        }
    })
    $c['ApplyRedirectButton'].Add_Click({ Invoke-TriageGuiApplyRedirect })
    $c['UndoRedirectButton'].Add_Click({ Invoke-TriageGuiUndoRedirect })
    $c['EnableActionsBox'].Add_Checked({ Update-TriageRedirectButtons -Ui $script:TriageUi })
    $c['EnableActionsBox'].Add_Unchecked({ Update-TriageRedirectButtons -Ui $script:TriageUi })
    $c['RedirectGrid'].Add_SelectionChanged({ Update-TriageRedirectButtons -Ui $script:TriageUi })
    Update-TriageRedirectButtons -Ui $ui
    $ui.Window.Add_Closing({ $script:TriageCancel = $true })

    [void]$ui.Window.ShowDialog()
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

function Test-TriageGui {
    param([Parameter(Mandatory = $true)][string]$OutputPath)
    Initialize-TriageGui
    $script:TriageRedirectPlan = @()
    $script:TriageRedirectHistory = New-Object 'System.Collections.Generic.List[object]'
    $ui = New-TriageWindow

    foreach ($name in (Get-TriageControlNames)) {
        if (-not $ui.Controls.ContainsKey($name) -or $null -eq $ui.Controls[$name]) {
            throw ('GUI self-test: control not found in XAML: ' + $name)
        }
    }

    Update-TriageWindow -Ui $ui -Result (Get-SampleTriageResult)

    if ($ui.Controls['MechanismsGrid'].Items.Count -le 0) { throw 'GUI self-test: MechanismsGrid has no items.' }
    if ($ui.Controls['FilesGrid'].Items.Count -le 0) { throw 'GUI self-test: FilesGrid has no items.' }
    if ($ui.Controls['RedirectGrid'].Items.Count -le 0) { throw 'GUI self-test: RedirectGrid has no items.' }

    $w = $ui.Window
    $size = New-Object System.Windows.Size -ArgumentList @(1100.0, 700.0)
    $rect = New-Object System.Windows.Rect -ArgumentList @(0.0, 0.0, 1100.0, 700.0)
    $w.Measure($size)
    $w.Arrange($rect)
    $w.UpdateLayout()
    $root = $w.Content

    # One picture per tab that matters: the findings, and the only tab that
    # can change anything.
    $fixPath = $OutputPath
    if ($OutputPath.EndsWith('.png', [System.StringComparison]::OrdinalIgnoreCase)) {
        $fixPath = $OutputPath.Substring(0, $OutputPath.Length - 4) + '-fix.png'
    } else {
        $fixPath = $OutputPath + '-fix.png'
    }
    $shots = @(
        [pscustomobject]@{ Tab = 0; Path = $OutputPath }
        [pscustomobject]@{ Tab = 1; Path = $fixPath }
    )
    foreach ($shot in $shots) {
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
    Write-Host 'No changes were made to your system. Review the report, then act yourself.' -ForegroundColor Yellow
    return
}

Show-TriageWindow -SourceDrive $SourceDrive -DestinationDrive $DestinationDrive
#endregion
