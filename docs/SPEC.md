# Classification specification (frozen contract, revision 3)

This document is the single source of truth for how the tool classifies a file
path. The implementation and the test oracle are both derived from it,
independently. It describes policy only; it contains no matching patterns.

## Buckets

| Bucket | Meaning |
| --- | --- |
| Redirect | A tool owns this store. Change the tool's setting or environment variable so it lives on another drive. |
| Move | Human-owned or tool-relocatable data. Copy, verify, delete the original (through the owning tool where one exists). |
| Delete | Regenerates or is reproducible. Never copied to another drive. |
| Never | Registry-bound, system state, or application configuration. Left in place. |
| Review | Nothing in this specification applies. |

## Inputs and matching semantics

* Input is one absolute Windows file path (drive letter form, e.g. `C:\...`). Matching is case-insensitive.
* `<profile>` means a user profile directory, `X:\Users\<name>`, for any single directory name (`Public` and `Default` included).
* Classification depends on the path only, never on file contents.
* The **extension** of a file is the text from the last `.` in its name, provided that `.` is not the first character of the name. `data.tar.gz` has extension `.gz`; `.csv` and `README` have none.

## Where a store is recognised

* A location written `X:\...` is recognised only there: directly at a drive root, on any drive letter.
* A location written `<profile>\rest` is recognised **wherever the directory sequence `rest` appears in a path**, on any drive. Profiles get relocated and tools get installed for all users, so `C:\ProgramData\anaconda3\pkgs` and `D:\work\.cache\huggingface` are the same stores as their profile-level defaults. The names must match whole directory names.
* Exceptions that must sit **directly inside a profile**: the cloud-sync roots (section 9a) and the known folders (section 13). `D:\Downloads` and `<profile>\Projects\Documents` are not known folders.
* A row that names a directory generically ("a `wandb` directory", "inside a `node_modules` directory") is recognised anywhere, as a whole directory name. `node_modules_backup` is not `node_modules`.
* A store row covers every file under the store unless the row names a file type.

## Precedence

When more than one row applies, the first applicable tier wins:

1. **Protected system locations** (section 1). These are anchored at the drive root: `X:\Windows\...` is protected, a folder that merely contains a directory named `Windows` deeper in the path (for example `<profile>\AppData\Local\Microsoft\Windows\...`) is not.
2. **Named stores** (sections 2 to 10, except 9a and the file-keyed rows). If two named stores apply, the deeper (more specific) one wins. Example: the Steam shader cache inside a Steam library is Delete, not Move. A named store also wins over a reproducible artefact inside it: `node_modules` inside a Steam game or a VS Code extension belongs to that store.
2b. **File-keyed rows** (virtual disks in section 5, `.dmp` in section 10): they apply only when no named store from tier 2 applies, and they win over every later tier.
3. **Reproducible artefacts** (section 11) win over cloud-sync roots, known folders and install paths that contain them. Example: `node_modules` under Downloads is Delete.
4. **Cloud-sync roots** (section 9a) win over known folders inside them. Example: `<profile>\OneDrive\Documents\x.docx` is Never.
5. **Install paths** (section 12).
6. **Known folders** (section 13).
7. **Generic fallbacks** (section 14).
8. **File-type fallback** (section 15), then **Review**.

Within one tier, when the "deeper wins" rule does not decide, the first applicable row in table order wins.

## 1. Protected system locations

| Location | Bucket |
| --- | --- |
| `X:\Windows\` and everything under it (Installer, WinSxS, System32\DriverStore, Prefetch, Temp included) | Never |
| `X:\System Volume Information\` (drive root only) | Never |
| `X:\$Recycle.Bin\` (drive root only) | Delete |

## 2. Python and data-science toolchain

| Store | Default location | Bucket |
| --- | --- | --- |
| pip cache | `<profile>\AppData\Local\pip\Cache` | Redirect |
| uv cache | `<profile>\AppData\Local\uv` | Redirect |
| Poetry cache and virtualenvs | `<profile>\AppData\Local\pypoetry` | Redirect |
| conda package cache | `<profile>\anaconda3\pkgs`, `<profile>\miniconda3\pkgs`, `<profile>\AppData\Local\conda` | Redirect |
| conda environments | `<profile>\anaconda3\envs`, `<profile>\miniconda3\envs` | Delete (recreate elsewhere) |

## 3. ML and AI model stores

| Store | Default location | Bucket |
| --- | --- | --- |
| Hugging Face cache | `<profile>\.cache\huggingface` | Redirect |
| PyTorch hub cache | `<profile>\.cache\torch` | Redirect |
| Keras | `<profile>\.keras` | Redirect |
| TensorFlow Datasets | `<profile>\tensorflow_datasets` | Redirect |
| NLTK data | `<profile>\AppData\Roaming\nltk_data`, `<profile>\nltk_data` | Redirect |
| Ollama models | `<profile>\.ollama\models` | Redirect |
| LM Studio models | `<profile>\.lmstudio\models` | Redirect |
| Triton cache | `<profile>\.triton` | Redirect |
| Weights & Biases | a `wandb` directory that is not inside a `site-packages` directory (there it is the installed Python package, not run data) | Redirect |
| DVC cache | `.dvc\cache` inside a project | Redirect |
| MLflow runs | an `mlruns` directory (also when nested inside a `wandb` directory: deeper wins) | Move |

## 4. Package managers and developer tools

| Store | Default location | Bucket |
| --- | --- | --- |
| npm cache | `<profile>\AppData\Local\npm-cache` | Redirect |
| Yarn cache | `<profile>\AppData\Local\Yarn\Cache` | Redirect |
| pnpm store | `<profile>\AppData\Local\pnpm-store` | Redirect |
| NuGet packages | `<profile>\.nuget\packages` | Redirect |
| Maven repository | `<profile>\.m2\repository` | Redirect |
| Gradle | `<profile>\.gradle` | Redirect |
| Cargo | `<profile>\.cargo` | Redirect |
| Go module cache | `<profile>\go\pkg\mod` | Redirect |
| Composer cache | `<profile>\AppData\Local\Composer` | Redirect |
| RubyGems | `<profile>\.gem` | Redirect |
| Scoop apps | `<profile>\scoop\apps` | Redirect |
| Android SDK | `<profile>\AppData\Local\Android\Sdk` | Redirect |
| Android emulator images | `<profile>\.android\avd` | Redirect |
| VS Code extensions | `<profile>\.vscode\extensions` | Redirect |
| Unity caches | `<profile>\AppData\Local\Unity\caches` | Redirect |
| Unreal derived data cache | `<profile>\AppData\Local\UnrealEngine\Common\DerivedDataCache` | Redirect |
| Vagrant boxes | `<profile>\.vagrant.d` | Redirect |
| Visual Studio package cache | `X:\ProgramData\Microsoft\VisualStudio\Packages` | Delete |

## 5. Containers and virtual machines

| Store | Default location | Bucket |
| --- | --- | --- |
| Docker Desktop data | `<profile>\AppData\Local\Docker` | Redirect |
| WSL distribution disk | any `.vhdx` file under `<profile>\AppData\Local\Packages\<any package>\LocalState` | Redirect |
| Hyper-V machines | `X:\ProgramData\Microsoft\Windows\Hyper-V`, `X:\Users\Public\Documents\Hyper-V` | Move |
| VirtualBox machines | `<profile>\VirtualBox VMs` | Move |
| VMware machines | `<profile>\Documents\Virtual Machines` | Move |
| Any other virtual disk (`.vhdx`, `.vhd`, `.vmdk`, `.vdi`) | anywhere (file-keyed, tier 2b) | Move |

## 6. Games

| Store | Default location | Bucket |
| --- | --- | --- |
| Steam library | a `steamapps` directory (commonly `X:\Program Files (x86)\Steam\steamapps`) | Move |
| Steam shader cache, interrupted downloads | `steamapps\shadercache`, `steamapps\downloading` | Delete |
| Epic Games | `X:\Program Files\Epic Games`, `X:\Program Files (x86)\Epic Games` | Move |
| GOG Galaxy games | `X:\Program Files (x86)\GOG Galaxy\Games` | Move |
| Battle.net, Ubisoft | `X:\Program Files (x86)\Battle.net`, `X:\Program Files (x86)\Ubisoft` | Move |
| Microsoft Store / Xbox apps | `X:\Program Files\WindowsApps` | Move |
| Minecraft Java | `<profile>\AppData\Roaming\.minecraft` | Redirect |
| GPU shader caches | `<profile>\AppData\Local\NVIDIA\DXCache`, `<profile>\AppData\Local\AMD\DxCache`, `<profile>\AppData\Local\D3DSCache` | Delete |
| Game saves | `<profile>\Documents\My Games`, `<profile>\Saved Games` | Move |

## 7. Creative and media

| Store | Default location | Bucket |
| --- | --- | --- |
| Adobe media cache | `<profile>\AppData\Roaming\Adobe\Common\Media Cache Files`, `<profile>\AppData\Roaming\Adobe\Common\Media Cache` | Redirect |
| Camera Raw cache | `<profile>\AppData\Local\Adobe\CameraRaw\Cache` | Redirect |
| Lightroom previews | a `... Previews.lrdata` directory | Move |
| DaVinci Resolve cache | `<profile>\AppData\Roaming\Blackmagic Design`, `<profile>\AppData\Local\Blackmagic Design` (the installed program under Program Files is section 12) | Redirect |
| Office document cache | `<profile>\AppData\Local\Microsoft\Office\<version>\OfficeFileCache` | Delete |
| Plex Media Server data | `<profile>\AppData\Local\Plex Media Server` | Move |
| Spotify offline storage | `<profile>\AppData\Local\Spotify\Storage` | Redirect |
| iTunes media | `<profile>\Music\iTunes\iTunes Media` | Redirect |

## 8. Communication

| Store | Default location | Bucket |
| --- | --- | --- |
| Outlook offline mailbox | `.ost` files only, under `<profile>\AppData\Local\Microsoft\Outlook` (other files there fall through to later tiers) | Redirect |
| Outlook archives | `<profile>\Documents\Outlook Files` | Move |
| Zoom recordings | `<profile>\Documents\Zoom` | Redirect |
| Teams (new) cache | `<profile>\AppData\Local\Packages\MSTeams_<id>\LocalCache` | Delete |
| Teams (classic) cache | under `<profile>\AppData\Roaming\Microsoft\Teams`: everything inside a directory whose name contains the text `Cache`. The rest of that folder is profile data and falls through. | Delete |
| Slack cache | under `<profile>\AppData\Roaming\Slack`: everything inside a directory whose name contains the text `Cache`. The rest of that folder is profile data and falls through. | Delete |
| Discord cache | `<profile>\AppData\Roaming\discord\Cache`, `<profile>\AppData\Roaming\discord\Code Cache` (exactly these two directories) | Delete |
| Telegram Desktop | `<profile>\AppData\Roaming\Telegram Desktop` | Redirect |

## 9. Mobile backups and cloud sync

Named stores (tier 2):

| Store | Default location | Bucket |
| --- | --- | --- |
| iPhone / iPad backups | `<profile>\Apple\MobileSync\Backup`, `<profile>\AppData\Roaming\Apple Computer\MobileSync\Backup` | Move |
| Google Drive stream cache | `<profile>\AppData\Local\Google\DriveFS` | Redirect |
| Box Drive cache | `<profile>\AppData\Local\Box\Box` | Redirect |

### 9a. Cloud-sync roots (tier 4, directly inside a profile only)

| Root | Location | Bucket |
| --- | --- | --- |
| OneDrive | a directory directly inside a profile named exactly `OneDrive`, or `OneDrive - <anything>` (business). `OneDriveTemp` or `OneDrive_backup` are not OneDrive roots. | Never |
| Dropbox | `<profile>\Dropbox` | Move |
| Google Drive mirrored folder | `<profile>\My Drive` | Move |

## 10. Browsers, temp and crash data

| Store | Default location | Bucket |
| --- | --- | --- |
| Firefox cache | `<profile>\AppData\Local\Mozilla\Firefox\Profiles` | Redirect |
| Chromium-family caches (Chrome, Edge, Brave) | under a directory named `User Data` that is itself somewhere below `<profile>\AppData\Local`: everything inside a directory whose name contains the text `Cache` (`Cache`, `Code Cache`, `GPUCache`). A file whose own name contains `Cache` does not count, and a `User Data` directory elsewhere is not a browser profile. | Delete |
| Windows internet cache | `<profile>\AppData\Local\Microsoft\Windows\INetCache` | Delete |
| User temp | `<profile>\AppData\Local\Temp` | Delete |
| Crash dumps | `<profile>\AppData\Local\CrashDumps` | Delete |
| Windows Error Reporting queue | `X:\ProgramData\Microsoft\Windows\WER`, `<profile>\AppData\Local\Microsoft\Windows\WER` | Delete |
| Memory dump files (`.dmp`) | anywhere outside tier 1 (file-keyed, tier 2b) | Delete |

## 11. Reproducible artefacts

| Artefact | Bucket |
| --- | --- |
| anything inside a `node_modules` directory | Delete |
| anything inside a `.venv` directory | Delete |
| a `venv` directory's `Scripts`, `Lib` or `Include` subtree | Delete |
| anything inside a `__pycache__` directory | Delete |
| Rust build output: a `debug` or `release` directory directly inside a `target` directory (not under a target-triple directory) | Delete |

## 12. Install paths

| Location | Bucket |
| --- | --- |
| `X:\Program Files\`, `X:\Program Files (x86)\` (anything not covered by sections 2 to 11) | Never |
| `<profile>\AppData\Local\Programs` (per-user installs; anything not covered by sections 2 to 11) | Never |

## 13. Known folders

| Folder | Bucket |
| --- | --- |
| `<profile>\Downloads`, `<profile>\Documents`, `<profile>\Pictures`, `<profile>\Videos`, `<profile>\Music`, `<profile>\3D Objects` (directly inside a profile only) | Move |

`Desktop` is deliberately not a rule: files there fall through to the later tiers.

## 14. Generic fallbacks

| Location | Bucket |
| --- | --- |
| `<profile>\AppData\Local\Packages\<package>\LocalCache` (exactly one directory between `Packages` and `LocalCache`): packaged-app data, not a cache despite the name. Final: the file-type fallback does not apply. New Teams (section 8) is the one exception. | Review |
| `<profile>\AppData\Local\Microsoft\TokenBroker`: sign-in tokens. Final, as above. | Review |
| below `AppData\Local\`: everything inside a directory whose name **begins or ends** with the text `Cache` (`Cache`, `GPUCache`, `Code Cache`, `npm-cache`, `cache2`, `CachedData`, `Caches`; but not `MyCacheStuff`). The match is on a whole directory name; a file whose own name contains `Cache` does not count. | Delete |
| a directory named `logs` at any depth below `AppData\Local\<app>\` | Delete |
| everything else under `AppData\Roaming\` | Never |

## 15. File-type fallback

A file not classified above is **Move** when its extension is a self-contained
data type: disk images and archives (`.iso .img .wim .esd .zip .7z .rar .tar .gz .bz2 .xz .cab`),
media (`.mp4 .mkv .avi .mov .wmv .flv .mp3 .flac .wav .aac`),
creative projects (`.psd .psb .ai .indd .aep .prproj .drp .blend`),
camera raw and TIFF (`.raw .cr2 .cr3 .nef .arw .dng .tif .tiff`),
datasets (`.csv .tsv .parquet .feather .arrow .h5 .hdf5 .npz .npy .mat`),
model weights (`.ckpt .safetensors .pt .pth .pb .onnx .gguf .tflite`),
backups and databases (`.bak .vbk .pst .ost .sql .bacpac .dump`),
documents (`.docx .xlsx .pptx .pdf .epub`).

Anything else is **Review**.

## Open questions

Raised by the independent review of revision 2 and not yet decided. Each is a
case where the current rule is consistent but the advice may not be ideal.
The oracle encodes the current behaviour.

1. Single-name stores (`.gradle`, `.cargo`, `.gem`, `.keras`, `.triton`, `nltk_data`, `Saved Games`) are recognised anywhere, so a small project-level directory of the same name is reported as Redirect.
2. A deliberate backup of a profile (`D:\Backup\<name>\AppData\...`) is classified like the live profile.
3. Named stores and file-keyed rows win over a OneDrive root that contains them (`OneDrive\Documents\Zoom` is Redirect, a `.vhdx` in OneDrive is Move), although moving things out of a synced tree needs care.
4. A file-keyed row beats a reproducible artefact that contains it (a `.vmdk` inside `node_modules` is Move).
5. A `.dmp` inside a named store takes that store's bucket instead of Delete.
6. Since revision 3, some real caches are no longer recognised and show as Review or Never: Windows icon and thumbnail cache files (only the file name says cache), caches of Chromium-based apps that keep `User Data` under `AppData\Roaming`, portable browsers, and cache or log folders inside `AppData\Local\Programs`. This is the safe direction; named rows can be added later.
7. Slack and classic Teams data outside their cache directories is now Never, including large `IndexedDB` trees.
8. Still ambiguous, and absent from the oracle: see `tests/oracle/AMBIGUITIES.md`.


## Revision history

* **Revision 2.** Written after the independent oracle review of revision 1 (see `tests/oracle/AMBIGUITIES.md` and `tests/oracle/ADJUDICATION.md`). Adds the recognition rules, tier 2b, section 9a, and tightens the rows the review showed to be ambiguous or to have unintended readings (wandb package directory, Blackmagic install path, Desktop, drive-root anchoring).
* **Revision 3.** Written after the independent defect review of the implementation. The generic cache rules in sections 10 and 14 matched the text `Cache` anywhere, including file names and packaged-app data folders, and so marked non-caches as Delete. They now match whole directory names in bounded locations. Slack and classic Teams are narrowed from the whole profile folder to its cache directories. Per-user install paths are Never.
