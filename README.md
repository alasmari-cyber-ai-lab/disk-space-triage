# Disk Space Triage

[![CI](https://github.com/alasmari-cyber-ai-lab/disk-space-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/alasmari-cyber-ai-lab/disk-space-triage/actions/workflows/ci.yml)

A Windows tool that shows what is filling your system drive and how each item
can leave it safely. Its scan is read-only. Built for machines that do ML and LLM work,
where model caches, package caches, container disks and virtual environments
fill `C:` faster than anything a normal cleanup tool looks for.

It then frees the space, one confirmed step at a time: it moves caches and
model stores to another drive (and tells the owning tool where they went),
sends rebuildable folders to the Recycle Bin, moves large data files, and
empties the Recycle Bin. After every step it shows the free space it measured
before and after, so you can see what the step really did.

## What it tells you

Every file it sees lands in one of five buckets:

| Bucket | Meaning | Example |
| --- | --- | --- |
| **Redirect** | A tool owns it. Change the tool's setting so the store lives on another drive. Permanent. | `HF_HOME`, `PIP_CACHE_DIR`, Docker disk image location |
| **Delete** | Regenerates or is reproducible. Never copy it. | `node_modules`, `.venv`, temp files |
| **Move** | Copy, verify, delete the original. | Downloads, datasets, game libraries |
| **Never** | Registry-bound or system state. Leave it. | `C:\Windows`, `Program Files`, `AppData\Roaming` |
| **Review** | Nothing matched. Check what owns it. | |

The report ranks the Redirect, Delete and Move findings by size, so the first
row is the single change that frees the most space.

## Run it

1. Download `DiskSpaceTriage.ps1` and `Start-DiskSpaceTriage.cmd` into the same folder.
2. Read the script if you want to. It is one plain-text file.
3. Double-click `Start-DiskSpaceTriage.cmd`. Run it as your normal user, **not** as administrator.
4. Choose **Scan**. Nothing changes during a scan.
5. Open **Move caches**, **Delete** or **Move files**, select a row marked Ready and choose the button below the list. Each step asks before it does anything.
6. Choose **Empty Recycle Bin** at the top to actually free what was deleted or moved. The window shows the free space before and after.
7. Optional: **Save report** writes the findings to `Documents\DiskReports`. **Copy summary** copies what was done and the measured free space, with no file or folder names, so it is safe to share.

From a terminal:

```powershell
# Window
powershell -NoProfile -ExecutionPolicy Bypass -File .\DiskSpaceTriage.ps1

# No window: print a summary and write the reports
powershell -NoProfile -ExecutionPolicy Bypass -File .\DiskSpaceTriage.ps1 -Mode Console

# Include an extra folder (full path), list files of 250 MB and larger
powershell -NoProfile -ExecutionPolicy Bypass -File .\DiskSpaceTriage.ps1 -Mode Console -MinSizeMB 250 -AdditionalRoot C:\ComfyUI

# See every classification rule
powershell -NoProfile -ExecutionPolicy Bypass -File .\DiskSpaceTriage.ps1 -ShowRules
```

To pass several extra folders, run it from inside PowerShell:
`& .\DiskSpaceTriage.ps1 -Mode Console -AdditionalRoot C:\ComfyUI, C:\work`.

Requires Windows 10 or 11. Nothing to install: it uses Windows PowerShell 5.1
and WPF, which ship with Windows.

To check your download, compare its hash with the one on the release page:

```powershell
Get-FileHash .\DiskSpaceTriage.ps1 -Algorithm SHA256
```

## What it can change, and only when you say so

The scan is read-only. Four actions can change something. Each acts on one
item, asks first (the default answer is No), measures the free space before
and after, and writes what it did to `DiskTriage_actions.csv`. Nothing is
overwritten. No button is ever greyed out without an explanation: a button
that cannot act tells you why when you choose it.

**Why the Recycle Bin matters.** The Recycle Bin of a drive is on that drive.
Deleting or moving something sends the original there, so `C:` is exactly as
full as before until the bin is emptied. The window always shows how much the
Recycle Bin on the drive holds, and **Empty Recycle Bin** is the step that
returns the space. It is permanent and empties your whole Recycle Bin on that
drive, not only what the tool put there; the confirmation says so.

**Move caches (Redirect).** For twelve cache and model stores (`HF_HOME`,
`TORCH_HOME`, `PIP_CACHE_DIR`, `npm_config_cache`, `OLLAMA_MODELS` and
others). **Move to the other drive** copies every file to the same name and
position below `D:\FromC` (`C:\Users\you\.cache\huggingface` becomes
`D:\FromC\Users\you\.cache\huggingface`), compares each copy with its
original by SHA-256, lists the old folder again to make sure nothing changed
meanwhile, sets the matching **user** environment variable so the owning tool
uses the new folder, and only then asks Windows to put the old folder in the
Recycle Bin. If anything fails or you cancel before that point, the copies
are removed again and nothing has changed. A store that contains a junction,
symbolic link or cloud placeholder is refused. **Only change the setting**
is the lighter alternative: new downloads go to the other drive, the files
that are there now stay, and no space is freed; it can be undone until you
close the window. The tool never touches a variable that points anywhere
other than its own folder.

**Delete.** Asks Windows to put one whole folder in the
Recycle Bin. Only these are offered: a project's `node_modules` with a
`package.json` and a lockfile beside it, Rust `target\debug` and
`target\release` beside a `Cargo.toml`, Steam, GPU and DirectX shader caches,
crash dumps, and browser, Discord, Slack and classic Teams folders named
exactly like a cache (`Cache`, `Code Cache`, `GPUCache` ...). A folder is
refused if it belongs to an installed application or sits in a sync folder,
if it contains another store, a virtual disk, a personal file type
(documents, datasets, model weights, videos, backups), a junction or anything
unreadable, or if it is too large or has paths too long for the Recycle Bin.

**Move files.** For large data files of known types
(archives, disk images, videos, datasets, model weights, documents): the file
is copied to `D:\FromC\<same path>` under a temporary name, read back and
compared with the original by SHA-256, renamed, and only then is Windows
asked to put the original in the Recycle Bin. A cancelled or failed copy is
removed and the original is left untouched. Files under `AppData`,
`Program Files`, `ProgramData`, hidden tool folders such as `.git`, the usual
cloud-sync folders, and mail stores are not offered. The tool cannot know
whether a project refers to a file or whether an unusual folder is synced:
check before you move.

Everything else stays advice: Docker, WSL, games, virtual machines,
relocating a whole known folder (Downloads, Documents), environments, and
stores that hold tools or credentials (Cargo, Gradle, Yarn, TensorFlow
Datasets). The other drive must
be an internal NTFS disk, and not the Windows drive.

## Why you can trust it

These are properties of the code, checked on every commit, not promises.

| Property | How it is enforced |
| --- | --- |
| No network access | [`tests/Capability.Tests.ps1`](tests/Capability.Tests.ps1) parses the script and fails the build if any command, .NET type, static call or instance method outside a short allowlist appears. Only local fixed disks are scanned; network drives are refused. CI also runs a real scan with outbound traffic blocked by the firewall. |
| The scan is read-only | A test compares the names, sizes and timestamps of a scanned tree before and after. No scan function contains a call that can open, write or remove a file. |
| Actions really free space | CI creates two throw-away NTFS volumes and runs Delete, Move file and Move store on them ([`tests/Volume.Tests.ps1`](tests/Volume.Tests.ps1)). It asserts that recycling alone frees nothing, that the tool measures and reports that, and that free space rises by the size of the data once the Recycle Bin is emptied. The job fails if any of those tests is skipped. |
| Removal goes through the Recycle Bin | Each recycle call is pinned by a test to its function, to the Recycle Bin option and to the mode in which Windows asks before deleting anything permanently. The recycling actions refuse to run without an interactive desktop. The script itself deletes permanently only copies it has just made (an unverified temporary copy, or the copies of a store move that did not finish). Emptying the Recycle Bin is one pinned call, for one drive, reachable from one confirmed button. Whether an item finally lands in the Recycle Bin is decided by Windows (for example, if you have turned the Recycle Bin off). |
| Every action asks first | A test checks that each action handler shows a Yes/No question whose default is No before it calls the function that acts, and that the window contains no enabling tick box and no button that starts switched off. |
| A move never touches the original before the copy is checked | For files and for whole stores alike, the copy is written under a temporary name as a new file (never overwriting), read back and compared by SHA-256 while the original is held open, and only then renamed. On CI the tests move a real file, cancel during copy and during verification, plant a leftover, and try to overwrite; a test fails if CI could not run them. |
| Delete is limited to listed stores | The lists of removable stores, cache folder names and movable folders are pinned by a test. The folder is re-examined at the moment of deletion: it must be the top of one listed store, outside installed software and sync folders, with no other store, virtual disk, personal file type, link or unreadable content in it. Tests attempt to remove a normal folder, the profile, a sub-folder, an application's `node_modules`, a store holding a document, and a store containing a junction. The check recognises file types, not meaning: a hand-edited file of an ordinary type inside `node_modules` is not detected. |
| Changes only what you confirm | The single setter call may appear in exactly two functions, must take its variable name from a list of twelve names pinned by a test, its value from the folder recomputed inside the function, and must target the current user. On CI the tests set a real variable, check the refusals (unknown variable, any other folder, the Windows drive, a non-empty folder, already set) and undo it. |
| Reads file contents only to copy | The scan accesses names, sizes, timestamps and attributes only. Files are opened for reading only by the copy-and-verify step. The size of the Recycle Bin is read from the bin's own 16-byte index records, not from your files. |
| No administrator rights | It refuses to start elevated. CI checks the refusal. |
| No hidden code | No `Invoke-Expression`, compiled C#, reflection, COM or external processes. Two `Add-Type` calls load assemblies that ship with Windows (WPF, and the Visual Basic runtime that provides the Recycle Bin); the test pins both lines exactly. One registry value is read, to follow the Windows light or dark setting; the test pins that line too. |
| Writes only where it says | Three files per export plus the action log, to a folder on a local fixed disk; redirect folders and moved files only below `FromC`. Network paths, mapped network drives, USB sticks, and any folder that is or sits below a junction or symbolic link are refused. |
| No persistence | No services, scheduled tasks or start-up entries. The only lasting traces are the reports and any user variable you chose to set. |
| The report is safe to open | Self-contained HTML with a Content-Security-Policy that blocks every external request; file paths are inserted as text, never as markup. |

More detail, including what it does **not** protect against, is in [SECURITY.md](SECURITY.md).

## How the classification is tested

The rules are easy to get subtly wrong: an early broad rule silently hides a
later specific one. So the test data is independent of the code:

1. [`docs/SPEC.md`](docs/SPEC.md) states the policy in plain language, with no patterns.
2. The oracle, [`tests/oracle/expected_classifications.csv`](tests/oracle/expected_classifications.csv), was written from the spec alone by a reviewer that never saw the implementation.
3. [`tests/Oracle.Tests.ps1`](tests/Oracle.Tests.ps1) is the only place the two meet. The oracle file is hash-pinned; every change to it is recorded in [`tests/oracle/ADJUDICATION.md`](tests/oracle/ADJUDICATION.md).

## Limits

- The allowlist is a strong tripwire against accidental or careless additions, not a proof against a determined author. Trust in a given copy still rests on its hash and on the file being readable.
- It reports logical file sizes. Compressed, sparse and hard-linked files can occupy less than shown.
- It scans your profile and a set of common folders, not the whole drive. Add more with `-AdditionalRoot`. Junctions and symbolic links are not followed, and folders more than 24 levels deep are not scanned; the report says how many of each it skipped.
- **Redirect does not always mean "then delete the old folder".** Some redirected stores hold your own data (recordings, game worlds, run logs, container volumes). The Why column says which; when in doubt, move.
- Files below the size threshold are counted in every total but classified by their folder, not individually.
- System stores that need administrator rights (page file, hibernation file, Windows Update cache) are listed as a checklist, not measured.
- Classification is advice. Read the "What to do" column before acting.
- The Recycle Bin has a size limit. For a very large folder or file, Windows may say it is too big to recycle and offer to delete it permanently; the tool lets Windows ask you. For Delete, answer No unless you are sure. After a move, the checked copy already exists, so Yes is safe.
- Moving a store copies files that are hard-linked into other places (uv and pnpm do this) as full files, and removing the old ones frees less than their listed size while those other links exist.
- Hugging Face stores created with Windows Developer Mode contain symbolic links; the tool refuses to move those and offers only the setting.
- In dark mode the title bar stays light: changing it needs a system call this tool deliberately does not make.
- While a file is being moved the window stays responsive enough to cancel, but a large file takes as long as copying it twice.

## Repository layout

```
DiskSpaceTriage.ps1          the whole tool, one file
Start-DiskSpaceTriage.cmd    double-click launcher
docs/SPEC.md                 classification policy (source of truth)
docs/USER-GUIDE.md           how to act on each bucket
docs/DECISIONS.md            why it is one PowerShell file, and what would change that
tests/                       Pester tests: oracle, engine, capability allowlist, actions on test volumes
tools/                       optional checks for machines without PowerShell
.github/workflows/ci.yml     Windows CI
```

## Licence

MIT. See [LICENSE](LICENSE).
