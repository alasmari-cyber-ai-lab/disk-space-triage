# Disk Space Triage

[![CI](https://github.com/alasmari-cyber-ai-lab/disk-space-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/alasmari-cyber-ai-lab/disk-space-triage/actions/workflows/ci.yml)

A Windows tool that shows what is filling your system drive and how each item
can leave it safely. Its scan is read-only. Built for machines that do ML and LLM work,
where model caches, package caches, container disks and virtual environments
fill `C:` faster than anything a normal cleanup tool looks for.

It tells you which **one setting** frees the most space. If you allow it, it
can also act: apply that setting, send rebuildable folders to the Recycle
Bin, and move large data files to the other drive. Every action is off by
default and confirmed one item at a time.

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
4. Choose **Scan**, then **Export report**. Reports go to `Documents\DiskReports`.
5. Optional: use one of the three action tabs (see below). On each, tick the box, select a row marked Ready, and press the button.

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

The scan is read-only. Three tabs can change something. Each has its own
"Allow" box, acts on one selected item, asks first, and writes what it did to
`DiskTriage_actions.csv`. Nothing is deleted permanently and nothing is
overwritten.

**Fix with one setting (Redirect).** For twelve cache stores (`HF_HOME`,
`TORCH_HOME`, `PIP_CACHE_DIR`, `npm_config_cache`, `OLLAMA_MODELS` and others)
the tool creates an empty folder on the other drive, with the same name and
position below `D:\FromC`, and sets the matching **user** environment
variable to it: `C:\Users\you\.cache\huggingface` becomes
`D:\FromC\Users\you\.cache\huggingface`. It does not move or delete the old
folder; afterwards it tells you what to do with it (delete a pure cache, move
Ollama models, copy the Hugging Face sign-in token). It never touches a
variable you have already set. **Undo last change** works until you close the
window; after that, remove the variable under Settings > System > About >
Advanced system settings > Environment Variables.

**Delete rebuildable folders.** Sends one whole folder to the Recycle Bin.
Only these are offered: `node_modules` with a lockfile beside it, Rust
`target\debug` and `target\release` beside a `Cargo.toml`, Steam, GPU and
DirectX shader caches, crash dumps, and browser, Discord, Slack and classic
Teams cache folders. A folder is refused if it contains anything that is not
part of that store, a junction, or anything unreadable. Space is freed when
you empty the Recycle Bin.

**Move files to the other drive.** For large plain data files (downloads,
datasets, videos, archives, model weights): the file is copied to
`D:\FromC\<same path>`, the copy is verified byte for byte with SHA-256, and
only then is the original sent to the Recycle Bin. A cancelled or failed copy
is removed and the original is left untouched. Files that belong to a
program, game, virtual machine, backup or sync folder are never offered.

Everything else stays advice: Docker, WSL, games, virtual machines, the
Windows known folders, environments, and stores that hold tools or
credentials (Cargo, Gradle, Yarn, TensorFlow Datasets). The other drive must
be an internal NTFS disk, and not the Windows drive.

## Why you can trust it

These are properties of the code, checked on every commit, not promises.

| Property | How it is enforced |
| --- | --- |
| No network access | [`tests/Capability.Tests.ps1`](tests/Capability.Tests.ps1) parses the script and fails the build if any command, .NET type, static call or instance method outside a short allowlist appears. Only local fixed disks are scanned; network drives are refused. CI also runs a real scan with outbound traffic blocked by the firewall. |
| The scan is read-only | A test compares the names, sizes and timestamps of a scanned tree before and after. No scan function contains a call that can open, write or remove a file. |
| Nothing is deleted permanently | Removal goes through one Recycle Bin call per action, pinned by a test to its function and to the Recycle Bin option. The single permanent delete in the script removes the tool's own unverified partial copy, and is pinned to that variable. |
| A move cannot lose data | The destination is opened only as a new file (never overwriting); the copy is re-read and compared by SHA-256 before the original is touched. On CI the tests move a real file, cancel a move, and try to overwrite. |
| Delete touches only rebuildable stores | The folder is re-examined at the moment of deletion: it must be the top of one listed store, with nothing foreign, linked or unreadable in it. Tests attempt to remove a normal folder, the profile, a sub-folder, a mixed store and a store containing a junction. |
| Changes only what you confirm | The single setter call may appear in exactly two functions, must take its variable name from a list of twelve names pinned by a test, its value from the folder recomputed inside the function, and must target the current user. On CI the tests set a real variable, check the refusals (unknown variable, any other folder, the Windows drive, a non-empty folder, already set) and undo it. |
| Reads file contents only to move a file | The scan accesses names, sizes, timestamps and attributes only. The one function that opens a file for reading is the copy-and-verify step of Move. |
| No administrator rights | It refuses to start elevated. CI checks the refusal. |
| No hidden code | No `Invoke-Expression`, compiled C#, reflection, COM or external processes. Two `Add-Type` calls load assemblies that ship with Windows (WPF, and the Visual Basic runtime that provides the Recycle Bin); the test pins both lines exactly. |
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
- The Recycle Bin has a size limit. For a very large folder or file, Windows may say it is too big to recycle and offer to delete it permanently; the tool lets Windows ask you, and you should answer No unless you are sure.
- While a file is being moved the window stays responsive enough to cancel, but a large file takes as long as copying it twice.

## Repository layout

```
DiskSpaceTriage.ps1          the whole tool, one file
Start-DiskSpaceTriage.cmd    double-click launcher
docs/SPEC.md                 classification policy (source of truth)
docs/USER-GUIDE.md           how to act on each bucket
tests/                       Pester tests: oracle, engine, capability allowlist
tools/                       optional checks for machines without PowerShell
.github/workflows/ci.yml     Windows CI
```

## Licence

MIT. See [LICENSE](LICENSE).
