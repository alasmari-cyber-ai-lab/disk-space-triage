# Disk Space Triage

[![CI](https://github.com/alasmari-cyber-ai-lab/disk-space-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/alasmari-cyber-ai-lab/disk-space-triage/actions/workflows/ci.yml)

A Windows tool that shows what is filling your system drive and how each item
can leave it safely. Its scan is read-only. Built for machines that do ML and LLM work,
where model caches, package caches, container disks and virtual environments
fill `C:` faster than anything a normal cleanup tool looks for.

It never moves or deletes anything. It tells you which **one setting** frees
the most space. For the common caches it can also apply that setting for you,
if you allow it and confirm each change.

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
5. Optional: on the **Fix with one setting** tab, tick the box, select a row and choose **Apply selected**.

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

## The one change it can make

The scan is read-only. On the **Fix with one setting** tab the tool can, for a
fixed list of cache stores (`HF_HOME`, `TORCH_HOME`, `PIP_CACHE_DIR`,
`npm_config_cache`, `OLLAMA_MODELS` and a few more):

1. create an empty folder on the other drive, with the same name and position
   it has on `C:`, below `D:\FromC`:
   `C:\Users\you\.cache\huggingface` becomes `D:\FromC\Users\you\.cache\huggingface`;
2. set the matching **user** environment variable to that folder.

That is all. It does not move or delete the old folder, it never touches a
variable you have already set, it needs no administrator rights, it asks
before every change, it writes each change to `DiskTriage_actions.csv`, and
**Undo last change** removes the variable again (until you close the window;
after that, remove it under Settings > System > About > Advanced system
settings > Environment Variables). After each change it tells you what to do
with the old folder: delete it for a pure cache, move its contents for stores
such as Ollama models or the Hugging Face folder, which holds your sign-in
token. The other drive must be a local NTFS disk, and not the Windows drive. Stores that also hold tools,
credentials or your own data (Cargo, Gradle, Yarn, TensorFlow Datasets, Docker, WSL, games) are not on
the list and stay manual.

## Why you can trust it

These are properties of the code, checked on every commit, not promises.

| Property | How it is enforced |
| --- | --- |
| No network access | [`tests/Capability.Tests.ps1`](tests/Capability.Tests.ps1) parses the script and fails the build if any command, .NET type, static call or instance method outside a short allowlist appears. Only local fixed disks are scanned; network drives are refused. CI also runs a real scan with outbound traffic blocked by the firewall. |
| Never moves or deletes; the scan is read-only | Same allowlist: no move, copy, delete or open call exists in the script. A test compares the names, sizes and timestamps of a scanned tree before and after. |
| Changes only what you confirm | The single setter call may appear in exactly two functions, must take its variable name from a list of twelve names pinned by a test, its value from the folder recomputed inside the function, and must target the current user. On CI the tests set a real variable, check the refusals (unknown variable, any other folder, the Windows drive, a non-empty folder, already set) and undo it. |
| Never reads file contents | Only names, sizes, timestamps and attributes are accessed. |
| No administrator rights | It refuses to start elevated. CI checks the refusal. |
| No hidden code | No `Invoke-Expression`, compiled C#, reflection, COM or external processes. One `Add-Type` call loads the WPF assemblies that ship with Windows; the test pins that line exactly. |
| Writes only its reports and log | Three files per export plus the action log, to a folder on a local fixed disk; and empty folders below `FromC` for confirmed redirects. Network paths, mapped network drives, USB sticks, and any folder that is or sits below a junction or symbolic link are refused. |
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
- Classification is advice. Read the "What to do" column before acting, and verify a copy before deleting an original.

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
