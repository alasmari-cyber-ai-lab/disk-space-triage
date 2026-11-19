# Disk Space Triage

[![CI](https://github.com/alasmari-cyber-ai-lab/disk-space-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/alasmari-cyber-ai-lab/disk-space-triage/actions/workflows/ci.yml)

A read-only Windows tool that shows what is filling your system drive and how
each item can leave it safely. Built for machines that do ML and LLM work,
where model caches, package caches, container disks and virtual environments
fill `C:` faster than anything a normal cleanup tool looks for.

It never moves or deletes anything. It tells you which **one setting** frees
the most space, and you make the change.

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

From a terminal:

```powershell
# Window
powershell -NoProfile -ExecutionPolicy Bypass -File .\DiskSpaceTriage.ps1

# No window: print a summary and write the reports
powershell -NoProfile -ExecutionPolicy Bypass -File .\DiskSpaceTriage.ps1 -Mode Console

# Include extra folders, list files of 250 MB and larger
.\DiskSpaceTriage.ps1 -Mode Console -MinSizeMB 250 -AdditionalRoot C:\Datasets, C:\work

# See every classification rule
.\DiskSpaceTriage.ps1 -ShowRules
```

Requires Windows 10 or 11. Nothing to install: it uses Windows PowerShell 5.1
and WPF, which ship with Windows.

To check your download, compare its hash with the one on the release page:

```powershell
Get-FileHash .\DiskSpaceTriage.ps1 -Algorithm SHA256
```

## Why you can trust it

These are properties of the code, checked on every commit, not promises.

| Property | How it is enforced |
| --- | --- |
| No network access of any kind | [`tests/Capability.Tests.ps1`](tests/Capability.Tests.ps1) parses the script and fails the build if any command or .NET type outside a short allowlist appears. CI also runs a real scan with outbound traffic blocked by the firewall. |
| Read-only on everything it scans | Same allowlist: no move, copy, delete or set commands exist in the script. A test hashes a scanned tree before and after. |
| Never reads file contents | Only names, sizes, timestamps and attributes are accessed. |
| No administrator rights | It refuses to start elevated. CI checks the refusal. |
| No hidden code | No `Invoke-Expression`, compiled C#, reflection, COM or external processes. One `Add-Type` call loads the WPF assemblies that ship with Windows; the test pins that line exactly. |
| Writes only its reports | Three files per export, to a folder on a local fixed disk. Network paths, removable drives and junctions are refused. |
| No persistence | No registry keys, services or scheduled tasks. |
| The report is safe to open | Self-contained HTML with a Content-Security-Policy that blocks every external request; file paths are inserted as text, never as markup. |

More detail, including what it does **not** protect against, is in [SECURITY.md](SECURITY.md).

## How the classification is tested

The rules are easy to get subtly wrong: an early broad rule silently hides a
later specific one. So the test data is independent of the code:

1. [`docs/SPEC.md`](docs/SPEC.md) states the policy in plain language, with no patterns.
2. The oracle, [`tests/oracle/expected_classifications.csv`](tests/oracle/expected_classifications.csv), was written from the spec alone by a reviewer that never saw the implementation.
3. [`tests/Oracle.Tests.ps1`](tests/Oracle.Tests.ps1) is the only place the two meet. The oracle file is hash-pinned; every change to it is recorded in [`tests/oracle/ADJUDICATION.md`](tests/oracle/ADJUDICATION.md).

## Limits

- It reports logical file sizes. Compressed, sparse and hard-linked files can occupy less than shown.
- It scans your profile and a set of common folders, not the whole drive. Add more with `-AdditionalRoot`.
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
