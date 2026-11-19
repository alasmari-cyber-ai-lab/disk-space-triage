# Security

## Design

Disk Space Triage is a diagnostic. It is built so that running it cannot make
anything worse, and so that this can be checked by reading one file.

| Threat | Control |
| --- | --- |
| The tool damages data | The scan cannot change anything. The Delete action sends one folder to the Recycle Bin, and only if, re-examined at that moment, it is the top of a listed rebuildable store with nothing foreign, linked or unreadable inside. The Move action never overwrites, verifies its copy by SHA-256 before the original is touched, and sends the original to the Recycle Bin. The only permanent delete removes the tool's own unverified partial copy. Each of these calls is pinned to one function and one argument by the capability test. |
| The tool changes settings behind your back | The only setting it can change is a user environment variable from a fixed list of cache locations, and only after you tick the enabling box and confirm that change. It refuses a variable that is already set, any folder other than the one expected folder for that store below `<drive>:\FromC\Users\<you>`, a folder that already has content, the Windows drive, a drive that is not local NTFS, and any path below a junction. Setting a user variable writes one value under `HKCU\Environment`; that is the only registry write the tool makes. System-critical variables (`PATH`, `TEMP`, `APPDATA` ...) are excluded by a test. No change is made unless the log folder is available, and each change is undoable from the window until it is closed. |
| The tool leaks data | No network commands or types exist in it. Only local fixed disks are scanned, and report folders on network paths are refused. The HTML report loads nothing external. CI runs a scan with outbound traffic blocked. |
| The tool gains privileges | It needs none and refuses to run elevated. It never requests elevation and performs no token, service or scheduled-task operation, and no registry write other than the user variable described above. |
| A file on disk attacks the tool | File contents are never read. Paths are treated as untrusted text: they are matched, measured and written into reports as data (JSON-escaped, inserted with `textContent`). |
| A junction redirects the scan or the report | Junctions and symbolic links are never followed during the scan. A report folder that is, or sits below, a junction or symbolic link is refused. |
| A later change quietly adds a capability | `tests/Capability.Tests.ps1` fails the build for any command, .NET type, static call, URL or write location outside the allowlist. |

## What it does not protect against

- **A wrong judgement about what is rebuildable.** The Delete list is conservative, but a `node_modules` folder you patched by hand, or a browser cache you wanted, is gone to the Recycle Bin if you confirm. Restore it from there.
- **The Recycle Bin limit.** If an item is larger than the Recycle Bin allows, Windows offers permanent deletion. The tool shows that Windows prompt rather than suppressing it; the choice is yours.
- **Moved files and the programs that expect them.** A project that refers to a dataset by its old path must be updated by you.

- **Permissions of redirected folders.** A cache in your profile is private to you. Its replacement below `D:\FromC` inherits the permissions of that drive, which on many PCs let every local user read and change it. On a shared or lab computer, another user could read a Hugging Face token stored there or tamper with cached packages. Use the redirect feature only on a PC you do not share, or tighten the permissions of `D:\FromC\Users\<you>` yourself.
- **External and substituted drives.** Windows reports USB hard disks and SUBST drives as fixed disks. If a redirected drive is unplugged, the tools that use it fail until it returns or you undo the change.
- **Variables set elsewhere.** A value set by conda activation, a shell profile, an IDE or a `.env` file overrides the user variable for that program; the tool cannot see those.

- **The effect of a redirect.** After you redirect a cache, the tool that owns it downloads into the new folder; the old folder stays on the system drive until you delete it. A redirected Hugging Face folder no longer contains your sign-in token until you sign in again or copy it.

- **A modified copy.** If you did not get the file from this repository, compare its SHA-256 with the published one, or read it.
- **Running it elevated with `-AllowElevated`.** The read-only design still holds, but the scan can then see more of the machine than it needs.
- **What you do next.** The report recommends deletions and moves. Acting on it is your decision; verify before deleting.
- **A report folder that syncs.** The default folder is `Documents\DiskReports`. If your Documents folder is backed up by OneDrive or a similar client, that client uploads the reports like any other document. Choose another folder with `-ReportDirectory` if that matters.
- **Cloud folders.** While listing a OneDrive folder, Windows may ask the OneDrive client for the folder's listing. The tool itself opens no connection, and it does not count or download cloud-only files.
- **External disks.** Windows reports most USB hard disks as fixed disks, so they are accepted as scan and report targets; USB sticks and network drives are not.
- **The limits of the allowlist test.** It checks commands, types, static calls, instance method names, redirection and the window markup. It is a tripwire for changes, not a formal proof.
- **Report contents.** Reports list real file paths from your machine, which can reveal project, client or user names. Treat a report like any other internal document before sharing it.

## The execution-policy flag

`Start-DiskSpaceTriage.cmd` starts PowerShell with `-ExecutionPolicy Bypass`.
This applies to that one process only and changes no system or user setting.
It is needed because the script is not code-signed. If your organisation
enforces a signing policy, follow that policy instead.

## Reporting a problem

Open a GitHub issue. For anything you believe is exploitable, use GitHub's
private vulnerability reporting on this repository instead of a public issue.
