# Security

## Design

Disk Space Triage is a diagnostic with four optional actions. Its scan
cannot change anything; each action is confirmed per item (default answer
No), measured, logged, and narrow enough to be checked by reading one file.

| Threat | Control |
| --- | --- |
| The tool damages data | The scan cannot change anything. Delete asks Windows to recycle one folder, and only if, re-examined at that moment, it is the top of a listed rebuildable store, outside installed software and sync folders, with no other store, virtual disk, personal file type, link or unreadable content inside, and small enough for the Recycle Bin. Move never overwrites, writes its copy under a temporary name, compares it with the original by SHA-256 while the original is held open, and only then renames it and asks Windows to recycle the original. Moving a whole store uses the same per-file copy and check, re-lists the old folder to confirm it is unchanged, and recycles it only after every file is verified and the setting is switched; a move that fails earlier removes the copies it made and leaves everything else as it was. The script deletes permanently only copies it has just made. Each of these calls is pinned to one function and one argument by the capability test. |
| Emptying the Recycle Bin removes something you wanted | It is a separate button with its own warning-level confirmation that states the item count, the size, and that it covers everything in your Recycle Bin on that drive. It is one pinned `Clear-RecycleBin` call for one local fixed drive, and nothing else in the tool can reach it. |
| The tool changes settings behind your back | The only setting it can change is a user environment variable from a fixed list of cache locations, and only after you confirm that change. It refuses a variable that is already set to anything but its own folder, any folder other than the one expected folder for that store below `<drive>:\FromC\Users\<you>`, a folder that already has content, the Windows drive, a drive that is not local NTFS, and any path below a junction. Setting a user variable writes one value under `HKCU\Environment`; that is the only registry write the tool makes. The only registry read is the Windows light/dark app setting. System-critical variables (`PATH`, `TEMP`, `APPDATA` ...) are excluded by a test. No change is made unless the log folder is available, and each change is undoable from the window until it is closed. |
| The tool leaks data | No network commands or types exist in it. Only local fixed disks are scanned, and report folders on network paths are refused. The HTML report loads nothing external. CI runs a scan with outbound traffic blocked. |
| The tool gains privileges | It needs none and refuses to run elevated. It never requests elevation and performs no token, service or scheduled-task operation, and no registry write other than the user variable described above. |
| A file on disk attacks the tool | File contents are never interpreted; they are read only to copy and hash a file being moved. Paths are treated as untrusted text: they are matched, measured and written into reports as data (JSON-escaped, inserted with `textContent`). |
| A junction redirects the scan or the report | Junctions and symbolic links are never followed during the scan. A report folder that is, or sits below, a junction or symbolic link is refused. |
| A later change quietly adds a capability | `tests/Capability.Tests.ps1` fails the build for any command, .NET type, static call, URL or write location outside the allowlist. |

## What it does not protect against

- **Windows deciding to delete permanently.** The tool asks for the Recycle Bin and lets Windows show its own prompts. If the Recycle Bin is turned off for a drive, or Windows asks whether to delete permanently and you agree, the item is gone. The tool then reports "removed", not "in the Recycle Bin".
- **Moved files are less protected.** A file moved out of your profile takes the permissions of the new folder, which on many PCs let every local user read it. Alternate data streams are not copied, so a downloaded file loses its "from the internet" mark. Encrypted (EFS) files are refused.
- **The copy check.** The copy is read back and compared, which catches a bad copy, but Windows may serve part of that read from memory. It is strong evidence, not proof, that the disk holds the right bytes.
- **Sync folders the tool does not recognise.** OneDrive, Dropbox, iCloud Drive, Google Drive, Box and similar are recognised in their usual places, and cloud-marked files are refused. A synced folder elsewhere may not be recognised; moving a file out of it removes it from the cloud and from other people's copies.
- **An interrupted move.** If the process is killed mid-copy, a file ending in `.triage-partial` is left on the destination. It is never given the real name; delete it. A store move killed part-way also leaves the files copied so far in the new folder; the setting is not switched and the old folder is untouched, so delete the new folder and start again.

- **A wrong judgement about what is rebuildable.** The Delete list is conservative, but a `node_modules` folder you patched by hand, or a browser cache you wanted, is gone to the Recycle Bin if you confirm. Restore it from there.
- **Moved files and the programs that expect them.** A project that refers to a dataset by its old path must be updated by you.

- **Permissions of redirected folders.** A cache in your profile is private to you. Its replacement below `D:\FromC` inherits the permissions of that drive, which on many PCs let every local user read and change it. On a shared or lab computer, another user could read a Hugging Face token stored there or tamper with cached packages. Use the redirect feature only on a PC you do not share, or tighten the permissions of `D:\FromC\Users\<you>` yourself.
- **External and substituted drives.** Windows reports USB hard disks and SUBST drives as fixed disks. If a redirected drive is unplugged, the tools that use it fail until it returns or you undo the change.
- **Variables set elsewhere.** A value set by conda activation, a shell profile, an IDE or a `.env` file overrides the user variable for that program; the tool cannot see those.

- **The effect of "Only change the setting".** The owning tool downloads into the new folder; the old folder stays on the system drive and no space is freed. A Hugging Face folder redirected this way no longer contains your sign-in token until you sign in again or copy it. "Move to the other drive" avoids both by bringing the contents along.
- **A store in use while it is moved.** The tool re-lists the old folder after copying and stops if anything changed, but it cannot see a program that merely holds files open. Close the owning program first. If Windows cannot recycle the old folder because files are in use, the tool says the old folder is still there.
- **Files that already exist in the new folder.** When the setting already points at the new folder and both folders hold a file of the same name with different contents, a pure download cache keeps the file already in use; any other store stops without removing anything.

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
