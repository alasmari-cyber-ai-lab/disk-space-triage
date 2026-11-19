# Security

## Design

Disk Space Triage is a diagnostic. It is built so that running it cannot make
anything worse, and so that this can be checked by reading one file.

| Threat | Control |
| --- | --- |
| The tool damages data | It contains no command that moves, copies, deletes or modifies files. Enforced by the capability allowlist test. |
| The tool changes settings behind your back | The only setting it can change is a user environment variable from a fixed list of cache locations, and only after you tick the enabling box and confirm that change. It refuses a variable that is already set, a folder outside `<drive>:\FromC\Users`, and any path below a junction. System-critical variables (`PATH`, `TEMP`, `APPDATA` ...) are excluded by a test. Every change is logged and can be undone. |
| The tool leaks data | No network commands or types exist in it. Only local fixed disks are scanned, and report folders on network paths are refused. The HTML report loads nothing external. CI runs a scan with outbound traffic blocked. |
| The tool gains privileges | It needs none and refuses to run elevated. It never requests elevation and performs no token, service, registry or scheduled-task operation. |
| A file on disk attacks the tool | File contents are never read. Paths are treated as untrusted text: they are matched, measured and written into reports as data (JSON-escaped, inserted with `textContent`). |
| A junction redirects the scan or the report | Junctions and symbolic links are never followed during the scan. A report folder that is, or sits below, a junction or symbolic link is refused. |
| A later change quietly adds a capability | `tests/Capability.Tests.ps1` fails the build for any command, .NET type, static call, URL or write location outside the allowlist. |

## What it does not protect against

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
