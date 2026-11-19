# Security

## Design

Disk Space Triage is a diagnostic. It is built so that running it cannot make
anything worse, and so that this can be checked by reading one file.

| Threat | Control |
| --- | --- |
| The tool damages data | It contains no command that moves, copies, deletes or modifies files. Enforced by the capability allowlist test. |
| The tool leaks data | No network commands or types exist in it. Report folders on network paths are refused. The HTML report loads nothing external. CI runs a scan with outbound traffic blocked. |
| The tool gains privileges | It needs none and refuses to run elevated. It never requests elevation and performs no token, service, registry or scheduled-task operation. |
| A file on disk attacks the tool | File contents are never read. Paths are treated as untrusted text: they are matched, measured and written into reports as data (JSON-escaped, inserted with `textContent`). |
| A junction redirects the scan or the report | Reparse points are never followed during the scan. A report folder that is a junction or symbolic link is refused. |
| A later change quietly adds a capability | `tests/Capability.Tests.ps1` fails the build for any command, .NET type, static call, URL or write location outside the allowlist. |

## What it does not protect against

- **A modified copy.** If you did not get the file from this repository, compare its SHA-256 with the published one, or read it.
- **Running it elevated with `-AllowElevated`.** The read-only design still holds, but the scan can then see more of the machine than it needs.
- **What you do next.** The report recommends deletions and moves. Acting on it is your decision; verify before deleting.
- **Report contents.** Reports list real file paths from your machine, which can reveal project, client or user names. Treat a report like any other internal document before sharing it.

## The execution-policy flag

`Start-DiskSpaceTriage.cmd` starts PowerShell with `-ExecutionPolicy Bypass`.
This applies to that one process only and changes no system or user setting.
It is needed because the script is not code-signed. If your organisation
enforces a signing policy, follow that policy instead.

## Reporting a problem

Open a GitHub issue. For anything you believe is exploitable, use GitHub's
private vulnerability reporting on this repository instead of a public issue.
