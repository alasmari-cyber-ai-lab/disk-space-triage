# Adjudication: oracle revision 1 to revision 2

Derived from `docs/SPEC.md` revision 2 only. Every one of the 485 revision-1 rows was re-derived; 8 changed bucket.

## Rows whose expected bucket changed

| id | path | old | new | deciding revision-2 sentence |
| --- | --- | --- | --- | --- |
| T072 | `D:\projects\api\.venv\Lib\site-packages\wandb\__init__.py` | Redirect | Delete | Weights & Biases: a `wandb` directory that is not inside a `site-packages` directory (there it is the installed Python package, not run data). |
| T179 | `E:\Media\Blackmagic Design\DaVinci Resolve\CacheClip\3f9a1c7e2b4d6f8a\0a1b2c3d.dvcc` | Redirect | Review | DaVinci Resolve cache: `<profile>\AppData\Roaming\Blackmagic Design`, `<profile>\AppData\Local\Blackmagic Design`. |
| T184 | `C:\Program Files\Blackmagic Design\DaVinci Resolve\Resolve.exe` | Redirect | Never | DaVinci Resolve cache: ... (the installed program under Program Files is section 12). |
| T265 | `C:\Users\khalid\AppData\Local\Microsoft\Windows\WER\ReportArchive\AppCrash_python.exe_9f2c1d7a\Report.wer` | Review | Delete | Windows Error Reporting queue: `X:\ProgramData\Microsoft\Windows\WER`, `<profile>\AppData\Local\Microsoft\Windows\WER`. |
| T333 | `C:\Users\khalid\Desktop\ubuntu-24.04-live-server-amd64.iso` | Review | Move | `Desktop` is deliberately not a rule: files there fall through to the later tiers. |
| T334 | `C:\Users\dev-01\Desktop\final_cut_v7.mp4` | Review | Move | `Desktop` is deliberately not a rule: files there fall through to the later tiers. |
| T335 | `C:\Users\Noura Al-Qahtani\Desktop\Reports\Annual Report 2023.pdf` | Review | Move | `Desktop` is deliberately not a rule: files there fall through to the later tiers. |
| T336 | `C:\USERS\KHALID\DESKTOP\MODEL.SAFETENSORS` | Review | Move | `Desktop` is deliberately not a rule: files there fall through to the later tiers. |

Some further rows kept their bucket but had `spec_section` or `rationale` refreshed (Desktop no longer a rule, section 9 split into 9 and 9a, Chromium and Office rows now decided by their own section, tier 2b wording).

## Rows added

T486 to T643 (158 rows, all adversarial): cases from the old AMBIGUITIES.md that revision 2 decides, plus probes of each new statement (`<profile>\rest` outside a profile, drive-root-only locations, whole-directory-name matching, tier 2b, section 9a, known folders and Desktop, the extension definition, wandb in site-packages, Blackmagic, Outlook non-.ost, WER, Rust target triples, revised sections 10 and 14).
