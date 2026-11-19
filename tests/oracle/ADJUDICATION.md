# Adjudication: oracle revision 1 to revision 2

Derived from `docs/SPEC.md` revision 2 only. Every one of the 485 revision-1 rows was re-derived; 8 changed bucket.

## Rows whose expected bucket changed

| id | path | old | new | deciding revision-2 sentence |
| --- | --- | --- | --- | --- |
| T072 | `D:\projects\api\.venv\Lib\site-packages\wandb\__init__.py` | Redirect | Delete | Weights & Biases: a `wandb` directory that is not inside a `site-packages` directory (there it is the installed Python package, not run data). |
| T179 | `E:\Media\Blackmagic Design\DaVinci Resolve\CacheClip\3f9a1c7e2b4d6f8a\0a1b2c3d.dvcc` | Redirect | Review | DaVinci Resolve cache: `<profile>\AppData\Roaming\Blackmagic Design`, `<profile>\AppData\Local\Blackmagic Design`. |
| T184 | `C:\Program Files\Blackmagic Design\DaVinci Resolve\Resolve.exe` | Redirect | Never | DaVinci Resolve cache: ... (the installed program under Program Files is section 12). |
| T265 | `C:\Users\alex\AppData\Local\Microsoft\Windows\WER\ReportArchive\AppCrash_python.exe_9f2c1d7a\Report.wer` | Review | Delete | Windows Error Reporting queue: `X:\ProgramData\Microsoft\Windows\WER`, `<profile>\AppData\Local\Microsoft\Windows\WER`. |
| T333 | `C:\Users\alex\Desktop\ubuntu-24.04-live-server-amd64.iso` | Review | Move | `Desktop` is deliberately not a rule: files there fall through to the later tiers. |
| T334 | `C:\Users\dev-01\Desktop\final_cut_v7.mp4` | Review | Move | `Desktop` is deliberately not a rule: files there fall through to the later tiers. |
| T335 | `C:\Users\Noura Al-Qahtani\Desktop\Reports\Annual Report 2023.pdf` | Review | Move | `Desktop` is deliberately not a rule: files there fall through to the later tiers. |
| T336 | `C:\USERS\ALEX\DESKTOP\MODEL.SAFETENSORS` | Review | Move | `Desktop` is deliberately not a rule: files there fall through to the later tiers. |

Some further rows kept their bucket but had `spec_section` or `rationale` refreshed (Desktop no longer a rule, section 9 split into 9 and 9a, Chromium and Office rows now decided by their own section, tier 2b wording).

## Rows added

T486 to T643 (158 rows, all adversarial): cases from the old AMBIGUITIES.md that revision 2 decides, plus probes of each new statement (`<profile>\rest` outside a profile, drive-root-only locations, whole-directory-name matching, tier 2b, section 9a, known folders and Desktop, the extension definition, wandb in site-packages, Blackmagic, Outlook non-.ost, WER, Rust target triples, revised sections 10 and 14).

# Revision 3

Derived from `docs/SPEC.md` revision 3 only. Every one of the 643 revision-2 rows was re-derived; 13 changed bucket.

## Rows whose expected bucket changed

| id | path | old | new | deciding revision-3 sentence |
| --- | --- | --- | --- | --- |
| T202 | `C:\Users\alex\AppData\Roaming\Microsoft\Teams\desktop-config.json` | Delete | Never | Teams (classic) cache: ... everything inside a directory whose name contains the text `Cache`. The rest of that folder is profile data and falls through. |
| T203 | `C:\Users\dev-01\AppData\Roaming\Slack\storage\root-state.json` | Delete | Never | Slack cache: ... everything inside a directory whose name contains the text `Cache`. The rest of that folder is profile data and falls through. |
| T262 | `D:\PortableApps\GoogleChromePortable\Data\profile\User Data\Default\Cache\Cache_Data\f_0003e1` | Delete | Review | Chromium-family caches: under a directory named `User Data` that is itself somewhere below `<profile>\AppData\Local` ... a `User Data` directory elsewhere is not a browser profile. |
| T355 | `C:\Users\Sara.Ahmed\AppData\Local\Microsoft\Windows\Explorer\thumbcache_256.db` | Delete | Review | Section 14: The match is on a whole directory name; a file whose own name contains `Cache` does not count. |
| T356 | `C:\Users\alex\AppData\Local\IconCache.db` | Delete | Review | Section 14: The match is on a whole directory name; a file whose own name contains `Cache` does not count. |
| T368 | `C:\Users\alex\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\perUserCache_0.dat` | Delete | Review | Section 14: `<profile>\AppData\Local\Packages\<package>\LocalCache` ... packaged-app data, not a cache despite the name. Final: the file-type fallback does not apply. |
| T369 | `C:\Users\alex\AppData\Local\Comms\UnistoreDB\store.cachefile.tmp` | Delete | Review | Section 14: The match is on a whole directory name; a file whose own name contains `Cache` does not count. |
| T371 | `C:\Users\alex\AppData\Local\Programs\Python\Python311\python.exe` | Review | Never | Section 12: `<profile>\AppData\Local\Programs` (per-user installs; anything not covered by sections 2 to 11) is Never. |
| T378 | `C:\Users\alex\AppData\Local\Programs\OBS Studio\data\intro_template.mov` | Move | Never | Section 12: `<profile>\AppData\Local\Programs` (per-user installs; anything not covered by sections 2 to 11) is Never. |
| T636 | `C:\Users\cache-admin\AppData\Local\Programs\Tool\tool.exe` | Review | Never | Section 12: `<profile>\AppData\Local\Programs` (per-user installs; anything not covered by sections 2 to 11) is Never. |
| T637 | `D:\PortableApps\Chrome\User Data\Default\Code Cache\js\3f9a1c7e2b4d6f8a_0` | Delete | Review | Chromium-family caches: under a directory named `User Data` that is itself somewhere below `<profile>\AppData\Local` ... a `User Data` directory elsewhere is not a browser profile. |
| T638 | `D:\PortableApps\Chrome\User Data\Default\GPUCache\data_1` | Delete | Review | Chromium-family caches: under a directory named `User Data` that is itself somewhere below `<profile>\AppData\Local` ... a `User Data` directory elsewhere is not a browser profile. |
| T640 | `C:\Users\alex\AppData\Roaming\Notion\User Data\Default\Cache\Cache_Data\data_0` | Delete | Never | Chromium-family caches: under a directory named `User Data` that is itself somewhere below `<profile>\AppData\Local` ... a `User Data` directory elsewhere is not a browser profile. |

Six further rows kept their bucket but had `spec_section` or `rationale` refreshed to the revision-3 wording.

## Rows added

T644 to T738 (95 rows, all adversarial): files whose own name contains Cache; directory names that begin with, end with or merely contain Cache; `Packages\<package>\LocalCache` (final Review, two directories between, new Teams exception, tier 2b and tier 3 inside it); TokenBroker; `AppData\Local\Programs` against reproducible artefacts, named stores, file-keyed rows and the generic rules; `User Data` inside and outside AppData\Local; Slack and classic Teams cache directories against their other files.

## Mechanical edit after revision 3

The sample user name in oracle paths was replaced by `alex` (same length class, no rule depends on the name). No expected bucket changed; the cross-check was re-run afterwards.
