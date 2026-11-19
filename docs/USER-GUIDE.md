# User guide: acting on the report

Work through the buckets in this order. Each step is cheaper and safer than
the next, and may make the next one unnecessary.

1. **Delete** - reproducible things. Read the Why column first: an environment needs its package list exported, and `node_modules` needs a lockfile, before it can be rebuilt.
2. **Redirect** - change the setting and confirm it took effect. Then deal with the old folder: **delete it only if the Why column calls it a cache or re-downloadable; otherwise move its contents.** Recordings, game worlds, run logs and container data are yours, not caches.
3. **Move** - copy, verify, then remove the original. The tool does this for plain data files; for anything else, keep the original until you are sure.
4. **Administrator checklist** - once, by hand.

Aim for 15 to 20 percent free on the system drive, not for an empty drive.

## Fix with one setting (the tool does it for you)

For pure caches the window can make the change itself. On the **Fix with one
setting** tab, tick **Allow this tool to make these changes**, select a row
marked Ready, and choose **Apply selected**. The tool creates an empty folder
on the other drive and sets one user variable; it shows both before you
confirm.

- The new folder keeps its name and place: `C:\Users\you\.cache\huggingface`
  becomes `D:\FromC\Users\you\.cache\huggingface`, so its origin stays
  obvious. If that folder already exists with something in it, the tool
  refuses and asks you to look first.
- Nothing is moved or deleted. Close and reopen your terminals and
  applications (or sign out and in), use the program once, and check that
  files appear in the new folder.
- **Then follow what the tool says about the old folder.** For a pure cache
  (pip, uv, npm, NuGet, Go, Composer) delete it. For Ollama, move the models
  across: models you created yourself cannot be downloaded again. For Hugging
  Face, sign in again or copy the `token` file before deleting anything. For
  Keras, copy `keras.json`.
- **Undo last change** removes the variable again, until you close the
  window. Later, remove it yourself under Settings > System > About >
  Advanced system settings > Environment Variables, "User variables". Every
  change is listed in `DiskTriage_actions.csv` next to your reports.
- Use this on your own PC. On a shared computer the new folder may be
  readable by other users (see SECURITY.md). The other drive must be an
  internal NTFS disk that stays connected.

### What if a program insists on its C: path?

- **Redirecting a cache does not move the program.** `pip`, Python, Ollama and
  the rest stay installed where they are and keep running from `C:`. Only the
  folder where they store downloads changes, and they read its location from
  the variable every time they start. Nothing has to "run from D:".
- **A program with no setting and a hard-coded path** (iPhone backups are the
  usual example) is handled with a junction: move the folder to the other
  drive, then leave a junction at the old path. The program still sees its
  `C:` path; the data lives elsewhere. The tool does not do this for you; the
  steps are in the Move section below.
- **An installed program itself** must never be moved. Uninstall it and
  install it again on the other drive.
- **If something misbehaves after a redirect**, use Undo last change (or
  delete the variable in Settings > System > About > Advanced system settings
  > Environment Variables, under "User variables"). If you have not deleted
  the old folder, the program carries on as before; anything it downloaded
  into the new folder in the meantime stays there.

## Delete rebuildable folders (the tool does it for you)

On the **Delete rebuildable folders** tab, tick the box, select a row marked
Ready, and choose **Send selected to Recycle Bin**. The whole folder goes to
the Recycle Bin; restore it from there if you change your mind, and empty the
Recycle Bin to actually free the space.

- Only folders that rebuild or refill by themselves are listed. A row marked
  "Not possible" says why: no lockfile, something foreign inside, a link
  inside, or unreadable content.
- Close the application first for browser, Discord, Slack and Teams caches.
- After removing `node_modules`, run `npm ci` in that project when you next
  need it.
- Folders too large for the Recycle Bin, or with paths too long for it, are
  marked "Not possible": Windows could only delete them permanently. Remove
  those yourself in File Explorer if you are sure.
- If Windows ever asks whether to delete something permanently, answer No.

## Move files to the other drive (the tool does it for you)

On the **Move files to the other drive** tab, tick the box, select a file
marked Ready, and choose **Move selected file**. The file is copied to
`D:\FromC\<same folders>`, the copy is read back and compared with the
original, and only then is the original sent to the Recycle Bin.

- You can cancel while it runs; the partial copy is removed and the original
  stays.
- Nothing is overwritten. If a file of that name is already there, the tool
  stops and tells you.
- Update anything that referred to the old path (a notebook, a config file).
- Empty the Recycle Bin to free the space on C:.
- Only plain data files outside program folders, `AppData`, hidden tool
  folders and the usual sync folders are listed. Before moving a file, make
  sure no project or program still expects it at the old path and that its
  folder is not synced to a cloud service.
- The moved copy takes the permissions of the new folder; on a shared PC
  other users may be able to read it.
- If a move is interrupted (power cut, closing the black console window), a
  file ending in `.triage-partial` stays on the other drive. Delete it; the
  original is untouched.

## Redirect: the common settings

Set a user environment variable without administrator rights:

```
setx HF_HOME "D:\caches\huggingface"
```

It applies to newly opened terminals and applications.

| "What to do" in the report | How |
| --- | --- |
| `HF_HOME` | `setx HF_HOME "D:\caches\huggingface"`. Covers hub, datasets and metrics. |
| `TORCH_HOME`, `KERAS_HOME`, `TFDS_DATA_DIR`, `NLTK_DATA`, `OLLAMA_MODELS`, `TRITON_CACHE_DIR`, `WANDB_DIR` | Same pattern: `setx NAME "D:\..."`. Restart the tool afterwards. |
| `PIP_CACHE_DIR`, `UV_CACHE_DIR`, `POETRY_CACHE_DIR` | `setx NAME "D:\caches\..."`. Check with `pip cache dir`. |
| `pkgs_dirs in .condarc` | `conda config --add pkgs_dirs D:\conda\pkgs`. For new environments also `conda config --add envs_dirs D:\conda\envs`. |
| `npm config set cache` | `npm config set cache "D:\caches\npm"`. Check with `npm config get cache`. |
| `yarn cache-folder`, `pnpm store-dir` | `yarn config set cache-folder ...`, `pnpm config set store-dir ...`. |
| `NUGET_PACKAGES`, `GRADLE_USER_HOME`, `CARGO_HOME`, `GOMODCACHE`, `COMPOSER_CACHE_DIR`, `GEM_HOME`, `VAGRANT_HOME`, `ANDROID_SDK_ROOT`, `ANDROID_AVD_HOME` | `setx NAME "D:\..."`. |
| `localRepository` | In `%USERPROFILE%\.m2\settings.xml`: `<localRepository>D:\caches\m2</localRepository>`. |
| `Settings > Resources > Disk image location` | Docker Desktop moves the data for you when you change this. To shrink it first, look with `docker system df`, then remove what you do not need (`docker image prune`). Be careful with `docker system prune -a`: it deletes every stopped container, every unused image and the build cache. Never delete the folder by hand. |
| `wsl --manage --move` | `wsl --shutdown`, then `wsl --manage <distro> --move D:\WSL\<distro>`. |
| `Shrink cached period, or ForceOSTPath` | Outlook: File > Account Settings > Change > Mail to keep offline. Shrinking is easier than moving. |
| `Settings > Recording` | Zoom: change where local recordings are stored. |
| `Preferences > Media Cache` | Adobe Premiere / After Effects. The same dialog can delete unused cache. |
| `browser.cache.disk.parent_directory` | Firefox, in `about:config`. |

For a true cache (pip, npm, conda packages, Hugging Face downloads), do not
copy the old contents: set the variable, confirm it, delete the old folder,
and let it refill in the new place.

For everything else in the Redirect list, the old folder holds data. Zoom
recordings, Minecraft worlds, Weights and Biases runs, Docker volumes, the
DaVinci Resolve project library, Telegram data and the iTunes library must be
moved (ideally by the application itself), never deleted. Models and weights
you trained yourself are not caches either.

## Delete

| "What to do" | Meaning |
| --- | --- |
| `Reinstall from lockfile` | `node_modules`. If the project has a `package-lock.json`, delete the folder; `npm ci` rebuilds it. Without a lockfile, keep it. |
| `Recreate on the other drive`, `Export, then recreate on the other drive` | Virtual and conda environments. They store absolute paths and break when copied. First save the package list (`pip freeze > requirements.txt`, `conda env export > env.yml`), then delete, then recreate. |
| `Regenerates` | Application caches. Close the application first. For the Office document cache, let Office finish uploading your changes before clearing it. |
| `TEMP / TMP` | Temporary files. Settings > System > Storage > Temporary files does this safely. Leave the **Downloads** box unticked there. |
| `Empty Recycle Bin` | Right-click the Recycle Bin. |

## Move

| "What to do" | How |
| --- | --- |
| `Properties > Location tab` | Right-click Downloads, Documents, Pictures, Videos or Music > Properties > Location > Move. Point it at a named folder such as `D:\Users\you\Downloads`, never at the root of the drive. |
| `Explorer move` | Ordinary data files. Move them, then fix any project that referenced the old path. |
| `Steam > Storage > Move` | Add a library folder on the other drive in Steam, then move each game. Other launchers: use their own move function, or reinstall to D:. |
| `Move + mklink /J` | iPhone backups have no setting. Close the Apple software, move the `Backup` folder to D:, then, in a Command Prompt (not PowerShell), `mklink /J "<original path>" "D:\AppleBackup"`. |
| `Owning tool only`, `Machine > Move`, `Hyper-V Manager > Move` | Virtual machines. Shut the machine down and move it with its own tool. |
| `Files On-Demand` | OneDrive. Do not move the folder. Right-click large folders > Free up space. |

To undo a junction, open a Command Prompt (not PowerShell) and run
`rmdir "<link>"`, or from PowerShell `cmd /c rmdir "<link>"`. Never use
PowerShell's own `rmdir`/`Remove-Item`, `del /s` or Shift+Delete on a
junction: they can remove the files at the other end.

## Never and Review

**Never** means the path is recorded in the registry or belongs to Windows.
Free that space by uninstalling the program and installing it on another
drive, or with the administrator checklist. `C:\Windows\Installer` and
`C:\Windows\WinSxS` are not caches, whatever a size listing suggests.

**Review** means no rule matched. Find out which program owns the file before
doing anything with it.

## Administrator checklist

These are often the largest items and the tool does not measure them. Start
with Disk Cleanup (`cleanmgr` > Clean up system files): Windows Update
cleanup, previous Windows installations and the delivery cache usually return
tens of gigabytes. Then consider shrinking the hibernation file
(`powercfg /h /size 40`) and moving most of the page file, leaving a small one
on the system drive so crash dumps still work.
