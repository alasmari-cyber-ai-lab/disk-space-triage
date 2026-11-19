# User guide: acting on the report

Work through the buckets in this order. Each step is cheaper and safer than
the next, and may make the next one unnecessary.

1. **Delete** - nothing to verify, nothing to undo.
2. **Redirect** - set the setting, confirm it took effect, then delete the old folder.
3. **Move** - copy, verify, rename the original, delete it a few days later.
4. **Administrator checklist** - once, by hand.

Aim for 15 to 20 percent free on the system drive, not for an empty drive.

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
| `Settings > Resources > Disk image location` | Docker Desktop. Run `docker system prune -a` first; it often frees most of the space on its own. |
| `wsl --manage --move` | `wsl --shutdown`, then `wsl --manage <distro> --move D:\WSL\<distro>`. |
| `Shrink cached period, or ForceOSTPath` | Outlook: File > Account Settings > Change > Mail to keep offline. Shrinking is easier than moving. |
| `Settings > Recording` | Zoom: change where local recordings are stored. |
| `Preferences > Media Cache` | Adobe Premiere / After Effects. The same dialog can delete unused cache. |
| `browser.cache.disk.parent_directory` | Firefox, in `about:config`. |

For a cache, do not copy the old contents. Set the variable, delete the old
folder, and let it refill in the new place.

Models and weights you trained yourself are not caches. Move them like any
other data.

## Delete

| "What to do" | Meaning |
| --- | --- |
| `Reinstall from lockfile` | `node_modules`. Delete it; `npm ci` rebuilds it. |
| `Recreate on D:` | Virtual and conda environments. They store absolute paths and break when copied. Export (`pip freeze`, `conda env export`), delete, recreate. |
| `Regenerates` | Application caches. Close the application first. |
| `TEMP / TMP` | Temporary files. Settings > System > Storage > Temporary files does this safely. |
| `Empty Recycle Bin` | Right-click the Recycle Bin. |

## Move

| "What to do" | How |
| --- | --- |
| `Properties > Location tab` | Right-click Downloads, Documents, Pictures, Videos or Music > Properties > Location > Move. Point it at a named folder such as `D:\Users\you\Downloads`, never at the root of the drive. |
| `Explorer move` | Ordinary data files. Move them, then fix any project that referenced the old path. |
| `Steam > Storage > Move` | Add a library folder on D: in Steam, then move each game. Other launchers: use their own move function, or reinstall to D:. |
| `Move + mklink /J` | iPhone backups have no setting. Close the Apple software, move the `Backup` folder to D:, then `mklink /J "<original path>" "D:\AppleBackup"`. |
| `Owning tool only`, `Machine > Move`, `Hyper-V Manager > Move` | Virtual machines. Shut the machine down and move it with its own tool. |
| `Files On-Demand` | OneDrive. Do not move the folder. Right-click large folders > Free up space. |

To undo a junction, use `rmdir "<link>"`. Never delete a junction with
`del /s` or Shift+Delete: that can remove the files at the other end.

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
