# Oracle ambiguities (against SPEC.md revision 3)

Cases left out of `expected_classifications.csv` because revision 3 still does
not determine a single bucket. Derived from `docs/SPEC.md` only. C1 to C5 are
carried over unchanged from revision 2 (there B1 to B5); C6 and C7 are new.

## C1. `logs` directly inside `AppData\Local`

* Path: `C:\Users\alex\AppData\Local\logs\updater.log`
* Candidates: Delete versus Review.
* Tension: "a directory named `logs` at any depth below `AppData\Local\<app>\`". Here `logs` occupies the `<app>` position itself.

## C2. File-keyed rows and a dotfile name

* Paths: `D:\dumps\.dmp`, `D:\VMs\.vhdx`
* Candidates: Delete / Move versus Review.
* Tension: the file-keyed rows read "Memory dump files (`.dmp`)" and "Any other virtual disk (`.vhdx`, ...)" without saying they key on the extension; by the extension definition these names have none.

## C3. Is the WSL row tier 2 or tier 2b

* Path: `C:\Users\alex\AppData\Local\Temp\restore\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState\ext4.vhdx`
* Candidates: Redirect (WSL row is a tier 2 store, deeper than user temp) versus Delete (WSL row is file-keyed, so user temp excludes it).
* Tension: tier 2b is "virtual disks in section 5", which could include the WSL row, but only the "Any other virtual disk" row is marked "(file-keyed, tier 2b)".

## C4. A directory named exactly `Previews.lrdata`

* Path: `D:\Photos\Catalog\Previews.lrdata\previews.db`
* Candidates: Move versus Review.
* Tension: "a `... Previews.lrdata` directory" does not say whether leading text is required.

## C5. Degenerate OneDrive business names

* Paths: `C:\Users\alex\OneDrive -Contoso\notes.txt`, `C:\Users\alex\OneDrive  -  Contoso\notes.txt`
* Candidates: Never versus Review.
* Tension: "`OneDrive - <anything>`" does not say how strict the ` - ` separator is.

## C6. Other section 14 rows nested inside a "final Review" location

* Paths: `C:\Users\alex\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\Local\pip\Cache\http-v2\a\1\a1c9f0d2`, `C:\Users\alex\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalCache\logs\terminal.log`, `C:\Users\alex\AppData\Local\Microsoft\TokenBroker\logs\broker.log`
* Candidates: Review versus Delete.
* Tension: the two Review rows are "Final: the file-type fallback does not apply", which only names the file-type fallback. The spec gives no order among rows of the same tier, so it does not say whether a `Cache`-named or `logs` directory *nested inside* LocalCache or TokenBroker is Delete. (The CSV does include `TokenBroker\Cache\*.tbres` and files directly under `LocalCache` as Review: the Review rows would have no effect at all if the Cache rule beat them on the very directory they name.)

## C7. Zero directories between `Packages` and `LocalCache`

* Path: `C:\Users\alex\AppData\Local\Packages\LocalCache\state.bin`
* Candidates: Delete (not "exactly one directory between", and LocalCache ends with Cache) versus Review.
* Tension: literal reading gives Delete, but `LocalCache` here would itself be the `<package>` directory; the row does not address it. Not a realistic path; listed for completeness.
