# Oracle ambiguities (against SPEC.md revision 2)

Cases left out of `expected_classifications.csv` because revision 2 still does
not determine a single bucket. Derived from `docs/SPEC.md` only. All 13
revision-1 entries are resolved and now have rows in the CSV.

## B1. `logs` directly inside `AppData\Local`

* Path: `C:\Users\khalid\AppData\Local\logs\updater.log`
* Candidates: Delete versus Review.
* Tension: "a directory named `logs` at any depth below `AppData\Local\<app>\`". Here `logs` occupies the `<app>` position itself, so it is not below an app directory, yet it is a logs directory under AppData\Local.

## B2. File-keyed rows and a dotfile name

* Paths: `D:\dumps\.dmp`, `D:\VMs\.vhdx`
* Candidates: Delete / Move versus Review.
* Tension: the rows read "Memory dump files (`.dmp`)" and "Any other virtual disk (`.vhdx`, ...)" without saying they key on the extension; the extension definition says a name whose only `.` is its first character has none.

## B3. Is the WSL row tier 2 or tier 2b

* Path: `C:\Users\khalid\AppData\Local\Temp\restore\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState\ext4.vhdx`
* Candidates: Redirect (WSL row is a tier 2 named store and is deeper than user temp) versus Delete (WSL row is file-keyed, so user temp, a tier 2 store, excludes it).
* Tension: tier 2b is described as "virtual disks in section 5", which could include the WSL row ("any `.vhdx` file under ..."), but only the "Any other virtual disk" row is marked "(file-keyed, tier 2b)". The CSV treats the WSL row as tier 2 and only includes cases where both readings agree.

## B4. A directory named exactly `Previews.lrdata`

* Path: `D:\Photos\Catalog\Previews.lrdata\previews.db`
* Candidates: Move versus Review.
* Tension: "a `... Previews.lrdata` directory" does not say whether the leading text is required.

## B5. Degenerate OneDrive business names

* Paths: `C:\Users\khalid\OneDrive - \notes.txt` is not a legal name, but `C:\Users\khalid\OneDrive -Contoso\notes.txt` and `C:\Users\khalid\OneDrive  -  Contoso\notes.txt` are
* Candidates: Never versus Review.
* Tension: "`OneDrive - <anything>`" does not say how strict the ` - ` separator is. (`OneDrive-Contoso`, with no spaces at all, is in the CSV as Review.)
