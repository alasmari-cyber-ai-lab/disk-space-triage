# Decisions

Short records of choices that shape the tool, with the reason for each.

## 1. Packaging: stay one PowerShell + WPF file (November 2026)

**Question.** Should the tool become a compiled app (.NET WPF or WinUI 3,
shipped as a signed MSIX), or stay a single PowerShell script with a WPF
window?

**Decision.** Stay a single PowerShell 5.1 script with a WPF window for now.

**Why, measured against the two fixed requirements.**

| Requirement | PowerShell + WPF (now) | Compiled app, signed MSIX |
| --- | --- | --- |
| Least privilege | Runs as the current user. Nothing is installed, so nothing runs elevated at any point. | The app can run unelevated, but installing a package that is not signed by a trusted certificate needs administrator rights or Developer Mode. |
| No installer that needs admin | Two files, copied anywhere. | Needs a code-signing certificate that Windows trusts (a yearly cost and an identity check), or publication through the Microsoft Store. |
| Can be audited by the person running it | One plain-text file; the capability test parses it and pins every sensitive call. | A binary. Trust moves from "read it" to "trust the signature and the build". |
| Runs on a stock Windows 10/11 PC | Yes: PowerShell 5.1 and .NET Framework WPF ship with Windows. | Needs a .NET runtime bundled into the app (tens of megabytes) or installed first. |
| Look and feel | Windows 11 styling is hand-written XAML. Follows light, dark and high-contrast. The title bar cannot follow dark mode, and there is no Mica backdrop, because both need native calls the tool does not allow itself. | Native Fluent controls, dark title bar, backdrop materials, better screen-reader defaults. |
| Responsiveness | Long copies run on the window's thread with regular pauses to stay responsive; good enough to show progress and cancel. | Proper background work. |

The left column wins on the two requirements that are not negotiable, and
loses only on polish.

**What would change the decision.** Any one of:

- a code-signing certificate (or Store publication) becomes available, so a
  packaged app installs for a standard user without warnings;
- the audience grows beyond people who are comfortable starting a script;
- a feature needs something a script should not do (for example hard-link
  aware sizing or a dark title bar, which need native calls).

**If that happens.** Target the current long-term-support .NET release (.NET
10 at the time of writing; .NET 8 went out of support on 10 November 2026),
keep the classification rules, the oracle and the action tests as they are,
and port the engine before the window. The safety rules carry over unchanged:
no elevation, no network, Recycle Bin for removal, confirmation per item.

## 2. Emptying the Recycle Bin is in the tool (November 2026)

**Problem.** Delete and Move sent originals to the Recycle Bin. The Recycle
Bin of a drive is on that drive, so the drive stayed exactly as full, and the
tool did not say so anywhere a user would notice.

**Decision.** Keep the Recycle Bin as the only way originals are removed, and
add an explicit, separately confirmed **Empty Recycle Bin** step. Every action
now measures free space before and after and reports both, together with what
the Recycle Bin still holds.

**Trade-off accepted.** Windows empties the whole Recycle Bin of the drive
for the current user; the tool cannot limit that to its own items without
deleting files itself, which it must not do. The confirmation states the item
count, the size, and that everything in the bin is affected.

## 3. No enabling tick boxes (November 2026)

**Problem.** Each action tab had an "Allow" tick box, and the action button
stayed disabled until the box was ticked and a suitable row selected. Users
saw a dead button and no reason.

**Decision.** Remove the tick boxes. Buttons are enabled whenever the window
is idle; a button that cannot act says why. The safeguard that matters, a
per-item confirmation whose default answer is No, stays and is enforced by a
test.
