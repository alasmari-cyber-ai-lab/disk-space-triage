#!/usr/bin/env python3
"""Cross-check the rule table in DiskSpaceTriage.ps1 against the oracle, without PowerShell.

Mirrors Get-TriageClassification: first matching wildcard wins (case-insensitive,
whole-string), then the file-type fallback, then Review. A development aid; the
authoritative run is tests/Oracle.Tests.ps1 on Windows.
"""
import csv, fnmatch, re, sys, pathlib

root = pathlib.Path(__file__).resolve().parent.parent
text = (root / "DiskSpaceTriage.ps1").read_text(encoding="ascii")

rules = re.findall(r"^\s*New-TriageRule\s+'([^']*)'\s+'([^']*)'\s+'([^']*)'\s+'([^']*)'", text, re.M)
ext_block = re.search(r"\$script:TriageMoveExtensions\s*=\s*@\((.*?)\)", text, re.S).group(1)
extensions = set(re.findall(r"'([^']+)'", ext_block))

def compile_rule(pattern):
    # "re:" rules are case-insensitive regular expressions searched in the path.
    # Everything else is a PowerShell wildcard (* ? [..]) over the whole path;
    # fnmatch agrees once both sides are lowercased.
    if pattern.startswith("re:"):
        rx = re.compile(pattern[3:], re.I)
        return lambda path: rx.search(path) is not None
    low = pattern.lower()
    return lambda path: fnmatch.fnmatchcase(path.lower(), low)

compiled = [(compile_rule(m), b, m) for m, b, mech, _ in rules]

def classify(path):
    for matches, bucket, pattern in compiled:
        if matches(path):
            return bucket, pattern
    leaf_start = path.rfind("\\") + 1
    dot = path.rfind(".")
    if dot > leaf_start and path[dot:].lower() in extensions:
        return "Move", "(file-type fallback)"
    return "Review", "(no match)"

rows = list(csv.DictReader(open(root / "tests/oracle/expected_classifications.csv", encoding="utf-8", newline="")))
fails = []
for r in rows:
    got, why = classify(r["path"])
    if got != r["expected_bucket"]:
        fails.append((r, got, why))

for r, got, why in fails:
    print(f"{r['id']}  expected {r['expected_bucket']:8} got {got:8} via {why}\n      {r['path']}\n      spec {r['spec_section']}: {r['rationale']}")
print(f"\n{len(rows) - len(fails)}/{len(rows)} agree, {len(fails)} differ   ({len(rules)} rules, {len(extensions)} extensions)")
sys.exit(1 if fails else 0)
