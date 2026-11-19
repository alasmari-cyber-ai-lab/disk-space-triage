#!/usr/bin/env python3
"""Local syntax check for DiskSpaceTriage.ps1 using the tree-sitter PowerShell grammar.

A development aid for machines without PowerShell. The authoritative checks are
the Pester tests that run on Windows in CI.
    pip install tree-sitter tree-sitter-powershell
"""
import sys
import tree_sitter_powershell as tsp
from tree_sitter import Language, Parser

path = sys.argv[1] if len(sys.argv) > 1 else "DiskSpaceTriage.ps1"
import re
source = open(path, "rb").read()
# The grammar does not know numeric multipliers (1MB, 2GB); neutralise them, keeping offsets.
source = re.sub(rb"\b(\d+)(KB|MB|GB|TB)\b", lambda m: m.group(1) + b"  ", source)
# Valid PowerShell that the grammar cannot parse; lines matching these are not reported.
KNOWN_GAPS = [
    re.compile(r"\b(Select-Object|Format-Table|Add-Type)\b.*\w, \w"),   # bare-word comma lists
    re.compile(r"\[System\.Action\]\{"),                                # scriptblock cast
]
tree = Parser(Language(tsp.language())).parse(source)

problems = []
def walk(node):
    if node.type == "ERROR" or node.is_missing:
        problems.append(node)
        return
    for child in node.children:
        walk(child)
walk(tree.root_node)

lines = source.splitlines()
problems = [n for n in problems
            if not any(g.search(lines[n.start_point[0]].decode("utf-8", "replace")) for g in KNOWN_GAPS)]
for node in problems[:25]:
    line = node.start_point[0] + 1
    text = lines[node.start_point[0]].decode("utf-8", "replace").strip()
    print(f"{path}:{line}: {'missing ' + node.type if node.is_missing else 'syntax error'}: {text[:110]}")
print(f"{len(problems)} problem(s)")
sys.exit(1 if problems else 0)
