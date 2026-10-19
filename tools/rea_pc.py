"""Extract compact pseudocode from a saved REA procedure_pseudo_code JSON result."""
import json, re, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
src = d['normalized_result'] if 'normalized_result' in d else d['result']
out = []
for ln in src.split('\n'):
    m = re.match(r'/\* line: \d+(?:, address: (0x[0-9a-f]+))? \*/ ?(.*)', ln)
    addr, code = (m.group(1), m.group(2)) if m else (None, ln)
    if re.match(r'\s+\S.*// \[?r', code) or re.match(r'\s+\S.*; // [a-z0-9]+$', code): continue  # local decls
    out.append(f"{addr[-6:] if addr else '      '} {code}")
txt = '\n'.join(out)
if len(sys.argv) > 2: open(sys.argv[2], 'w', encoding='utf-8').write(txt)
print(txt)
