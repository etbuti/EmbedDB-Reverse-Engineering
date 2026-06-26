#!/usr/bin/env python3
"""
Phase 6.1: extract_resource.py

Current goal:
- consume resource_table.json
- normalize recovered names
- correlate nearby blob candidates
- produce extraction worklist

This is intentionally conservative: it prepares verified extraction jobs
instead of guessing payload boundaries.
"""
import argparse,json,csv,re
from pathlib import Path

def fix_name(name:str)->str:
    # Repair over-scanned names like 1-51.htm -> 1-5.htm
    name=name.replace("\\","/")
    name=re.sub(r'(\d-\d)(1)(\.htm)$',r'\1\2',name)
    name=re.sub(r'(\d-\d)(3)(\.htm)$',r'\1\2',name)
    name=re.sub(r'(\d-\d)(5)(\.htm)$',r'\1\2',name)
    name=re.sub(r'(\d-\d)(1)(\.files/)',r'\1\2',name)
    name=re.sub(r'(\d-\d)(3)(\.files/)',r'\1\2',name)
    name=re.sub(r'(\d-\d)(5)(\.files/)',r'\1\2',name)
    return name

ap=argparse.ArgumentParser()
ap.add_argument("resource_dir",type=Path)
ap.add_argument("outdir",type=Path)
args=ap.parse_args()

rt=json.loads((args.resource_dir/"resource_table.json").read_text(encoding="utf-8"))
out=args.outdir
out.mkdir(parents=True,exist_ok=True)

rows=[]
for r in rt["resources"]:
    fixed=fix_name(r["name"])
    before=r.get("nearest_blob_before",{})
    after=r.get("nearest_blob_after",{})
    rows.append({
        "name":fixed,
        "section":r["best_section"],
        "offset":r["name_offset_hex"],
        "blob_before":before.get("payload_offset_hex",""),
        "blob_after":after.get("payload_offset_hex",""),
        "status":"pending-boundary-resolution"
    })

with (out/"extraction_worklist.tsv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0].keys()),delimiter="\t")
    w.writeheader();w.writerows(rows)

(out/"phase6_report.md").write_text(
f"# Phase 6 worklist\n\nResources: {len(rows)}\n\n"
"Next objective:\n"
"1. infer record boundaries\n"
"2. recover first HTML\n"
"3. recover linked JPG\n"
"4. validate against browser rendering\n",
encoding="utf-8")

print("OK: extract_resource")
print("resources:",len(rows))
print("worklist:",out/"extraction_worklist.tsv")
