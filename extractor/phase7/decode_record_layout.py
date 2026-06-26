#!/usr/bin/env python3
"""
decode_record_layout.py

Phase 7: inspect the binary layout around resource records.

Usage:
    python3 extractor/tools/decode_record_layout.py \
        embeddb out_resource_table out_record_layout

Purpose:
    Dump fixed-size windows around every resource name so the actual
    record structure (offset/size/id fields) can be inferred.
"""

import argparse, json, struct
from pathlib import Path

def hexdump(buf, base):
    lines=[]
    for i in range(0,len(buf),16):
        chunk=buf[i:i+16]
        hx=" ".join(f"{b:02X}" for b in chunk)
        asc="".join(chr(b) if 32<=b<127 else "." for b in chunk)
        lines.append(f"{base+i:08X}  {hx:<47}  {asc}")
    return "\n".join(lines)

ap=argparse.ArgumentParser()
ap.add_argument("embeddb",type=Path)
ap.add_argument("resource_dir",type=Path)
ap.add_argument("outdir",type=Path)
args=ap.parse_args()

data=args.embeddb.read_bytes()
rt=json.loads((args.resource_dir/"resource_table.json").read_text(encoding="utf-8"))

out=args.outdir
(out/"records").mkdir(parents=True,exist_ok=True)

summary=[]

for r in rt["resources"]:
    off=int(r["name_offset_dec"])
    if off<0: continue
    start=max(0,off-128)
    end=min(len(data),off+256)
    block=data[start:end]

    words=[]
    for p in range(0,len(block)-4,4):
        v=struct.unpack_from("<I",block,p)[0]
        if 0 < v < len(data):
            words.append({
                "record_offset":hex(start+p),
                "value":v,
                "value_hex":hex(v)
            })

    name=r["name"].replace("/","_")
    outfile=out/"records"/f"{off:08X}_{name}.txt"
    outfile.write_text(
        f"RESOURCE: {r['name']}\n"
        f"OFFSET: {hex(off)}\n\n"
        "HEXDUMP\n"
        "=======\n"
        f"{hexdump(block,start)}\n\n"
        "POSSIBLE 32-BIT OFFSETS\n"
        "=======================\n"
        + "\n".join(f"{w['record_offset']} -> {w['value_hex']}" for w in words),
        encoding="utf-8"
    )

    summary.append({
        "name":r["name"],
        "offset":hex(off),
        "candidate_pointer_count":len(words),
        "dump":outfile.name
    })

(out/"record_summary.json").write_text(
    json.dumps(summary,indent=2,ensure_ascii=False),
    encoding="utf-8"
)

(out/"README.md").write_text(
"""# Phase 7

Inspect the generated record dumps.

Look for repeating structures:

- filename
- 32-bit pointer
- size
- id

When several neighbouring records share the same layout,
the record format can be reconstructed.
""",encoding="utf-8")

print("OK: decode_record_layout")
print("records:",len(summary))
print("output:",out)
