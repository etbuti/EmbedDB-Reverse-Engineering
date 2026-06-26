#!/usr/bin/env python3
"""
compare_record_layout.py

Phase 7.1: compare neighbouring resource records horizontally.

Usage:
    python3 extractor/tools/compare_record_layout.py \
        embeddb out_resource_table out_record_compare

Outputs:
    out_record_compare/record_compare.tsv
    out_record_compare/lesson1_compare.tsv
    out_record_compare/byte_columns.tsv
    out_record_compare/compare_report.md

Purpose:
    Compare bytes around multiple resource-name offsets so repeated
    record fields can be identified.
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
from pathlib import Path
from collections import Counter, defaultdict


def ascii_byte(b: int) -> str:
    return chr(b) if 32 <= b < 127 else "."


def read_resource_table(path: Path) -> list[dict]:
    j = json.loads((path/"resource_table.json").read_text(encoding="utf-8"))
    return j["resources"]


def norm_lesson(name: str) -> bool:
    return "1-5" in name or "1-51" in name or "1-53" in name or "1-55" in name


def dump_row(data: bytes, name: str, off: int, before: int, after: int) -> dict:
    start = max(0, off-before)
    end = min(len(data), off+after)
    buf = data[start:end]
    return {
        "name": name,
        "name_offset_hex": hex(off),
        "window_start_hex": hex(start),
        "window_len": len(buf),
        "hex": " ".join(f"{b:02X}" for b in buf),
        "ascii": "".join(ascii_byte(b) for b in buf),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("embeddb", type=Path)
    ap.add_argument("resource_dir", type=Path)
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--before", type=int, default=64)
    ap.add_argument("--after", type=int, default=160)
    args = ap.parse_args()

    data = args.embeddb.read_bytes()
    resources = read_resource_table(args.resource_dir)
    out = args.outdir
    out.mkdir(parents=True, exist_ok=True)

    # Use section 1 resources, sorted by actual name offset.
    rs = []
    for r in resources:
        if str(r.get("best_section")) != "1":
            continue
        off = int(r["name_offset_dec"])
        if off >= 0:
            rs.append((off, r["name"], r))
    rs.sort()

    rows = [dump_row(data, name, off, args.before, args.after) for off, name, _ in rs]
    lesson_rows = [row for row in rows if norm_lesson(row["name"])]

    # Byte-column comparison around lesson resources.
    # For each relative position, report common byte values.
    byte_cols = []
    selected = [(off, name, r) for off, name, r in rs if norm_lesson(name)]
    for rel in range(-args.before, args.after):
        vals = []
        for off, name, r in selected:
            pos = off + rel
            if 0 <= pos < len(data):
                vals.append(data[pos])
        if not vals:
            continue
        c = Counter(vals)
        common = c.most_common(5)
        byte_cols.append({
            "relative_offset": rel,
            "common_values_hex": ",".join(f"{v:02X}:{n}" for v,n in common),
            "ascii_common": ",".join(f"{ascii_byte(v)}:{n}" for v,n in common),
            "unique_count": len(c),
            "sample_count": len(vals),
        })

    # DWORD interpretation around lesson name offsets.
    dword_rows = []
    for off, name, _ in selected:
        for rel in range(-args.before, args.after-3, 4):
            pos = off + rel
            if 0 <= pos+4 <= len(data):
                chunk = data[pos:pos+4]
                le = struct.unpack("<I", chunk)[0]
                be = struct.unpack(">I", chunk)[0]
                dword_rows.append({
                    "name": name,
                    "name_offset_hex": hex(off),
                    "relative_offset": rel,
                    "absolute_offset_hex": hex(pos),
                    "bytes_hex": chunk.hex(),
                    "le_uint32": le,
                    "le_hex": hex(le),
                    "be_uint32": be,
                    "be_hex": hex(be),
                    "le_inside_file": 0 <= le < len(data),
                    "be_inside_file": 0 <= be < len(data),
                })

    def write_tsv(path, rows, fields):
        with open(path, "w", encoding="utf-8", newline="") as f:
            w=csv.DictWriter(f, fieldnames=fields, delimiter="\t")
            w.writeheader()
            for r in rows:
                w.writerow(r)

    write_tsv(out/"record_compare.tsv", rows, ["name","name_offset_hex","window_start_hex","window_len","hex","ascii"])
    write_tsv(out/"lesson1_compare.tsv", lesson_rows, ["name","name_offset_hex","window_start_hex","window_len","hex","ascii"])
    write_tsv(out/"byte_columns.tsv", byte_cols, ["relative_offset","common_values_hex","ascii_common","unique_count","sample_count"])
    write_tsv(out/"lesson1_dwords.tsv", dword_rows, [
        "name","name_offset_hex","relative_offset","absolute_offset_hex",
        "bytes_hex","le_uint32","le_hex","be_uint32","be_hex",
        "le_inside_file","be_inside_file"
    ])

    md = []
    md.append("# Phase 7.1 record layout comparison\n")
    md.append(f"- total section1 records: `{len(rows)}`")
    md.append(f"- lesson-like records: `{len(lesson_rows)}`")
    md.append(f"- window: `-{args.before}` / `+{args.after}` bytes around resource name offset")
    md.append("\n## Next inspection targets\n")
    md.append("- `lesson1_compare.tsv`: visual hex/ascii comparison around lesson resources")
    md.append("- `byte_columns.tsv`: stable and variable byte columns")
    md.append("- `lesson1_dwords.tsv`: little/big endian DWORD values around names")
    md.append("\nLook for relative offsets where DWORDs form monotonic, repeated, or in-file values.")
    (out/"compare_report.md").write_text("\n".join(md)+"\n", encoding="utf-8")

    print("OK: compare_record_layout")
    print("section1 records:", len(rows))
    print("lesson-like records:", len(lesson_rows))
    print("output:", out)

if __name__ == "__main__":
    main()
