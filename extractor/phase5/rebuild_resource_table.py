#!/usr/bin/env python3
"""
rebuild_resource_table.py

Phase 5 resource table rebuilder for Open English Learning Archive.

Goal:
    Rebuild a higher-level resource table by correlating:
      - resource names from binfiles section 1
      - resource names from realfiles
      - blob candidates from binfiles
      - section classification evidence

Usage:
    python3 extractor/tools/rebuild_resource_table.py embeddb out_realfiles out_binfiles out_resource_table

Inputs:
    embeddb
    out_realfiles/realfiles_names.tsv
    out_realfiles/realfiles_lesson1.tsv
    out_binfiles/binfiles_resource_hits.tsv
    out_binfiles/binfiles_blob_candidates.tsv
    out_binfiles/binfiles_sections.json

Outputs:
    out_resource_table/resource_table.json
    out_resource_table/resource_table.tsv
    out_resource_table/lesson1_resource_table.tsv
    out_resource_table/section1_neighbors.tsv
    out_resource_table/rebuild_report.md

This tool does not extract final files. It builds the name -> neighborhood -> candidate blob map.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from collections import defaultdict, Counter
from typing import Iterable


def read_tsv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def write_tsv(path: Path, rows: Iterable[dict], columns: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        f.write("\t".join(columns) + "\n")
        for row in rows:
            vals = []
            for c in columns:
                v = row.get(c, "")
                if isinstance(v, (dict, list)):
                    v = json.dumps(v, ensure_ascii=False)
                if isinstance(v, str):
                    v = v.replace("\t", " ").replace("\n", "\\n").replace("\r", "\\r")
                vals.append(str(v))
            f.write("\t".join(vals) + "\n")


def ext_of(name: str) -> str:
    p = name.replace("\\", "/").split("?")[0]
    if "." not in p:
        return ""
    return p.rsplit(".", 1)[-1].lower()


def norm_name(name: str) -> str:
    p = name.replace("\\", "/")
    prefixes = [
        "g:/nceproject/第一册/1/",
        "G:/nceproject/第一册/1/",
    ]
    for pre in prefixes:
        if p.startswith(pre):
            p = p[len(pre):]
    # Some over-greedy scans may include bytes before the meaningful path.
    for marker in ["1-5.files/", "1-5.htm", "1-5.files", "filelist.xml"]:
        if marker in p:
            p = p[p.find(marker):]
    return p.strip("\x00\r\n\t ")


def safe_int(v: str, default: int = -1) -> int:
    try:
        return int(v)
    except Exception:
        return default


def load_sections(path: Path) -> list[dict]:
    if not path.exists():
        return []
    j = json.loads(path.read_text(encoding="utf-8"))
    return j.get("sections", [])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("embeddb", type=Path)
    ap.add_argument("realfiles_outdir", type=Path)
    ap.add_argument("binfiles_outdir", type=Path)
    ap.add_argument("outdir", type=Path)
    args = ap.parse_args()

    data = args.embeddb.read_bytes()
    out = args.outdir
    out.mkdir(parents=True, exist_ok=True)

    real_names = read_tsv(args.realfiles_outdir / "realfiles_names.tsv")
    real_lesson1 = read_tsv(args.realfiles_outdir / "realfiles_lesson1.tsv")
    bin_names = read_tsv(args.binfiles_outdir / "binfiles_resource_hits.tsv")
    blob_candidates = read_tsv(args.binfiles_outdir / "binfiles_blob_candidates.tsv")
    sections = load_sections(args.binfiles_outdir / "binfiles_sections.json")

    # Prefer section 1 based on Phase 4.3 evidence, but record all.
    section_bounds = {}
    for s in sections:
        section_bounds[str(s["section_index"])] = {
            "start": safe_int(str(s["schema_offset_dec"])),
            "end": safe_int(str(s["scan_end_dec"])),
            "span": safe_int(str(s.get("span_bytes", "")), 0),
        }

    # Build normalized binfiles resource records.
    resource_records = []
    for r in bin_names:
        name = norm_name(r.get("name", ""))
        if not name:
            continue
        section = str(r.get("section_index", ""))
        off = safe_int(r.get("offset_dec", ""))
        resource_records.append({
            "source": "binfiles",
            "section_index": section,
            "name": name,
            "ext": ext_of(name),
            "name_offset_dec": off,
            "name_offset_hex": hex(off) if off >= 0 else "",
            "raw_name": r.get("name", ""),
        })

    # Add realfiles names as secondary source.
    for r in real_names:
        name = norm_name(r.get("normalized") or r.get("filename") or "")
        if not name:
            continue
        off = safe_int(r.get("name_offset_dec", ""))
        resource_records.append({
            "source": "realfiles",
            "section_index": r.get("section_index", ""),
            "name": name,
            "ext": ext_of(name),
            "name_offset_dec": off,
            "name_offset_hex": hex(off) if off >= 0 else "",
            "raw_name": r.get("filename", ""),
        })

    # Group by normalized resource name.
    grouped = defaultdict(list)
    for r in resource_records:
        grouped[r["name"]].append(r)

    # Blob candidates normalized.
    blobs_by_section = defaultdict(list)
    for b in blob_candidates:
        section = str(b.get("section_index", ""))
        payload_off = safe_int(b.get("payload_offset_dec", ""))
        length_off = safe_int(b.get("length_field_offset_dec", ""))
        length_val = safe_int(b.get("length_value", ""))
        rec = {
            "section_index": section,
            "length_field_offset_dec": length_off,
            "length_field_offset_hex": hex(length_off) if length_off >= 0 else "",
            "length_value": length_val,
            "payload_offset_dec": payload_off,
            "payload_offset_hex": hex(payload_off) if payload_off >= 0 else "",
            "payload_signature": b.get("payload_signature", ""),
            "endian": b.get("endian", ""),
        }
        blobs_by_section[section].append(rec)

    for section in blobs_by_section:
        blobs_by_section[section].sort(key=lambda x: x["length_field_offset_dec"])

    # For each resource occurrence in section 1, find nearest neighbor resources and blobs.
    neighbor_rows = []
    resource_table = []
    for name, occs in sorted(grouped.items()):
        ext = ext_of(name)
        # Choose best occurrence: binfiles section 1 if present, else any binfiles, else realfiles.
        sorted_occs = sorted(
            occs,
            key=lambda x: (
                0 if x["source"] == "binfiles" and x["section_index"] == "1" else
                1 if x["source"] == "binfiles" else 2,
                x["name_offset_dec"] if x["name_offset_dec"] >= 0 else 10**18
            )
        )
        best = sorted_occs[0]
        section = best["section_index"]
        off = best["name_offset_dec"]

        same_section_resources = sorted(
            [r for r in resource_records if r["section_index"] == section and r["name_offset_dec"] >= 0],
            key=lambda x: x["name_offset_dec"]
        )
        positions = [r["name_offset_dec"] for r in same_section_resources]
        prev_name = next_name = ""
        prev_gap = next_gap = ""
        if off >= 0 and positions:
            idx = next((i for i, r in enumerate(same_section_resources) if r is best or (r["name"] == best["name"] and r["name_offset_dec"] == off)), None)
            if idx is not None:
                if idx > 0:
                    prev = same_section_resources[idx-1]
                    prev_name = prev["name"]
                    prev_gap = off - prev["name_offset_dec"]
                if idx + 1 < len(same_section_resources):
                    nxt = same_section_resources[idx+1]
                    next_name = nxt["name"]
                    next_gap = nxt["name_offset_dec"] - off

        # Nearest blob candidates in same section.
        blobs = blobs_by_section.get(section, [])
        nearest_blob_before = None
        nearest_blob_after = None
        if off >= 0 and blobs:
            before = [b for b in blobs if b["length_field_offset_dec"] <= off]
            after = [b for b in blobs if b["length_field_offset_dec"] > off]
            if before:
                nearest_blob_before = max(before, key=lambda b: b["length_field_offset_dec"])
            if after:
                nearest_blob_after = min(after, key=lambda b: b["length_field_offset_dec"])

        entry = {
            "name": name,
            "ext": ext,
            "best_source": best["source"],
            "best_section": section,
            "name_offset_dec": off,
            "name_offset_hex": hex(off) if off >= 0 else "",
            "occurrence_count": len(occs),
            "sources": sorted(set(o["source"] for o in occs)),
            "sections": sorted(set(o["section_index"] for o in occs)),
            "prev_name": prev_name,
            "prev_gap": prev_gap,
            "next_name": next_name,
            "next_gap": next_gap,
            "nearest_blob_before": nearest_blob_before or {},
            "nearest_blob_after": nearest_blob_after or {},
        }
        resource_table.append(entry)

        neighbor_rows.append({
            "name": name,
            "ext": ext,
            "best_source": best["source"],
            "best_section": section,
            "name_offset_hex": entry["name_offset_hex"],
            "prev_name": prev_name,
            "prev_gap": prev_gap,
            "next_name": next_name,
            "next_gap": next_gap,
            "blob_before_offset_hex": (nearest_blob_before or {}).get("length_field_offset_hex", ""),
            "blob_before_payload_hex": (nearest_blob_before or {}).get("payload_offset_hex", ""),
            "blob_before_len": (nearest_blob_before or {}).get("length_value", ""),
            "blob_before_sig": (nearest_blob_before or {}).get("payload_signature", ""),
            "blob_after_offset_hex": (nearest_blob_after or {}).get("length_field_offset_hex", ""),
            "blob_after_payload_hex": (nearest_blob_after or {}).get("payload_offset_hex", ""),
            "blob_after_len": (nearest_blob_after or {}).get("length_value", ""),
            "blob_after_sig": (nearest_blob_after or {}).get("payload_signature", ""),
        })

    # Lesson 1 focused rows.
    lesson_markers = ("1-5.htm", "1-5.files/")
    lesson_rows = [
        r for r in resource_table
        if r["name"].startswith("1-5.htm") or r["name"].startswith("1-5.files/") or "1-5" in r["name"]
    ]

    by_ext = Counter(r["ext"] for r in resource_table)
    by_section = Counter(r["best_section"] for r in resource_table)

    manifest = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "resource_count": len(resource_table),
        "resource_count_by_ext": dict(by_ext),
        "resource_count_by_best_section": dict(by_section),
        "blob_candidate_count": len(blob_candidates),
        "section_bounds": section_bounds,
        "lesson1_count": len(lesson_rows),
        "resources": resource_table,
        "note": "Resource table reconstruction. Offset/blob mapping is not final yet.",
    }

    (out / "resource_table.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    write_tsv(out / "resource_table.tsv", resource_table, [
        "name", "ext", "best_source", "best_section", "name_offset_dec", "name_offset_hex",
        "occurrence_count", "sources", "sections"
    ])

    write_tsv(out / "lesson1_resource_table.tsv", lesson_rows, [
        "name", "ext", "best_source", "best_section", "name_offset_dec", "name_offset_hex",
        "occurrence_count", "sources", "sections", "prev_name", "prev_gap", "next_name", "next_gap",
        "nearest_blob_before", "nearest_blob_after"
    ])

    write_tsv(out / "section1_neighbors.tsv", [r for r in neighbor_rows if r["best_section"] == "1"], [
        "name", "ext", "best_source", "best_section", "name_offset_hex",
        "prev_name", "prev_gap", "next_name", "next_gap",
        "blob_before_offset_hex", "blob_before_payload_hex", "blob_before_len", "blob_before_sig",
        "blob_after_offset_hex", "blob_after_payload_hex", "blob_after_len", "blob_after_sig"
    ])

    md = []
    md.append("# Resource table rebuild report\n")
    md.append(f"- source: `{args.embeddb}`")
    md.append(f"- size: `{len(data)}` bytes")
    md.append(f"- sha256: `{manifest['sha256']}`")
    md.append(f"- resources: `{len(resource_table)}`")
    md.append(f"- by ext: `{dict(by_ext)}`")
    md.append(f"- by best section: `{dict(by_section)}`")
    md.append(f"- blob candidates: `{len(blob_candidates)}`")
    md.append(f"- Lesson 1 candidates: `{len(lesson_rows)}`")
    md.append("\n## Lesson 1 rows\n")
    for r in lesson_rows[:30]:
        md.append(
            f"- `{r['name']}` ext `{r['ext']}` section `{r['best_section']}` "
            f"offset `{r['name_offset_hex']}`"
        )
        md.append(f"  prev `{r['prev_name']}` gap `{r['prev_gap']}`")
        md.append(f"  next `{r['next_name']}` gap `{r['next_gap']}`")
    md.append("\n## Interpretation\n")
    md.append("This table correlates resource names with local neighborhoods and nearest blob candidates. "
              "Next step: inspect section1_neighbors.tsv to infer record layout, then build extract_resource.py.")
    (out / "rebuild_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("OK: rebuild_resource_table")
    print(f"source: {args.embeddb}")
    print(f"resources: {len(resource_table)}")
    print(f"by ext: {dict(by_ext)}")
    print(f"by best section: {dict(by_section)}")
    print(f"blob candidates: {len(blob_candidates)}")
    print(f"Lesson 1 candidates: {len(lesson_rows)}")
    if lesson_rows:
        print("Lesson 1 sample:")
        for r in lesson_rows[:8]:
            print(f"  {r['name']} section={r['best_section']} offset={r['name_offset_hex']} ext={r['ext']}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
