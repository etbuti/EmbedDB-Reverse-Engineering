#!/usr/bin/env python3
"""
parse_realfiles.py

Phase 2.2 evidence parser for the `realfiles[filename:S,offset:I,size:I]`
table in the MyEbook / ebookmm `embeddb` container.

Usage:
    python3 extractor/tools/parse_realfiles.py embeddb out_realfiles

Outputs:
    out_realfiles/realfiles_sections.json
    out_realfiles/realfiles_names.tsv
    out_realfiles/realfiles_lesson1.tsv
    out_realfiles/realfiles_integer_candidates.tsv
    out_realfiles/realfiles_report.md

Important:
    This version is intentionally conservative. It parses the visible filename
    table and collects evidence around likely offset/size columns, but it does
    not yet claim final payload extraction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Iterable


REALFILES_SCHEMA = b"realfiles[filename:S,offset:I,size:I]"
BINFILES_SCHEMA = b"binfiles[filename:S,bindata:B]"
FULL_PATH_RE = re.compile(rb"g:/nceproject/.*?\x00", re.DOTALL)


def find_all(data: bytes, needle: bytes) -> list[int]:
    out = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        out.append(idx)
        start = idx + 1
    return out


def decode_gbk(raw: bytes) -> str:
    raw = raw.rstrip(b"\x00")
    for enc in ("gb18030", "gbk", "utf-8", "latin1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.hex()


def ext_of(path: str) -> str:
    p = path.replace("\\", "/").split("?")[0]
    if "." not in p:
        return ""
    return p.rsplit(".", 1)[-1].lower()


def normalize_path(path: str) -> str:
    p = path.replace("\\", "/")
    prefix = "g:/nceproject/第一册/1/"
    if p.startswith(prefix):
        return p[len(prefix):]
    return p


def write_tsv(path: Path, rows: Iterable[dict], columns: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        f.write("\t".join(columns) + "\n")
        for row in rows:
            vals = []
            for c in columns:
                v = row.get(c, "")
                if isinstance(v, str):
                    v = v.replace("\t", " ").replace("\n", "\\n").replace("\r", "\\r")
                vals.append(str(v))
            f.write("\t".join(vals) + "\n")


def ascii_preview(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def section_boundaries(data: bytes) -> list[dict]:
    real_hits = find_all(data, REALFILES_SCHEMA)
    bin_hits = find_all(data, BINFILES_SCHEMA)

    # Use next schema occurrence or EOF as a conservative boundary.
    all_schema_hits = sorted(set(real_hits + bin_hits + [len(data)]))
    sections = []

    for idx, off in enumerate(real_hits):
        next_schema = len(data)
        for h in all_schema_hits:
            if h > off:
                next_schema = h
                break

        # Expand a little after the next schema if this is a short duplicate,
        # because some containers repeat table declarations before data.
        scan_end = next_schema
        if scan_end - off < 4096:
            scan_end = min(len(data), off + 90000)

        blob = data[off:scan_end]
        paths = []
        for m in FULL_PATH_RE.finditer(blob):
            abs_off = off + m.start()
            raw = m.group(0)[:-1]
            name = decode_gbk(raw)
            paths.append({
                "index": len(paths),
                "name_offset_dec": abs_off,
                "name_offset_hex": hex(abs_off),
                "filename": name,
                "normalized": normalize_path(name),
                "ext": ext_of(name),
                "raw_len": len(raw),
            })

        first_name = paths[0]["name_offset_dec"] if paths else None
        last_name_end = paths[-1]["name_offset_dec"] + paths[-1]["raw_len"] + 1 if paths else None

        sections.append({
            "section_index": idx,
            "schema_offset_dec": off,
            "schema_offset_hex": hex(off),
            "scan_end_dec": scan_end,
            "scan_end_hex": hex(scan_end),
            "path_count": len(paths),
            "first_name_offset_dec": first_name,
            "first_name_offset_hex": hex(first_name) if first_name is not None else "",
            "last_name_end_dec": last_name_end,
            "last_name_end_hex": hex(last_name_end) if last_name_end is not None else "",
            "paths": paths,
            "schema_window_ascii": ascii_preview(data[off: min(len(data), off + 256)]),
        })

    return sections


def integer_candidates(data: bytes, start: int, end: int, file_size: int) -> list[dict]:
    """Scan a span for plausible little/big-endian int32 values.

    This is evidence only. A value is considered "offset-like" if it points
    inside the file. It is considered "size-like" if it is a positive value
    smaller than the file.
    """
    rows = []
    start = max(0, start)
    end = min(len(data), end)
    for off in range(start, max(start, end - 3)):
        chunk = data[off:off+4]
        if len(chunk) != 4:
            continue
        le_u = struct.unpack("<I", chunk)[0]
        be_u = struct.unpack(">I", chunk)[0]
        le_s = struct.unpack("<i", chunk)[0]
        be_s = struct.unpack(">i", chunk)[0]

        for endian, unsigned, signed in (
            ("le", le_u, le_s),
            ("be", be_u, be_s),
        ):
            kind = []
            if 0 <= unsigned < file_size:
                kind.append("offset-like")
            if 0 < unsigned < file_size:
                kind.append("size-like")
            # Favor values that point near known binary-looking areas.
            if kind and (unsigned > 256 or unsigned in (0, 1, 2, 3)):
                rows.append({
                    "offset_dec": off,
                    "offset_hex": hex(off),
                    "endian": endian,
                    "uint32": unsigned,
                    "int32": signed,
                    "kind": ",".join(kind),
                    "bytes_hex": chunk.hex(),
                })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("embeddb", type=Path)
    ap.add_argument("outdir", type=Path)
    args = ap.parse_args()

    data = args.embeddb.read_bytes()
    out = args.outdir
    out.mkdir(parents=True, exist_ok=True)

    sections = section_boundaries(data)
    best = max(sections, key=lambda s: s["path_count"]) if sections else None

    all_name_rows = []
    lesson_rows = []
    if best:
        for p in best["paths"]:
            row = {
                "section_index": best["section_index"],
                **p,
            }
            all_name_rows.append(row)
            n = p["normalized"].lower()
            if n.startswith("1-5.") or "1-5.files" in n or "/1-5." in n:
                lesson_rows.append(row)

    int_rows = []
    if best and best["first_name_offset_dec"] is not None:
        # The most suspicious area is immediately before the filename block:
        # it may contain column data for offset/size, row count, or indexes.
        int_start = best["first_name_offset_dec"] - 2048
        int_end = best["first_name_offset_dec"] + 256
        int_rows = integer_candidates(data, int_start, int_end, len(data))

    sections_public = []
    for s in sections:
        slim = {k: v for k, v in s.items() if k != "paths"}
        slim["first_10_paths"] = s["paths"][:10]
        slim["last_10_paths"] = s["paths"][-10:]
        sections_public.append(slim)

    report = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "realfiles_schema_count": len(find_all(data, REALFILES_SCHEMA)),
        "binfiles_schema_count": len(find_all(data, BINFILES_SCHEMA)),
        "sections": sections_public,
        "selected_section_index": best["section_index"] if best else None,
        "selected_path_count": best["path_count"] if best else 0,
        "lesson1_candidate_count": len(lesson_rows),
        "integer_candidate_count": len(int_rows),
        "note": "Phase 2.2 evidence parser. Filename table parsed; offset/size layout not yet finalized.",
    }

    (out / "realfiles_sections.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    write_tsv(out / "realfiles_names.tsv", all_name_rows, [
        "section_index", "index", "name_offset_dec", "name_offset_hex",
        "filename", "normalized", "ext", "raw_len"
    ])

    write_tsv(out / "realfiles_lesson1.tsv", lesson_rows, [
        "section_index", "index", "name_offset_dec", "name_offset_hex",
        "filename", "normalized", "ext", "raw_len"
    ])

    write_tsv(out / "realfiles_integer_candidates.tsv", int_rows, [
        "offset_dec", "offset_hex", "endian", "uint32", "int32", "kind", "bytes_hex"
    ])

    md = []
    md.append("# realfiles parse report\n")
    md.append(f"- source: `{args.embeddb}`")
    md.append(f"- size: `{len(data)}` bytes")
    md.append(f"- sha256: `{report['sha256']}`")
    md.append(f"- realfiles schema count: `{report['realfiles_schema_count']}`")
    md.append(f"- binfiles schema count: `{report['binfiles_schema_count']}`")
    md.append(f"- selected section: `{report['selected_section_index']}`")
    md.append(f"- selected filename rows: `{report['selected_path_count']}`")
    md.append(f"- Lesson 1 candidates: `{report['lesson1_candidate_count']}`")
    md.append(f"- integer candidates near filename block: `{report['integer_candidate_count']}`")
    md.append("\n## Current conclusion\n")
    md.append("The visible `realfiles` filename table can now be enumerated. "
              "The next step is to correlate the binary area immediately before "
              "the filename block with `offset:I` and `size:I` columns.")
    if lesson_rows:
        md.append("\n## Lesson 1 related rows\n")
        for r in lesson_rows:
            md.append(f"- `{r['index']}` `{r['normalized']}` at `{r['name_offset_hex']}`")
    (out / "realfiles_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("OK: parse_realfiles")
    print(f"source: {args.embeddb}")
    print(f"size: {len(data)} bytes")
    print(f"realfiles schema count: {report['realfiles_schema_count']}")
    print(f"binfiles schema count: {report['binfiles_schema_count']}")
    print(f"selected section: {report['selected_section_index']}")
    print(f"selected filename rows: {report['selected_path_count']}")
    print(f"Lesson 1 candidates: {report['lesson1_candidate_count']}")
    print(f"integer candidates near filename block: {report['integer_candidate_count']}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
