#!/usr/bin/env python3
"""
parse_binfiles.py

Phase 4.1 evidence parser for:
    binfiles[filename:S,bindata:B]

Goal:
    Map binfiles sections and collect evidence about row boundaries and bindata layout.

Usage:
    python3 extractor/tools/parse_binfiles.py embeddb out_binfiles

Outputs:
    out_binfiles/binfiles_sections.json
    out_binfiles/binfiles_resource_hits.tsv
    out_binfiles/binfiles_blob_candidates.tsv
    out_binfiles/binfiles_hex_windows.tsv
    out_binfiles/binfiles_report.md

This tool does not extract final files. It identifies structures and candidate blob zones.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Iterable


BINFILES_SCHEMA = b"binfiles[filename:S,bindata:B]"
REALFILES_SCHEMA = b"realfiles[filename:S,offset:I,size:I]"
SYSTEM_SCHEMA = b"system.config[name:S,value:S]"

RESOURCE_RE = re.compile(
    rb"(?i)(?:[A-Za-z0-9_\-./\\\x80-\xff]+?\.(?:htm|html|jpg|jpeg|gif|png|xml|mp3|wav|wma|css|js))"
)

SIGNATURES = [
    ("jpg_ffd8ff", b"\xff\xd8\xff"),
    ("jpg_jfif", b"JFIF"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("gif89a", b"GIF89a"),
    ("gif87a", b"GIF87a"),
    ("html_lower", b"<html"),
    ("html_upper", b"<HTML"),
    ("xml", b"<?xml"),
    ("mp3_id3", b"ID3"),
    ("mp3_frame_fb", b"\xff\xfb"),
    ("mp3_frame_f3", b"\xff\xf3"),
    ("mp3_frame_f2", b"\xff\xf2"),
    ("riff", b"RIFF"),
    ("zlib_78_9c", b"\x78\x9c"),
    ("zlib_78_da", b"\x78\xda"),
    ("zlib_78_01", b"\x78\x01"),
]


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


def safe_decode(raw: bytes) -> str:
    raw = raw.strip(b"\x00\r\n\t ")
    for enc in ("gb18030", "gbk", "utf-8", "latin1"):
        try:
            s = raw.decode(enc)
            if any(ch.isprintable() for ch in s):
                return s
        except UnicodeDecodeError:
            continue
    return raw.hex()


def ascii_preview(buf: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in buf)


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


def hex_window(data: bytes, offset: int, before: int = 96, after: int = 256) -> dict:
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    buf = data[start:end]
    return {
        "window_start_dec": start,
        "window_start_hex": hex(start),
        "window_end_dec": end,
        "window_end_hex": hex(end),
        "window_hex": buf.hex(),
        "window_ascii": ascii_preview(buf),
    }


def ext_of(name: str) -> str:
    name = name.replace("\\", "/").split("?")[0]
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def get_schema_sections(data: bytes) -> list[dict]:
    bin_hits = find_all(data, BINFILES_SCHEMA)
    real_hits = find_all(data, REALFILES_SCHEMA)
    sys_hits = find_all(data, SYSTEM_SCHEMA)
    schema_hits = sorted(set(bin_hits + real_hits + sys_hits + [len(data)]))

    sections = []
    for idx, off in enumerate(bin_hits):
        next_schema = len(data)
        for h in schema_hits:
            if h > off:
                next_schema = h
                break
        scan_end = next_schema
        if scan_end - off < 4096:
            scan_end = min(len(data), off + 160000)
        sections.append({
            "section_index": idx,
            "schema_offset_dec": off,
            "schema_offset_hex": hex(off),
            "scan_end_dec": scan_end,
            "scan_end_hex": hex(scan_end),
            "span_bytes": scan_end - off,
        })
    return sections


def scan_resources_in_section(data: bytes, section: dict) -> list[dict]:
    start = int(section["schema_offset_dec"])
    end = int(section["scan_end_dec"])
    blob = data[start:end]
    rows = []
    for m in RESOURCE_RE.finditer(blob):
        off = start + m.start()
        raw = m.group(0)
        name = safe_decode(raw)
        if len(name) > 300:
            name = name[-300:]
        rows.append({
            "section_index": section["section_index"],
            "offset_dec": off,
            "offset_hex": hex(off),
            "name": name,
            "ext": ext_of(name),
            "raw_len": len(raw),
            "raw_hex_head": raw[:80].hex(),
        })
    return rows


def scan_signatures_in_section(data: bytes, section: dict) -> list[dict]:
    start = int(section["schema_offset_dec"])
    end = int(section["scan_end_dec"])
    rows = []
    for sig_name, sig in SIGNATURES:
        local_start = start
        while True:
            idx = data.find(sig, local_start, end)
            if idx < 0:
                break
            preview = data[idx:min(len(data), idx + 96)]
            rows.append({
                "section_index": section["section_index"],
                "signature": sig_name,
                "signature_hex": sig.hex(),
                "offset_dec": idx,
                "offset_hex": hex(idx),
                "preview_hex": preview[:48].hex(),
                "preview_ascii": ascii_preview(preview[:96]),
            })
            local_start = idx + 1
    rows.sort(key=lambda r: int(r["offset_dec"]))
    return rows


def scan_length_prefixed_candidates(data: bytes, section: dict) -> list[dict]:
    """Look for plausible 32-bit little/big endian lengths in binfiles sections.

    For a BLOB field, common layouts include:
        [len:uint32][data]
        [name][len:uint32][data]
        [type/id][len:uint32][data]

    This evidence scan checks whether an int32 is followed by a known file signature
    within a small gap.
    """
    start = int(section["schema_offset_dec"])
    end = int(section["scan_end_dec"])
    rows = []

    for off in range(start, max(start, end - 4)):
        chunk = data[off:off+4]
        if len(chunk) != 4:
            continue
        vals = [("le", struct.unpack("<I", chunk)[0]), ("be", struct.unpack(">I", chunk)[0])]
        for endian, val in vals:
            if not (0 < val <= len(data) and val < 5_000_000):
                continue
            # Check after 4 bytes and up to 32 bytes later for payload signature.
            search_start = off + 4
            search_end = min(len(data), search_start + 32)
            found = []
            for sig_name, sig in SIGNATURES:
                pos = data.find(sig, search_start, search_end)
                if pos >= 0:
                    found.append((sig_name, pos - search_start, pos))
            if found:
                sig_name, gap, pos = found[0]
                preview = data[pos:min(len(data), pos + 96)]
                rows.append({
                    "section_index": section["section_index"],
                    "length_field_offset_dec": off,
                    "length_field_offset_hex": hex(off),
                    "endian": endian,
                    "length_value": val,
                    "payload_signature": sig_name,
                    "payload_gap_after_length": gap,
                    "payload_offset_dec": pos,
                    "payload_offset_hex": hex(pos),
                    "payload_preview_hex": preview[:48].hex(),
                    "payload_preview_ascii": ascii_preview(preview[:96]),
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

    sections = get_schema_sections(data)

    all_resources = []
    all_sigs = []
    all_len_candidates = []
    window_rows = []

    for s in sections:
        resources = scan_resources_in_section(data, s)
        sigs = scan_signatures_in_section(data, s)
        lens = scan_length_prefixed_candidates(data, s)

        s["resource_hit_count"] = len(resources)
        s["signature_hit_count"] = len(sigs)
        s["length_prefixed_candidate_count"] = len(lens)

        all_resources.extend(resources)
        all_sigs.extend(sigs)
        all_len_candidates.extend(lens)

        # Windows around schema and first few resource/signature hits.
        for label, off in [("schema", int(s["schema_offset_dec"]))]:
            w = hex_window(data, off)
            window_rows.append({
                "section_index": s["section_index"],
                "label": label,
                "offset_dec": off,
                "offset_hex": hex(off),
                **w,
            })
        for r in resources[:10]:
            off = int(r["offset_dec"])
            w = hex_window(data, off)
            window_rows.append({
                "section_index": s["section_index"],
                "label": "resource",
                "offset_dec": off,
                "offset_hex": hex(off),
                **w,
            })
        for r in sigs[:10]:
            off = int(r["offset_dec"])
            w = hex_window(data, off)
            window_rows.append({
                "section_index": s["section_index"],
                "label": "signature",
                "offset_dec": off,
                "offset_hex": hex(off),
                **w,
            })

    by_ext = {}
    for r in all_resources:
        by_ext[r["ext"]] = by_ext.get(r["ext"], 0) + 1

    by_sig = {}
    for r in all_sigs:
        by_sig[r["signature"]] = by_sig.get(r["signature"], 0) + 1

    report = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "binfiles_schema_count": len(find_all(data, BINFILES_SCHEMA)),
        "realfiles_schema_count": len(find_all(data, REALFILES_SCHEMA)),
        "sections": sections,
        "resource_hit_count": len(all_resources),
        "resource_hits_by_ext": by_ext,
        "signature_hit_count": len(all_sigs),
        "signature_hits_by_type": by_sig,
        "length_prefixed_candidate_count": len(all_len_candidates),
        "note": "Phase 4.1 evidence parser. No final blob extraction yet.",
    }

    (out / "binfiles_sections.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    write_tsv(out / "binfiles_resource_hits.tsv", all_resources, [
        "section_index", "offset_dec", "offset_hex", "name", "ext", "raw_len", "raw_hex_head"
    ])

    write_tsv(out / "binfiles_blob_candidates.tsv", all_len_candidates, [
        "section_index", "length_field_offset_dec", "length_field_offset_hex",
        "endian", "length_value", "payload_signature", "payload_gap_after_length",
        "payload_offset_dec", "payload_offset_hex", "payload_preview_hex", "payload_preview_ascii"
    ])

    write_tsv(out / "binfiles_signature_hits.tsv", all_sigs, [
        "section_index", "signature", "signature_hex", "offset_dec", "offset_hex",
        "preview_hex", "preview_ascii"
    ])

    write_tsv(out / "binfiles_hex_windows.tsv", window_rows, [
        "section_index", "label", "offset_dec", "offset_hex",
        "window_start_dec", "window_start_hex", "window_end_dec", "window_end_hex",
        "window_hex", "window_ascii"
    ])

    md = []
    md.append("# binfiles parse report\n")
    md.append(f"- source: `{args.embeddb}`")
    md.append(f"- size: `{len(data)}` bytes")
    md.append(f"- sha256: `{report['sha256']}`")
    md.append(f"- binfiles schema count: `{report['binfiles_schema_count']}`")
    md.append(f"- realfiles schema count: `{report['realfiles_schema_count']}`")
    md.append(f"- binfiles sections: `{len(sections)}`")
    md.append(f"- resource hits in binfiles spans: `{len(all_resources)}`")
    md.append(f"- resource hits by ext: `{by_ext}`")
    md.append(f"- signature hits in binfiles spans: `{len(all_sigs)}`")
    md.append(f"- signature hits by type: `{by_sig}`")
    md.append(f"- length-prefixed blob candidates: `{len(all_len_candidates)}`")
    md.append("\n## Sections\n")
    for s in sections:
        md.append(
            f"- section `{s['section_index']}` schema `{s['schema_offset_hex']}` "
            f"span `{s['span_bytes']}` resources `{s['resource_hit_count']}` "
            f"signatures `{s['signature_hit_count']}` length-candidates `{s['length_prefixed_candidate_count']}`"
        )
    md.append("\n## Interpretation\n")
    md.append("If length-prefixed candidates are zero or weak, `bindata:B` may use a custom stream layout, "
              "a separate table, or protected encoding. If candidates exist, Phase 4.2 can dump candidate blobs.")
    (out / "binfiles_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("OK: parse_binfiles")
    print(f"source: {args.embeddb}")
    print(f"binfiles schema count: {report['binfiles_schema_count']}")
    print(f"binfiles sections: {len(sections)}")
    print(f"resource hits in binfiles spans: {len(all_resources)}")
    print(f"resource hits by ext: {by_ext}")
    print(f"signature hits in binfiles spans: {len(all_sigs)}")
    print(f"signature hits by type: {by_sig}")
    print(f"length-prefixed blob candidates: {len(all_len_candidates)}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
