#!/usr/bin/env python3
"""
embeddb_scan.py

Phase 2 evidence scanner for Open English Learning Archive.

Usage:
    python3 extractor/tools/embeddb_scan.py embeddb out_scan

Outputs:
    out_scan/markers.tsv
    out_scan/table_windows.tsv
    out_scan/resource_hits.tsv
    out_scan/payload_candidates.tsv
    out_scan/scan.json

This tool does NOT extract final files and does NOT guess the container codec.
It only records byte-level evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Iterable


MARKERS = [
    b"ebookmm",
    b"ebook mm file",
    b"shinesoft",
    b"ShineSoft",
    b"binfiles",
    b"binfiles[filename:S,bindata:B]",
    b"realfiles",
    b"realfiles[filename:S,offset:I,size:I]",
    b"system.config",
    b"system.config[name:S,value:S]",
    b"filelist.xml",
    b".htm",
    b".html",
    b".jpg",
    b".jpeg",
    b".gif",
    b".png",
    b".mp3",
    b"JFIF",
    b"GIF89a",
    b"GIF87a",
    b"ID3",
    b"RIFF",
    b"<html",
    b"<HTML",
]

PAYLOAD_SIGNATURES = [
    ("jpg_ffd8ff", b"\xff\xd8\xff"),
    ("jpg_jfif", b"JFIF"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("gif89a", b"GIF89a"),
    ("gif87a", b"GIF87a"),
    ("mp3_id3", b"ID3"),
    ("mp3_frame_fb", b"\xff\xfb"),
    ("mp3_frame_f3", b"\xff\xf3"),
    ("mp3_frame_f2", b"\xff\xf2"),
    ("wav_riff", b"RIFF"),
    ("html_lower", b"<html"),
    ("html_upper", b"<HTML"),
    ("xml", b"<?xml"),
]

RESOURCE_RE = re.compile(
    rb"(?i)(?:[A-Za-z0-9_\-./\\\x80-\xff]+?\.(?:htm|html|jpg|jpeg|gif|png|xml|mp3|wav|wma|css|js))"
)


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
    for enc in ("utf-8", "gb18030", "gbk", "latin1"):
        try:
            s = raw.decode(enc)
            if any(ch.isprintable() for ch in s):
                return s
        except UnicodeDecodeError:
            continue
    return raw.hex()


def hex_window(data: bytes, offset: int, before: int = 64, after: int = 192) -> tuple[int, int, str, str]:
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    chunk = data[start:end]
    text = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
    return start, end, chunk.hex(), text


def ext_of(name: str) -> str:
    name = name.split("?")[0].replace("\\", "/")
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


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


def scan_markers(data: bytes) -> tuple[list[dict], list[dict]]:
    marker_rows = []
    window_rows = []

    for marker in MARKERS:
        offsets = find_all(data, marker)
        marker_text = safe_decode(marker)
        marker_rows.append({
            "marker": marker_text,
            "marker_hex": marker.hex(),
            "count": len(offsets),
            "first_offset_dec": offsets[0] if offsets else "",
            "first_offset_hex": hex(offsets[0]) if offsets else "",
        })

        for i, off in enumerate(offsets[:100]):
            start, end, hx, ascii_text = hex_window(data, off)
            window_rows.append({
                "marker": marker_text,
                "hit_index": i,
                "offset_dec": off,
                "offset_hex": hex(off),
                "window_start_dec": start,
                "window_end_dec": end,
                "window_hex": hx,
                "window_ascii": ascii_text,
            })

    return marker_rows, window_rows


def scan_resources(data: bytes) -> list[dict]:
    rows = []
    seen = set()

    for m in RESOURCE_RE.finditer(data):
        raw = m.group(0)
        name = safe_decode(raw)
        if len(name) > 260:
            name = name[-260:]
        key = (m.start(), name)
        if key in seen:
            continue
        seen.add(key)

        rows.append({
            "offset_dec": m.start(),
            "offset_hex": hex(m.start()),
            "name": name,
            "ext": ext_of(name),
            "raw_hex_head": raw[:80].hex(),
        })

    return rows


def scan_payload_candidates(data: bytes) -> list[dict]:
    rows = []
    for sig_name, sig in PAYLOAD_SIGNATURES:
        for i, off in enumerate(find_all(data, sig)[:200]):
            start, end, hx, ascii_text = hex_window(data, off, before=16, after=96)
            rows.append({
                "signature": sig_name,
                "signature_hex": sig.hex(),
                "hit_index": i,
                "offset_dec": off,
                "offset_hex": hex(off),
                "window_start_dec": start,
                "window_end_dec": end,
                "window_hex": hx,
                "window_ascii": ascii_text,
            })
    rows.sort(key=lambda r: int(r["offset_dec"]))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("embeddb", type=Path)
    ap.add_argument("outdir", type=Path)
    args = ap.parse_args()

    data = args.embeddb.read_bytes()
    out = args.outdir
    out.mkdir(parents=True, exist_ok=True)

    marker_rows, window_rows = scan_markers(data)
    resource_rows = scan_resources(data)
    payload_rows = scan_payload_candidates(data)

    by_ext = {}
    for r in resource_rows:
        by_ext[r["ext"]] = by_ext.get(r["ext"], 0) + 1

    by_signature = {}
    for r in payload_rows:
        by_signature[r["signature"]] = by_signature.get(r["signature"], 0) + 1

    scan = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "marker_count": len(marker_rows),
        "resource_hit_count": len(resource_rows),
        "resource_hits_by_ext": by_ext,
        "payload_candidate_count": len(payload_rows),
        "payload_candidates_by_signature": by_signature,
        "outputs": {
            "markers": "markers.tsv",
            "table_windows": "table_windows.tsv",
            "resource_hits": "resource_hits.tsv",
            "payload_candidates": "payload_candidates.tsv",
        },
        "note": "Evidence scan only. No extraction or codec assumptions.",
    }

    write_tsv(out / "markers.tsv", marker_rows, [
        "marker", "marker_hex", "count", "first_offset_dec", "first_offset_hex"
    ])
    write_tsv(out / "table_windows.tsv", window_rows, [
        "marker", "hit_index", "offset_dec", "offset_hex",
        "window_start_dec", "window_end_dec", "window_hex", "window_ascii"
    ])
    write_tsv(out / "resource_hits.tsv", resource_rows, [
        "offset_dec", "offset_hex", "name", "ext", "raw_hex_head"
    ])
    write_tsv(out / "payload_candidates.tsv", payload_rows, [
        "signature", "signature_hex", "hit_index", "offset_dec", "offset_hex",
        "window_start_dec", "window_end_dec", "window_hex", "window_ascii"
    ])
    (out / "scan.json").write_text(json.dumps(scan, ensure_ascii=False, indent=2), encoding="utf-8")

    print("OK: embeddb_scan")
    print(f"source: {args.embeddb}")
    print(f"size: {len(data)} bytes")
    print(f"sha256: {scan['sha256']}")
    print(f"resource hits: {len(resource_rows)}")
    print(f"resource hits by ext: {by_ext}")
    print(f"payload candidates: {len(payload_rows)}")
    print(f"payload signatures: {by_signature}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
