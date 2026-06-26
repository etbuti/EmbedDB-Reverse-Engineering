#!/usr/bin/env python3
"""
broad_offset_scan.py

Phase 3.2 broad numeric resolver for Open English Learning Archive.

Why:
    Phase 3.1 only scored 22 integers near the visible filename block.
    The best result was weak, so offset/size columns are probably elsewhere,
    encoded differently, or stored in another table.

Goal:
    Scan broader regions for int32 values that point to real payload signatures.

Usage:
    python3 extractor/tools/broad_offset_scan.py embeddb out_broad_offsets

Outputs:
    out_broad_offsets/broad_offset_scores.tsv
    out_broad_offsets/signature_hits.tsv
    out_broad_offsets/cluster_summary.tsv
    out_broad_offsets/broad_resolve.json
    out_broad_offsets/broad_resolve_report.md

This tool does not extract files. It finds strong offset candidates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Iterable


SIGNATURES = [
    ("jpg_ffd8ff", b"\xff\xd8\xff", 150),
    ("jpg_jfif", b"JFIF", 100),
    ("png", b"\x89PNG\r\n\x1a\n", 150),
    ("gif89a", b"GIF89a", 130),
    ("gif87a", b"GIF87a", 130),
    ("html_lower", b"<html", 130),
    ("html_upper", b"<HTML", 130),
    ("xml", b"<?xml", 120),
    ("mp3_id3", b"ID3", 110),
    ("mp3_frame_fb", b"\xff\xfb", 80),
    ("mp3_frame_f3", b"\xff\xf3", 75),
    ("mp3_frame_f2", b"\xff\xf2", 75),
    ("riff", b"RIFF", 110),
]

SCHEMA_MARKERS = [
    ("realfiles_schema", b"realfiles[filename:S,offset:I,size:I]"),
    ("binfiles_schema", b"binfiles[filename:S,bindata:B]"),
    ("system_config_schema", b"system.config[name:S,value:S]"),
    ("ebookmm", b"ebookmm"),
    ("ebook_mm_file", b"ebook mm file"),
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


def build_signature_hits(data: bytes) -> list[dict]:
    rows = []
    for name, sig, weight in SIGNATURES:
        for i, off in enumerate(find_all(data, sig)):
            preview = data[off:min(len(data), off + 64)]
            rows.append({
                "signature": name,
                "signature_hex": sig.hex(),
                "hit_index": i,
                "offset_dec": off,
                "offset_hex": hex(off),
                "preview_hex": preview[:48].hex(),
                "preview_ascii": ascii_preview(preview[:64]),
            })
    rows.sort(key=lambda r: int(r["offset_dec"]))
    return rows


def nearest_sig_to_value(sig_offsets: list[dict], value: int, max_dist: int = 32):
    best = None
    for s in sig_offsets:
        off = int(s["offset_dec"])
        dist = abs(off - value)
        if dist <= max_dist:
            rec = (dist, s)
            if best is None or rec[0] < best[0]:
                best = rec
    return best


def score_int_value(data: bytes, source_off: int, endian: str, value: int, sig_offsets: list[dict]) -> dict | None:
    file_size = len(data)
    if not (0 <= value < file_size):
        return None

    score = 0
    reasons = []

    if value > 256:
        score += 10
        reasons.append("inside_file_after_header")
    else:
        score += 1
        reasons.append("inside_file_low_offset")

    nearest = nearest_sig_to_value(sig_offsets, value, max_dist=64)
    nearest_signature = ""
    nearest_offset = ""
    nearest_dist = ""
    if nearest:
        dist, sig = nearest
        nearest_signature = sig["signature"]
        nearest_offset = sig["offset_hex"]
        nearest_dist = dist
        # Exact signature is strongest.
        if dist == 0:
            score += 200
            reasons.append(f"exact_signature:{nearest_signature}")
        else:
            score += max(5, 100 - dist)
            reasons.append(f"near_signature:{nearest_signature}:dist={dist}")

    preview = data[value:min(file_size, value + 96)]
    if preview.startswith(b"\xff\xd8\xff"):
        score += 100
        reasons.append("preview_jpg_header")
    if b"JFIF" in preview[:32]:
        score += 80
        reasons.append("preview_jfif")
    if preview.startswith((b"<html", b"<HTML", b"<?xml")):
        score += 100
        reasons.append("preview_markup_header")
    if preview.startswith((b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")):
        score += 70
        reasons.append("preview_mp3_frame")
    if preview.startswith((b"GIF89a", b"GIF87a", b"\x89PNG")):
        score += 100
        reasons.append("preview_image_header")

    if score < 120:
        return None

    return {
        "source_offset_dec": source_off,
        "source_offset_hex": hex(source_off),
        "endian": endian,
        "value_dec": value,
        "value_hex": hex(value),
        "score": score,
        "nearest_signature": nearest_signature,
        "nearest_signature_offset": nearest_offset,
        "nearest_signature_distance": nearest_dist,
        "preview_hex": preview[:48].hex(),
        "preview_ascii": ascii_preview(preview[:96]),
        "reasons": ",".join(reasons),
    }


def scan_all_ints(data: bytes, sig_offsets: list[dict]) -> list[dict]:
    rows = []
    # Step by 1 because tables may not be aligned.
    for off in range(0, len(data) - 3):
        chunk = data[off:off+4]
        le = struct.unpack("<I", chunk)[0]
        be = struct.unpack(">I", chunk)[0]

        r = score_int_value(data, off, "le", le, sig_offsets)
        if r:
            rows.append(r)
        r = score_int_value(data, off, "be", be, sig_offsets)
        if r:
            rows.append(r)

    # Deduplicate source/value/endian, sort by score desc.
    seen = set()
    uniq = []
    for r in rows:
        key = (r["source_offset_dec"], r["endian"], r["value_dec"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)

    uniq.sort(key=lambda r: (int(r["score"]), -int(r["source_offset_dec"])), reverse=True)
    return uniq


def cluster_summary(rows: list[dict]) -> list[dict]:
    # Group by pointed payload value. If many int fields point to same payload,
    # that payload is likely referenced by an index/table.
    clusters = {}
    for r in rows:
        key = r["value_dec"]
        clusters.setdefault(key, []).append(r)

    out = []
    for value, items in clusters.items():
        best = max(items, key=lambda x: int(x["score"]))
        source_offsets = [int(x["source_offset_dec"]) for x in items]
        out.append({
            "payload_offset_dec": value,
            "payload_offset_hex": hex(value),
            "ref_count": len(items),
            "best_score": best["score"],
            "nearest_signature": best["nearest_signature"],
            "nearest_signature_distance": best["nearest_signature_distance"],
            "source_min_hex": hex(min(source_offsets)),
            "source_max_hex": hex(max(source_offsets)),
            "preview_ascii": best["preview_ascii"],
        })
    out.sort(key=lambda r: (int(r["best_score"]), int(r["ref_count"])), reverse=True)
    return out


def schema_hits(data: bytes) -> list[dict]:
    rows = []
    for name, marker in SCHEMA_MARKERS:
        for i, off in enumerate(find_all(data, marker)):
            preview = data[off:min(len(data), off + 160)]
            rows.append({
                "marker": name,
                "hit_index": i,
                "offset_dec": off,
                "offset_hex": hex(off),
                "preview_ascii": ascii_preview(preview),
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

    sig_hits = build_signature_hits(data)
    scored = scan_all_ints(data, sig_hits)
    clusters = cluster_summary(scored)
    schemas = schema_hits(data)

    write_tsv(out / "signature_hits.tsv", sig_hits, [
        "signature", "signature_hex", "hit_index", "offset_dec", "offset_hex",
        "preview_hex", "preview_ascii"
    ])
    write_tsv(out / "broad_offset_scores.tsv", scored[:2000], [
        "source_offset_dec", "source_offset_hex", "endian", "value_dec", "value_hex",
        "score", "nearest_signature", "nearest_signature_offset",
        "nearest_signature_distance", "preview_hex", "preview_ascii", "reasons"
    ])
    write_tsv(out / "cluster_summary.tsv", clusters[:500], [
        "payload_offset_dec", "payload_offset_hex", "ref_count", "best_score",
        "nearest_signature", "nearest_signature_distance", "source_min_hex",
        "source_max_hex", "preview_ascii"
    ])
    write_tsv(out / "schema_hits.tsv", schemas, [
        "marker", "hit_index", "offset_dec", "offset_hex", "preview_ascii"
    ])

    report = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "signature_hit_count": len(sig_hits),
        "strong_offset_score_count": len(scored),
        "cluster_count": len(clusters),
        "schema_hit_count": len(schemas),
        "top_offsets": scored[:20],
        "top_clusters": clusters[:20],
        "note": "Broad evidence resolver. Strong exact signatures suggest real payload starts.",
    }
    (out / "broad_resolve.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    md = []
    md.append("# Broad offset resolve report\n")
    md.append(f"- source: `{args.embeddb}`")
    md.append(f"- size: `{len(data)}` bytes")
    md.append(f"- sha256: `{report['sha256']}`")
    md.append(f"- signature hits: `{len(sig_hits)}`")
    md.append(f"- strong offset scores: `{len(scored)}`")
    md.append(f"- clusters: `{len(clusters)}`")
    md.append("\n## Top clusters\n")
    for i, c in enumerate(clusters[:20], 1):
        md.append(
            f"{i}. payload `{c['payload_offset_hex']}` refs `{c['ref_count']}` "
            f"score `{c['best_score']}` sig `{c['nearest_signature']}` "
            f"dist `{c['nearest_signature_distance']}`"
        )
        md.append(f"   preview: `{c['preview_ascii'][:120]}`")
    md.append("\n## Top direct offset scores\n")
    for i, r in enumerate(scored[:20], 1):
        md.append(
            f"{i}. value `{r['value_hex']}` from `{r['source_offset_hex']}` "
            f"score `{r['score']}` sig `{r['nearest_signature']}` "
            f"reasons `{r['reasons']}`"
        )
        md.append(f"   preview: `{r['preview_ascii'][:120]}`")
    (out / "broad_resolve_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("OK: broad_offset_scan")
    print(f"source: {args.embeddb}")
    print(f"signature hits: {len(sig_hits)}")
    print(f"strong offset scores: {len(scored)}")
    print(f"clusters: {len(clusters)}")
    if clusters:
        c = clusters[0]
        print(f"top cluster: {c['payload_offset_hex']} refs={c['ref_count']} score={c['best_score']} sig={c['nearest_signature']} dist={c['nearest_signature_distance']}")
        print(f"top preview: {c['preview_ascii'][:96]}")
    if scored:
        r = scored[0]
        print(f"top direct: {r['value_hex']} from={r['source_offset_hex']} score={r['score']} sig={r['nearest_signature']}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
