#!/usr/bin/env python3
"""
payload_probe.py

Phase 3.3 payload probe for Open English Learning Archive.

Why:
    broad_offset_scan.py found one strong direct offset:
        0x21810 -> mp3_frame_f3
    This tool probes that location and all signature hits, dumping small
    evidence chunks so we can verify whether it is a real payload start,
    a false positive inside protected data, or part of an encoded stream.

Usage:
    python3 extractor/tools/payload_probe.py embeddb out_broad_offsets out_payload_probe

Inputs:
    embeddb
    out_broad_offsets/cluster_summary.tsv
    out_broad_offsets/signature_hits.tsv

Outputs:
    out_payload_probe/probe_manifest.json
    out_payload_probe/probe_offsets.tsv
    out_payload_probe/chunks/
        chunk_*.bin
        chunk_*.mp3
        chunk_*.jpg
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Iterable


def read_tsv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


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


def ascii_preview(buf: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in buf)


def guess_ext(buf: bytes, sig: str = "") -> str:
    if buf.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if buf.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if buf.startswith((b"GIF89a", b"GIF87a")):
        return ".gif"
    if buf.startswith((b"<html", b"<HTML", b"<!DOCTYPE", b"<?xml")):
        return ".html"
    if buf.startswith((b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")):
        return ".mp3"
    if sig.startswith("mp3"):
        return ".mp3"
    return ".bin"


def mp3_frame_header_info(b0: int, b1: int, b2: int, b3: int) -> dict:
    """Parse enough MPEG header bits to decide if a frame is plausible."""
    header = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    sync = (header >> 21) & 0x7FF
    version_id = (header >> 19) & 0x3
    layer = (header >> 17) & 0x3
    bitrate_idx = (header >> 12) & 0xF
    sample_idx = (header >> 10) & 0x3
    padding = (header >> 9) & 0x1

    valid = (
        sync == 0x7FF and
        version_id != 1 and
        layer != 0 and
        bitrate_idx not in (0, 15) and
        sample_idx != 3
    )

    return {
        "valid": valid,
        "sync": sync,
        "version_id": version_id,
        "layer": layer,
        "bitrate_idx": bitrate_idx,
        "sample_idx": sample_idx,
        "padding": padding,
    }


def mp3_plausibility(buf: bytes) -> dict:
    if len(buf) < 4:
        return {"plausible": False, "valid_header_count": 0, "checked": 0}
    checked = 0
    valid = 0
    positions = []
    for i in range(0, min(len(buf) - 4, 4096)):
        if buf[i] == 0xFF and (buf[i+1] & 0xE0) == 0xE0:
            checked += 1
            info = mp3_frame_header_info(buf[i], buf[i+1], buf[i+2], buf[i+3])
            if info["valid"]:
                valid += 1
                positions.append(i)
    return {
        "plausible": valid >= 2 or (buf[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2") and valid >= 1),
        "valid_header_count": valid,
        "checked": checked,
        "first_valid_positions": positions[:20],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("embeddb", type=Path)
    ap.add_argument("broad_outdir", type=Path)
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--chunk-size", type=int, default=262144)
    args = ap.parse_args()

    data = args.embeddb.read_bytes()
    out = args.outdir
    chunks = out / "chunks"
    chunks.mkdir(parents=True, exist_ok=True)

    cluster_path = args.broad_outdir / "cluster_summary.tsv"
    sig_path = args.broad_outdir / "signature_hits.tsv"

    if not cluster_path.exists():
        raise SystemExit(f"missing input: {cluster_path}")
    if not sig_path.exists():
        raise SystemExit(f"missing input: {sig_path}")

    clusters = read_tsv(cluster_path)
    sigs = read_tsv(sig_path)

    # Probe top clusters first, then earliest direct signature hits.
    candidates = []
    for c in clusters[:30]:
        candidates.append({
            "kind": "cluster",
            "offset": int(c["payload_offset_dec"]),
            "signature": c.get("nearest_signature", ""),
            "score": c.get("best_score", ""),
            "source": c.get("source_min_hex", ""),
        })

    for s in sigs[:80]:
        candidates.append({
            "kind": "signature",
            "offset": int(s["offset_dec"]),
            "signature": s.get("signature", ""),
            "score": "",
            "source": "",
        })

    # Deduplicate by offset.
    seen = set()
    uniq = []
    for c in candidates:
        if c["offset"] in seen:
            continue
        seen.add(c["offset"])
        uniq.append(c)

    rows = []
    manifest = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "chunk_size": args.chunk_size,
        "chunks": [],
        "note": "Probe chunks only. These are not final extracted resources.",
    }

    for idx, c in enumerate(uniq):
        off = c["offset"]
        if not (0 <= off < len(data)):
            continue
        end = min(len(data), off + args.chunk_size)
        buf = data[off:end]
        ext = guess_ext(buf, c.get("signature", ""))
        filename = f"chunk_{idx:03d}_{off:08x}_{c['kind']}_{c.get('signature','unknown')}{ext}"
        path = chunks / filename
        path.write_bytes(buf)

        mp3_info = mp3_plausibility(buf)

        row = {
            "index": idx,
            "kind": c["kind"],
            "offset_dec": off,
            "offset_hex": hex(off),
            "signature": c.get("signature", ""),
            "score": c.get("score", ""),
            "chunk_file": str(path.relative_to(out)),
            "chunk_size": len(buf),
            "sha256": hashlib.sha256(buf).hexdigest(),
            "starts_hex": buf[:16].hex(),
            "preview_ascii": ascii_preview(buf[:96]),
            "mp3_plausible": mp3_info["plausible"],
            "mp3_valid_header_count": mp3_info["valid_header_count"],
            "mp3_checked_headers": mp3_info["checked"],
            "mp3_first_valid_positions": ",".join(map(str, mp3_info["first_valid_positions"])),
        }
        rows.append(row)
        manifest["chunks"].append(row)

    write_tsv(out / "probe_offsets.tsv", rows, [
        "index", "kind", "offset_dec", "offset_hex", "signature", "score",
        "chunk_file", "chunk_size", "sha256", "starts_hex", "preview_ascii",
        "mp3_plausible", "mp3_valid_header_count", "mp3_checked_headers",
        "mp3_first_valid_positions"
    ])
    (out / "probe_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print("OK: payload_probe")
    print(f"source: {args.embeddb}")
    print(f"candidate chunks: {len(rows)}")
    if rows:
        r = rows[0]
        print(f"top chunk: {r['chunk_file']}")
        print(f"top offset: {r['offset_hex']} sig={r['signature']} starts={r['starts_hex']}")
        print(f"top mp3 plausible: {r['mp3_plausible']} valid_headers={r['mp3_valid_header_count']}")
        print(f"top preview: {r['preview_ascii'][:96]}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
