#!/usr/bin/env python3
"""
probe_mp3_extent.py

Phase 4.2.1 MP3 extent probe for Open English Learning Archive.

Why:
    decode_bindata.py recovered MP3-looking chunks, but playback is mostly noise/1 second.
    We need to determine whether the issue is:
      - wrong start offset
      - wrong length
      - interleaved container records
      - false MP3 sync inside protected data

Usage:
    python3 extractor/tools/probe_mp3_extent.py embeddb out_bindata out_mp3_extent

Inputs:
    embeddb
    out_bindata/decode_candidates.tsv

Outputs:
    out_mp3_extent/mp3_extent_report.tsv
    out_mp3_extent/mp3_extent_manifest.json
    out_mp3_extent/candidates/
        mp3_probe_*.mp3

This tool scans MP3 frame continuity and dumps candidate extents.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Iterable


BITRATE_MPEG1_L3 = {
    1: 32, 2: 40, 3: 48, 4: 56, 5: 64, 6: 80, 7: 96, 8: 112,
    9: 128, 10: 160, 11: 192, 12: 224, 13: 256, 14: 320
}
BITRATE_MPEG2_L3 = {
    1: 8, 2: 16, 3: 24, 4: 32, 5: 40, 6: 48, 7: 56, 8: 64,
    9: 80, 10: 96, 11: 112, 12: 128, 13: 144, 14: 160
}
SAMPLE_RATES = {
    3: {0: 44100, 1: 48000, 2: 32000},  # MPEG1
    2: {0: 22050, 1: 24000, 2: 16000},  # MPEG2
    0: {0: 11025, 1: 12000, 2: 8000},   # MPEG2.5
}


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


def parse_mp3_header(buf: bytes, pos: int) -> dict | None:
    if pos + 4 > len(buf):
        return None
    b0, b1, b2, b3 = buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]
    header = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

    sync = (header >> 21) & 0x7FF
    version_id = (header >> 19) & 0x3
    layer = (header >> 17) & 0x3
    protection = (header >> 16) & 0x1
    bitrate_idx = (header >> 12) & 0xF
    sample_idx = (header >> 10) & 0x3
    padding = (header >> 9) & 0x1
    channel_mode = (header >> 6) & 0x3

    if sync != 0x7FF:
        return None
    if version_id == 1 or layer == 0:
        return None
    if bitrate_idx in (0, 15) or sample_idx == 3:
        return None

    # layer bits: 01 = Layer III, 10 = Layer II, 11 = Layer I
    if layer != 1:
        # We only trust Layer III for this probe.
        return None

    bitrate_table = BITRATE_MPEG1_L3 if version_id == 3 else BITRATE_MPEG2_L3
    bitrate_kbps = bitrate_table.get(bitrate_idx)
    sample_rate = SAMPLE_RATES.get(version_id, {}).get(sample_idx)
    if not bitrate_kbps or not sample_rate:
        return None

    if version_id == 3:
        frame_len = int((144000 * bitrate_kbps) / sample_rate + padding)
    else:
        frame_len = int((72000 * bitrate_kbps) / sample_rate + padding)

    if frame_len <= 4 or frame_len > 2000:
        return None

    return {
        "pos": pos,
        "frame_len": frame_len,
        "version_id": version_id,
        "layer": layer,
        "bitrate_kbps": bitrate_kbps,
        "sample_rate": sample_rate,
        "padding": padding,
        "channel_mode": channel_mode,
        "protection": protection,
    }


def follow_frames(buf: bytes, start: int, max_frames: int = 20000) -> dict:
    frames = []
    pos = start
    first_bad = None

    while pos + 4 <= len(buf) and len(frames) < max_frames:
        h = parse_mp3_header(buf, pos)
        if not h:
            first_bad = pos
            break
        frames.append(h)
        pos += h["frame_len"]

    duration_sec = 0.0
    for h in frames:
        # Layer III samples per frame.
        samples = 1152 if h["version_id"] == 3 else 576
        duration_sec += samples / h["sample_rate"]

    return {
        "start": start,
        "frame_count": len(frames),
        "end": pos,
        "extent_len": pos - start,
        "first_bad": first_bad,
        "duration_sec": duration_sec,
        "first_frame": frames[0] if frames else None,
        "last_frame": frames[-1] if frames else None,
    }


def find_syncs(buf: bytes, limit: int = 2000000) -> list[int]:
    out = []
    n = min(len(buf), limit)
    for i in range(0, n - 4):
        if buf[i] == 0xFF and (buf[i+1] & 0xE0) == 0xE0:
            if parse_mp3_header(buf, i):
                out.append(i)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("embeddb", type=Path)
    ap.add_argument("bindata_outdir", type=Path)
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--max-scan", type=int, default=1200000)
    args = ap.parse_args()

    data = args.embeddb.read_bytes()
    cand_path = args.bindata_outdir / "decode_candidates.tsv"
    if not cand_path.exists():
        raise SystemExit(f"missing input: {cand_path}")

    out = args.outdir
    dump_dir = out / "candidates"
    dump_dir.mkdir(parents=True, exist_ok=True)

    candidates = read_tsv(cand_path)
    # Only raw mp3 candidates.
    mp3_rows = [
        r for r in candidates
        if r.get("identified_kind") == "mp3" and r.get("method") == "raw"
    ]

    # Deduplicate by payload offset.
    seen_offsets = set()
    uniq = []
    for r in mp3_rows:
        off = int(r["payload_offset_dec"])
        if off in seen_offsets:
            continue
        seen_offsets.add(off)
        uniq.append(r)

    rows = []
    manifest = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "input_mp3_candidate_count": len(mp3_rows),
        "unique_offset_count": len(uniq),
        "outputs": [],
        "note": "MP3 extent probe. Candidate streams are not final filenames.",
    }

    for idx, r in enumerate(uniq):
        off = int(r["payload_offset_dec"])
        max_end = min(len(data), off + args.max_scan)
        window = data[off:max_end]

        # Probe from the offset itself.
        probes = []
        probes.append(("offset", 0, follow_frames(window, 0)))

        # Probe from first valid syncs nearby, because our payload offset may include a small record header.
        syncs = find_syncs(window, limit=min(len(window), 8192))
        for s in syncs[:20]:
            if s == 0:
                continue
            probes.append((f"sync+{s}", s, follow_frames(window, s)))

        # Pick best: most frames, then longest extent.
        best_label, best_local, best = max(
            probes,
            key=lambda x: (x[2]["frame_count"], x[2]["extent_len"])
        )

        chunk = window[best_local:best["end"]]
        out_name = f"mp3_probe_{idx:03d}_{off+best_local:08x}_{best['frame_count']}frames.mp3"
        out_path = dump_dir / out_name
        out_path.write_bytes(chunk)

        first_frame = best["first_frame"] or {}
        row = {
            "candidate_index": idx,
            "source_payload_offset_hex": hex(off),
            "best_start_hex": hex(off + best_local),
            "best_start_label": best_label,
            "frame_count": best["frame_count"],
            "extent_len": best["extent_len"],
            "duration_sec": f"{best['duration_sec']:.3f}",
            "first_bad_global_hex": hex(off + best["first_bad"]) if best["first_bad"] is not None else "",
            "bitrate_kbps": first_frame.get("bitrate_kbps", ""),
            "sample_rate": first_frame.get("sample_rate", ""),
            "version_id": first_frame.get("version_id", ""),
            "output_file": str(out_path.relative_to(out)),
            "output_size": len(chunk),
            "sha256": hashlib.sha256(chunk).hexdigest(),
            "preview_ascii": ascii_preview(chunk[:96]),
        }
        rows.append(row)
        manifest["outputs"].append(row)

    write_tsv(out / "mp3_extent_report.tsv", rows, [
        "candidate_index", "source_payload_offset_hex", "best_start_hex",
        "best_start_label", "frame_count", "extent_len", "duration_sec",
        "first_bad_global_hex", "bitrate_kbps", "sample_rate", "version_id",
        "output_file", "output_size", "sha256", "preview_ascii"
    ])
    (out / "mp3_extent_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    rows_sorted = sorted(rows, key=lambda x: (int(x["frame_count"]), int(x["extent_len"])), reverse=True)

    md = []
    md.append("# MP3 extent probe report\n")
    md.append(f"- source: `{args.embeddb}`")
    md.append(f"- unique offsets: `{len(uniq)}`")
    md.append("\n## Best streams\n")
    for row in rows_sorted[:20]:
        md.append(
            f"- start `{row['best_start_hex']}` frames `{row['frame_count']}` "
            f"duration `{row['duration_sec']}s` file `{row['output_file']}`"
        )
    (out / "mp3_extent_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("OK: probe_mp3_extent")
    print(f"source: {args.embeddb}")
    print(f"input mp3 candidates: {len(mp3_rows)}")
    print(f"unique offsets: {len(uniq)}")
    if rows_sorted:
        top = rows_sorted[0]
        print(f"best stream: start={top['best_start_hex']} frames={top['frame_count']} duration={top['duration_sec']}s size={top['output_size']}")
        print(f"best file: {top['output_file']}")
        print(f"first bad: {top['first_bad_global_hex']}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
