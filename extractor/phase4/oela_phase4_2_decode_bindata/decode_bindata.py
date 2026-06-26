#!/usr/bin/env python3
"""
decode_bindata.py

Phase 4.2 candidate BLOB decoder for Open English Learning Archive.

Goal:
    Take length-prefixed BLOB candidates found by parse_binfiles.py,
    dump the candidate bytes, try common decoders, and identify recovered content.

Usage:
    python3 extractor/tools/decode_bindata.py embeddb out_binfiles out_bindata

Inputs:
    embeddb
    out_binfiles/binfiles_blob_candidates.tsv

Outputs:
    out_bindata/decode_candidates.tsv
    out_bindata/decode_manifest.json
    out_bindata/decoded/
        candidate_*.bin
        candidate_*.zlib
        candidate_*.rawdeflate
        candidate_*.html
        candidate_*.xml
        candidate_*.jpg
        candidate_*.mp3

This tool is still evidence-first. It may recover real files, but it does not
yet assign original filenames unless supported by later mapping logic.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import zlib
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


def identify(buf: bytes) -> tuple[str, str]:
    head = buf[:256]
    low = head.lower()
    if buf.startswith(b"\xff\xd8\xff"):
        return "jpg", ".jpg"
    if buf.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", ".png"
    if buf.startswith((b"GIF89a", b"GIF87a")):
        return "gif", ".gif"
    if buf.startswith((b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")):
        return "mp3", ".mp3"
    if buf.startswith(b"RIFF"):
        return "riff", ".wav"
    if low.startswith((b"<html", b"<!doctype html")) or b"<html" in low[:128]:
        return "html", ".html"
    if low.startswith(b"<?xml") or b"<xml" in low[:128] or b"<xml" in low:
        return "xml", ".xml"
    if buf.startswith((b"\x78\x01", b"\x78\x9c", b"\x78\xda")):
        return "zlib_stream", ".zlib"
    if buf.startswith(b"\x1f\x8b"):
        return "gzip_stream", ".gz"
    # crude text test
    if head:
        printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b <= 126)
        if printable / len(head) > 0.85:
            return "text", ".txt"
    return "binary", ".bin"


def try_decoders(buf: bytes) -> list[tuple[str, bytes, str]]:
    """Return list of (method, decoded_bytes, note)."""
    out = [("raw", buf, "raw candidate bytes")]

    # Standard zlib.
    try:
        out.append(("zlib", zlib.decompress(buf), "zlib.decompress"))
    except Exception as e:
        pass

    # Raw deflate.
    try:
        out.append(("rawdeflate", zlib.decompress(buf, -15), "zlib raw deflate window"))
    except Exception:
        pass

    # gzip.
    try:
        out.append(("gzip", gzip.decompress(buf), "gzip.decompress"))
    except Exception:
        pass

    # Sometimes a few bytes precede compressed stream. Try offsets 1..32.
    for skip in range(1, 33):
        sub = buf[skip:]
        if len(sub) < 8:
            break
        if sub.startswith((b"\x78\x01", b"\x78\x9c", b"\x78\xda")):
            try:
                out.append((f"zlib_skip_{skip}", zlib.decompress(sub), f"zlib after skipping {skip} bytes"))
            except Exception:
                pass
        try:
            # Very conservative: only keep rawdeflate skip results if decoded data looks recognizable.
            dec = zlib.decompress(sub, -15)
            kind, _ = identify(dec)
            if kind not in ("binary",):
                out.append((f"rawdeflate_skip_{skip}", dec, f"raw deflate after skipping {skip} bytes"))
        except Exception:
            pass

    return out


def safe_int(v: str, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("embeddb", type=Path)
    ap.add_argument("binfiles_outdir", type=Path)
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--max-candidates", type=int, default=200)
    args = ap.parse_args()

    data = args.embeddb.read_bytes()
    cand_path = args.binfiles_outdir / "binfiles_blob_candidates.tsv"
    if not cand_path.exists():
        raise SystemExit(f"missing input: {cand_path}")

    out = args.outdir
    decoded_dir = out / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)

    candidates = read_tsv(cand_path)
    rows = []
    manifest = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "candidate_count": len(candidates),
        "decoded": [],
        "note": "Phase 4.2 candidate decoder. Filename mapping is not finalized.",
    }

    for i, c in enumerate(candidates[:args.max_candidates]):
        payload_off = safe_int(c.get("payload_offset_dec", "0"))
        length_val = safe_int(c.get("length_value", "0"))
        section = c.get("section_index", "")

        # Candidate length may be exact payload size, compressed size, or a false positive.
        # Cap to file end and also avoid huge accidental slices.
        if payload_off < 0 or payload_off >= len(data):
            continue
        max_len = min(length_val if length_val > 0 else 262144, len(data) - payload_off, 5_000_000)
        if max_len <= 0:
            continue

        raw = data[payload_off:payload_off + max_len]
        raw_kind, raw_ext = identify(raw)

        # Always save raw candidate.
        raw_name = f"candidate_{i:03d}_sec{section}_{payload_off:08x}_raw{raw_ext}"
        raw_path = decoded_dir / raw_name
        raw_path.write_bytes(raw)

        decoded_variants = try_decoders(raw)
        for method, dec, note in decoded_variants:
            kind, ext = identify(dec)
            # Save all raw, and save decoded variants that are not just opaque binary,
            # plus all zlib/rawdeflate/gzip attempts that succeeded.
            keep = method == "raw" or kind != "binary" or method != "raw"
            if not keep:
                continue
            name = f"candidate_{i:03d}_sec{section}_{payload_off:08x}_{method}_{kind}{ext}"
            path = decoded_dir / name
            # Avoid writing duplicate raw twice under different name if method raw already saved.
            if method == "raw":
                path = raw_path
                name = raw_name
            else:
                path.write_bytes(dec)

            row = {
                "candidate_index": i,
                "section_index": section,
                "length_field_offset_hex": c.get("length_field_offset_hex", ""),
                "length_field_offset_dec": c.get("length_field_offset_dec", ""),
                "endian": c.get("endian", ""),
                "length_value": length_val,
                "payload_offset_hex": hex(payload_off),
                "payload_offset_dec": payload_off,
                "input_signature": c.get("payload_signature", ""),
                "method": method,
                "identified_kind": kind,
                "output_file": str(path.relative_to(out)),
                "output_size": len(dec),
                "sha256": hashlib.sha256(dec).hexdigest(),
                "starts_hex": dec[:24].hex(),
                "preview_ascii": ascii_preview(dec[:160]),
                "note": note,
            }
            rows.append(row)
            manifest["decoded"].append(row)

    write_tsv(out / "decode_candidates.tsv", rows, [
        "candidate_index", "section_index", "length_field_offset_hex",
        "length_field_offset_dec", "endian", "length_value",
        "payload_offset_hex", "payload_offset_dec", "input_signature",
        "method", "identified_kind", "output_file", "output_size",
        "sha256", "starts_hex", "preview_ascii", "note"
    ])
    (out / "decode_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    # Summaries.
    by_kind = {}
    by_method = {}
    for r in rows:
        by_kind[r["identified_kind"]] = by_kind.get(r["identified_kind"], 0) + 1
        by_method[r["method"]] = by_method.get(r["method"], 0) + 1

    md = []
    md.append("# bindata decode report\n")
    md.append(f"- source: `{args.embeddb}`")
    md.append(f"- size: `{len(data)}` bytes")
    md.append(f"- sha256: `{manifest['sha256']}`")
    md.append(f"- blob candidates: `{len(candidates)}`")
    md.append(f"- decoded variants: `{len(rows)}`")
    md.append(f"- by kind: `{by_kind}`")
    md.append(f"- by method: `{by_method}`")
    md.append("\n## Interesting recovered variants\n")
    interesting = [r for r in rows if r["identified_kind"] not in ("binary", "zlib_stream", "gzip_stream")]
    for r in interesting[:30]:
        md.append(
            f"- `{r['identified_kind']}` via `{r['method']}` "
            f"offset `{r['payload_offset_hex']}` size `{r['output_size']}` file `{r['output_file']}`"
        )
        md.append(f"  preview: `{r['preview_ascii'][:160]}`")
    if not interesting:
        md.append("No recognizable decoded files yet. Next step: inspect candidate blobs and table boundaries.")
    (out / "decode_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("OK: decode_bindata")
    print(f"source: {args.embeddb}")
    print(f"blob candidates: {len(candidates)}")
    print(f"decoded variants: {len(rows)}")
    print(f"decoded by kind: {by_kind}")
    print(f"decoded by method: {by_method}")
    if rows:
        interesting = [r for r in rows if r["identified_kind"] not in ("binary", "zlib_stream", "gzip_stream")]
        if interesting:
            top = interesting[0]
        else:
            top = rows[0]
        print(f"top decoded: {top['identified_kind']} via={top['method']} file={top['output_file']} size={top['output_size']}")
        print(f"top preview: {top['preview_ascii'][:120]}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
