#!/usr/bin/env python3
"""
resolve_offsets.py

Phase 3.1 offset resolver for Open English Learning Archive.

Goal:
    Find the most credible offset candidates for embedded payloads.

Usage:
    python3 extractor/tools/resolve_offsets.py embeddb out_realfiles out_offsets

Inputs:
    embeddb
    out_realfiles/realfiles_integer_candidates.tsv
    out_realfiles/realfiles_lesson1.tsv

Outputs:
    out_offsets/offset_scores.tsv
    out_offsets/lesson1_offset_probe.tsv
    out_offsets/signature_hits.tsv
    out_offsets/resolve_report.md
    out_offsets/resolve.json

This tool does not extract full files yet. It ranks candidate offsets by evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Iterable


SIGNATURES = [
    ("jpg_ffd8ff", b"\xff\xd8\xff", 100),
    ("jpg_jfif_near", b"JFIF", 80),
    ("png", b"\x89PNG\r\n\x1a\n", 100),
    ("gif89a", b"GIF89a", 95),
    ("gif87a", b"GIF87a", 95),
    ("html_lower", b"<html", 90),
    ("html_upper", b"<HTML", 90),
    ("xml", b"<?xml", 85),
    ("mp3_id3", b"ID3", 85),
    ("mp3_frame_fb", b"\xff\xfb", 70),
    ("mp3_frame_f3", b"\xff\xf3", 65),
    ("mp3_frame_f2", b"\xff\xf2", 65),
    ("riff", b"RIFF", 80),
]


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


def find_all(data: bytes, sig: bytes) -> list[int]:
    out = []
    start = 0
    while True:
        idx = data.find(sig, start)
        if idx < 0:
            break
        out.append(idx)
        start = idx + 1
    return out


def nearest_signature(data: bytes, offset: int, radius: int = 64) -> tuple[int | None, str, int, str]:
    """Return nearest signature around offset.

    returns:
        distance, signature_name, signature_score, where
    """
    best = None
    start = max(0, offset - radius)
    end = min(len(data), offset + radius)
    window = data[start:end]

    for name, sig, score in SIGNATURES:
        local = window.find(sig)
        while local >= 0:
            hit = start + local
            dist = abs(hit - offset)
            rec = (dist, name, score, "exact" if hit == offset else f"near:{hit-offset:+d}")
            if best is None or (rec[0], -rec[2]) < (best[0], -best[2]):
                best = rec
            local = window.find(sig, local + 1)

    if best:
        return best
    return None, "", 0, ""


def score_candidate(data: bytes, value: int, candidate_source_offset: str, endian: str) -> dict:
    size = len(data)
    score = 0
    reasons = []

    inside = 0 <= value < size
    if inside:
        score += 20
        reasons.append("inside_file")
    else:
        return {
            "candidate_source_offset": candidate_source_offset,
            "endian": endian,
            "value_dec": value,
            "value_hex": hex(value),
            "score": 0,
            "inside_file": False,
            "nearest_signature": "",
            "signature_distance": "",
            "signature_where": "",
            "preview_hex": "",
            "preview_ascii": "",
            "reasons": "outside_file",
        }

    # Payloads rarely begin in the first tiny header area.
    if value > 256:
        score += 5
        reasons.append("after_header")

    # Check exact and nearby signatures.
    dist, sig_name, sig_score, where = nearest_signature(data, value)
    if sig_name:
        if dist == 0:
            score += sig_score
            reasons.append(f"exact_signature:{sig_name}")
        else:
            # nearby signature still useful, but weaker
            score += max(5, sig_score - dist)
            reasons.append(f"near_signature:{sig_name}:{where}")
    else:
        reasons.append("no_near_signature")

    preview = data[value:min(size, value + 96)]
    # Bonus if preview has text-looking html/xml.
    low = preview[:64].lower()
    if b"<html" in low or b"<?xml" in low or b"<!doctype" in low:
        score += 40
        reasons.append("text_markup_preview")

    # Bonus for JPEG header with JFIF shortly after.
    if preview.startswith(b"\xff\xd8\xff") and b"JFIF" in preview[:32]:
        score += 40
        reasons.append("jpeg_jfif_preview")

    # Bonus for MP3-looking continuous frame header.
    if preview[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        score += 30
        reasons.append("mp3_frame_preview")

    return {
        "candidate_source_offset": candidate_source_offset,
        "endian": endian,
        "value_dec": value,
        "value_hex": hex(value),
        "score": score,
        "inside_file": True,
        "nearest_signature": sig_name,
        "signature_distance": dist if dist is not None else "",
        "signature_where": where,
        "preview_hex": preview[:48].hex(),
        "preview_ascii": ascii_preview(preview[:96]),
        "reasons": ",".join(reasons),
    }


def build_signature_hits(data: bytes) -> list[dict]:
    rows = []
    for name, sig, weight in SIGNATURES:
        for i, off in enumerate(find_all(data, sig)[:300]):
            preview = data[off:min(len(data), off + 48)]
            rows.append({
                "signature": name,
                "signature_hex": sig.hex(),
                "hit_index": i,
                "offset_dec": off,
                "offset_hex": hex(off),
                "preview_hex": preview.hex(),
                "preview_ascii": ascii_preview(preview),
            })
    rows.sort(key=lambda r: int(r["offset_dec"]))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("embeddb", type=Path)
    ap.add_argument("realfiles_outdir", type=Path)
    ap.add_argument("outdir", type=Path)
    args = ap.parse_args()

    data = args.embeddb.read_bytes()
    out = args.outdir
    out.mkdir(parents=True, exist_ok=True)

    cand_path = args.realfiles_outdir / "realfiles_integer_candidates.tsv"
    lesson_path = args.realfiles_outdir / "realfiles_lesson1.tsv"

    if not cand_path.exists():
        raise SystemExit(f"missing input: {cand_path}")
    if not lesson_path.exists():
        raise SystemExit(f"missing input: {lesson_path}")

    int_rows = read_tsv(cand_path)
    lesson_rows = read_tsv(lesson_path)

    scored = []
    seen = set()
    for r in int_rows:
        try:
            value = int(r.get("uint32", ""))
        except ValueError:
            continue
        key = (value, r.get("endian", ""))
        if key in seen:
            continue
        seen.add(key)
        scored.append(score_candidate(
            data,
            value,
            r.get("offset_hex") or r.get("offset_dec") or "",
            r.get("endian", ""),
        ))

    scored.sort(key=lambda r: int(r["score"]), reverse=True)

    sig_hits = build_signature_hits(data)

    # Probe all lesson rows against top candidates. This is not final mapping;
    # it shows which candidates are globally credible while lesson filenames are known.
    lesson_probe = []
    top = scored[:30]
    for lr in lesson_rows:
        for rank, cand in enumerate(top, start=1):
            lesson_probe.append({
                "lesson_row_index": lr.get("index", ""),
                "lesson_resource": lr.get("normalized", lr.get("filename", "")),
                "candidate_rank": rank,
                "candidate_offset_hex": cand["value_hex"],
                "candidate_offset_dec": cand["value_dec"],
                "score": cand["score"],
                "nearest_signature": cand["nearest_signature"],
                "signature_distance": cand["signature_distance"],
                "signature_where": cand["signature_where"],
                "preview_ascii": cand["preview_ascii"],
                "reasons": cand["reasons"],
            })

    write_tsv(out / "offset_scores.tsv", scored, [
        "candidate_source_offset", "endian", "value_dec", "value_hex",
        "score", "inside_file", "nearest_signature", "signature_distance",
        "signature_where", "preview_hex", "preview_ascii", "reasons"
    ])

    write_tsv(out / "lesson1_offset_probe.tsv", lesson_probe, [
        "lesson_row_index", "lesson_resource", "candidate_rank",
        "candidate_offset_hex", "candidate_offset_dec", "score",
        "nearest_signature", "signature_distance", "signature_where",
        "preview_ascii", "reasons"
    ])

    write_tsv(out / "signature_hits.tsv", sig_hits, [
        "signature", "signature_hex", "hit_index", "offset_dec", "offset_hex",
        "preview_hex", "preview_ascii"
    ])

    report = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "integer_candidate_count": len(int_rows),
        "unique_scored_candidate_count": len(scored),
        "lesson1_resource_count": len(lesson_rows),
        "signature_hit_count": len(sig_hits),
        "top_candidates": scored[:10],
        "note": "Phase 3.1 resolver. Ranks likely offsets; does not extract full files.",
    }
    (out / "resolve.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    md = []
    md.append("# Offset resolve report\n")
    md.append(f"- source: `{args.embeddb}`")
    md.append(f"- size: `{len(data)}` bytes")
    md.append(f"- sha256: `{report['sha256']}`")
    md.append(f"- integer candidate rows: `{len(int_rows)}`")
    md.append(f"- unique scored candidates: `{len(scored)}`")
    md.append(f"- Lesson 1 resources: `{len(lesson_rows)}`")
    md.append(f"- signature hits: `{len(sig_hits)}`")
    md.append("\n## Top candidates\n")
    for i, c in enumerate(scored[:10], start=1):
        md.append(
            f"{i}. `{c['value_hex']}` score `{c['score']}` "
            f"sig `{c['nearest_signature']}` dist `{c['signature_distance']}` "
            f"reasons `{c['reasons']}`"
        )
        md.append(f"   preview: `{c['preview_ascii'][:120]}`")
    md.append("\n## Interpretation\n")
    md.append("A top candidate with an exact JPEG/HTML/XML/MP3 signature is a strong payload offset candidate. "
              "If no candidate has a strong signature, the offset/size table is likely not immediately near "
              "the visible filename block, and the next step should scan broader numeric regions.")
    (out / "resolve_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("OK: resolve_offsets")
    print(f"source: {args.embeddb}")
    print(f"integer candidate rows: {len(int_rows)}")
    print(f"unique scored candidates: {len(scored)}")
    print(f"Lesson 1 resources: {len(lesson_rows)}")
    print(f"signature hits: {len(sig_hits)}")
    if scored:
        best = scored[0]
        print(f"best candidate: {best['value_hex']} score={best['score']} sig={best['nearest_signature']} dist={best['signature_distance']}")
        print(f"best preview: {best['preview_ascii'][:96]}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
