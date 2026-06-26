#!/usr/bin/env python3
"""
classify_bin_sections.py

Phase 4.3 section classifier for Open English Learning Archive.

Why:
    MP3 extent probe shows candidates are not continuous MP3 streams
    (best stream only 1 valid frame). We need to classify the three
    binfiles sections and inspect their internal byte patterns.

Usage:
    python3 extractor/tools/classify_bin_sections.py embeddb out_binfiles out_section_classify

Inputs:
    embeddb
    out_binfiles/binfiles_sections.json
    out_binfiles/binfiles_resource_hits.tsv
    out_binfiles/binfiles_signature_hits.tsv
    out_binfiles/binfiles_blob_candidates.tsv

Outputs:
    out_section_classify/section_summary.tsv
    out_section_classify/section_gaps.tsv
    out_section_classify/section_samples.tsv
    out_section_classify/section_classify.json
    out_section_classify/section_classify_report.md
    out_section_classify/samples/*.bin

This is an evidence tool. It does not extract final resources.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from typing import Iterable
from collections import Counter, defaultdict


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
                if isinstance(v, str):
                    v = v.replace("\t", " ").replace("\n", "\\n").replace("\r", "\\r")
                vals.append(str(v))
            f.write("\t".join(vals) + "\n")


def ascii_preview(buf: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in buf)


def entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = Counter(buf)
    n = len(buf)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())


def load_sections(path: Path) -> list[dict]:
    j = json.loads(path.read_text(encoding="utf-8"))
    return j.get("sections", [])


def section_rows(rows: list[dict], idx: int) -> list[dict]:
    return [r for r in rows if str(r.get("section_index", "")) == str(idx)]


def ext_of(name: str) -> str:
    name = name.replace("\\", "/").split("?")[0]
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def classify_by_counts(resource_ext_counts: dict, sig_counts: dict, length_count: int) -> str:
    # Evidence-only rough label, not a final type.
    if sig_counts.get("mp3_frame_f3", 0) + sig_counts.get("mp3_frame_fb", 0) + sig_counts.get("mp3_frame_f2", 0) > 10:
        return "mp3-like/protected-audio"
    if resource_ext_counts.get("jpg", 0) > 20 and not sig_counts:
        return "image-index-or-protected-image"
    if resource_ext_counts.get("htm", 0) > 20 and not sig_counts:
        return "html-index-or-protected-html"
    if length_count > 0:
        return "length-prefixed-candidate-section"
    return "index-or-unknown"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("embeddb", type=Path)
    ap.add_argument("binfiles_outdir", type=Path)
    ap.add_argument("outdir", type=Path)
    args = ap.parse_args()

    data = args.embeddb.read_bytes()
    out = args.outdir
    samples_dir = out / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    sections_path = args.binfiles_outdir / "binfiles_sections.json"
    sections = load_sections(sections_path)

    resources = read_tsv(args.binfiles_outdir / "binfiles_resource_hits.tsv")
    sigs = read_tsv(args.binfiles_outdir / "binfiles_signature_hits.tsv")
    blobs = read_tsv(args.binfiles_outdir / "binfiles_blob_candidates.tsv")

    summary_rows = []
    gap_rows = []
    sample_rows = []

    for s in sections:
        idx = int(s["section_index"])
        start = int(s["schema_offset_dec"])
        end = int(s["scan_end_dec"])
        span = data[start:end]

        res = section_rows(resources, idx)
        sg = section_rows(sigs, idx)
        bl = section_rows(blobs, idx)

        ext_counts = Counter(r.get("ext", "") for r in res)
        sig_counts = Counter(r.get("signature", "") for r in sg)

        # Resource gaps inside section.
        offsets = sorted(int(r["offset_dec"]) for r in res if r.get("offset_dec", "").isdigit())
        for a, b in zip(offsets, offsets[1:]):
            gap_rows.append({
                "section_index": idx,
                "from_offset_hex": hex(a),
                "to_offset_hex": hex(b),
                "gap": b - a,
            })

        label = classify_by_counts(dict(ext_counts), dict(sig_counts), len(bl))

        summary_rows.append({
            "section_index": idx,
            "schema_offset_hex": hex(start),
            "scan_end_hex": hex(end),
            "span_bytes": end - start,
            "entropy_first_64k": f"{entropy(span[:65536]):.4f}",
            "resource_count": len(res),
            "resource_ext_counts": dict(ext_counts),
            "signature_count": len(sg),
            "signature_counts": dict(sig_counts),
            "blob_candidate_count": len(bl),
            "rough_class": label,
            "first_160_ascii": ascii_preview(span[:160]),
        })

        # Dump samples: start, around first resources, around first sigs/blob candidates.
        sample_points = [("section_start", start)]
        for r in res[:5]:
            sample_points.append((f"resource_{r.get('ext','')}", int(r["offset_dec"])))
        for r in sg[:5]:
            sample_points.append((f"signature_{r.get('signature','')}", int(r["offset_dec"])))
        for r in bl[:5]:
            sample_points.append((f"blob_{r.get('payload_signature','')}", int(r["payload_offset_dec"])))

        seen_points = set()
        for j, (kind, off) in enumerate(sample_points):
            if off in seen_points:
                continue
            seen_points.add(off)
            sample = data[off:min(len(data), off + 4096)]
            fname = f"section{idx}_{j:02d}_{kind}_{off:08x}.bin".replace("/", "_")
            (samples_dir / fname).write_bytes(sample)
            sample_rows.append({
                "section_index": idx,
                "kind": kind,
                "offset_hex": hex(off),
                "sample_file": str((samples_dir / fname).relative_to(out)),
                "sample_size": len(sample),
                "sha256": hashlib.sha256(sample).hexdigest(),
                "starts_hex": sample[:32].hex(),
                "preview_ascii": ascii_preview(sample[:160]),
            })

    write_tsv(out / "section_summary.tsv", summary_rows, [
        "section_index", "schema_offset_hex", "scan_end_hex", "span_bytes",
        "entropy_first_64k", "resource_count", "resource_ext_counts",
        "signature_count", "signature_counts", "blob_candidate_count",
        "rough_class", "first_160_ascii"
    ])
    write_tsv(out / "section_gaps.tsv", gap_rows, [
        "section_index", "from_offset_hex", "to_offset_hex", "gap"
    ])
    write_tsv(out / "section_samples.tsv", sample_rows, [
        "section_index", "kind", "offset_hex", "sample_file", "sample_size",
        "sha256", "starts_hex", "preview_ascii"
    ])

    report = {
        "source": str(args.embeddb),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "section_count": len(sections),
        "summary": summary_rows,
        "sample_count": len(sample_rows),
        "note": "Section classification evidence. Rough classes are not final extraction labels.",
    }
    (out / "section_classify.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    md = []
    md.append("# binfiles section classification report\n")
    md.append(f"- source: `{args.embeddb}`")
    md.append(f"- sections: `{len(sections)}`")
    md.append("\n## Sections\n")
    for row in summary_rows:
        md.append(
            f"- section `{row['section_index']}` class `{row['rough_class']}` "
            f"span `{row['span_bytes']}` resources `{row['resource_count']}` "
            f"signatures `{row['signature_count']}` blobs `{row['blob_candidate_count']}` "
            f"entropy `{row['entropy_first_64k']}`"
        )
        md.append(f"  ext: `{row['resource_ext_counts']}`")
        md.append(f"  sig: `{row['signature_counts']}`")
    (out / "section_classify_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("OK: classify_bin_sections")
    print(f"source: {args.embeddb}")
    print(f"sections: {len(sections)}")
    for row in summary_rows:
        print(
            f"section {row['section_index']}: class={row['rough_class']} "
            f"span={row['span_bytes']} resources={row['resource_count']} "
            f"sigs={row['signature_count']} blobs={row['blob_candidate_count']} "
            f"entropy={row['entropy_first_64k']}"
        )
        print(f"  ext={row['resource_ext_counts']}")
        print(f"  sig={row['signature_counts']}")
    print(f"output: {out}")


if __name__ == "__main__":
    main()
