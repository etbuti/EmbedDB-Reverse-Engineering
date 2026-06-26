#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Open English Learning Archive - NCE embeddb extractor v0.4

Purpose:
  Convert ShineSoft/MyEbook NCE embeddb into an open preservation workspace.

Status of v0.4:
  - maps resource names and duplicated tables
  - extracts protected BLOB candidates for JPEG/MP3/XML/HTML investigation
  - builds JSON manifests and a clean GitHub Pages tree
  - adds a codec-lab report for the remaining MyEbook protected payload layer

Usage:
  python3 extract_nce_embeddb_v04.py embeddb out

Important:
  v0.4 does NOT claim the protected payload is fully decoded yet.  It creates
  reproducible forensic output so the next version can finish the codec.
"""
from __future__ import annotations
import argparse, json, re, hashlib, html, shutil, struct, zlib
from pathlib import Path
from datetime import datetime, timezone

PATH_RE = re.compile(rb'g:/nceproject/[^\x00]+')
HTML_NAME_RE = re.compile(rb'(?:nce1|help|\d+-\d+)\.htm')
SCHEMA_MARKERS = [
    b'binfiles[filename:S,bindata:B]',
    b'realfiles[filename:S,offset:I,size:I]',
    b'ebookmm', b'ebook mm file', b'audioebook'
]


def dec_gbk(b: bytes) -> str:
    return b.decode('gbk', errors='replace')


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def safe_rel_path(p: str) -> str:
    p = p.replace('g:/nceproject/', '')
    p = p.replace('\\', '/')
    p = p.replace(':', '_')
    while p.startswith('/'):
        p = p[1:]
    return p


def classify(path: str) -> str:
    p = path.lower()
    if p.endswith(('.htm', '.html')): return 'html'
    if p.endswith(('.jpg', '.jpeg')): return 'image'
    if p.endswith('.xml'): return 'xml'
    if p.endswith('.mp3'): return 'audio'
    if p.endswith('.js'): return 'javascript'
    if '/addons/' in p or p.startswith('addons/'): return 'addon'
    return 'other'


def lesson_id(path: str) -> str:
    m = re.search(r'/1-(\d+)(?:\.htm|\.files/)', path)
    if m:
        return f'lesson-{int(m.group(1)):03d}'
    if '/nce1.' in path or path.endswith('/nce1.htm'):
        return 'index'
    return 'misc'


def collect_paths(data: bytes):
    items=[]; seen=set()
    for m in PATH_RE.finditer(data):
        raw=m.group(0)
        s=dec_gbk(raw)
        rel=safe_rel_path(s)
        items.append({
            'offset':m.start(), 'path':s, 'relative_path':rel,
            'kind':classify(rel), 'lesson':lesson_id(s),
            'duplicate': s in seen
        })
        seen.add(s)
    return items


def find_all(data: bytes, sig: bytes, limit=100000):
    out=[]; pos=0
    while True:
        i=data.find(sig,pos)
        if i<0: break
        out.append(i); pos=i+1
        if len(out)>=limit: break
    return out


def pair_markers(starts, ends, min_size=32, max_size=2_000_000):
    pairs=[]
    ends_sorted=sorted(ends)
    for s in starts:
        e = next((x for x in ends_sorted if x > s + min_size and x - s <= max_size), None)
        if e is not None:
            pairs.append((s, e+2))
    # remove nested/duplicate pairs by same start
    clean=[]; used=set()
    for s,e in pairs:
        if s not in used:
            clean.append((s,e)); used.add(s)
    return clean


def scan_signatures(data: bytes):
    sigs={
        'jpeg_soi_ffd8': b'\xff\xd8',
        'jpeg_eoi_ffd9': b'\xff\xd9',
        'mp3_frame_fffb': b'\xff\xfb',
        'mp3_frame_fff3': b'\xff\xf3',
        'id3': b'ID3',
        'riff': b'RIFF',
        'png': b'\x89PNG',
        'gif87a': b'GIF87a',
        'gif89a': b'GIF89a',
        'zip': b'PK\x03\x04',
        'zlib_7801': b'\x78\x01',
        'zlib_785e': b'\x78\x5e',
        'zlib_789c': b'\x78\x9c',
        'zlib_78da': b'\x78\xda',
        'html_lower': b'<html',
        'html_upper': b'<HTML',
        'xml': b'<?xml',
    }
    return {k: find_all(data,v) for k,v in sigs.items()}


def zlib_probe(data: bytes, positions):
    hits=[]
    for off in positions[:1000]:
        try:
            obj=zlib.decompressobj()
            out=obj.decompress(data[off:])
            consumed=len(data[off:])-len(obj.unused_data)
            if consumed > 4 and len(out) > 16:
                hits.append({'offset':off,'consumed':consumed,'out_size':len(out),'head_hex':out[:32].hex()})
        except Exception:
            pass
    return hits


def write_protected_blobs(data: bytes, outdir: Path, sigs: dict):
    blobdir=outdir/'protected_blobs'
    blobdir.mkdir(parents=True, exist_ok=True)
    entries=[]
    # JPEG-like: SOI/EOI survives, interior appears protected.
    jpg_pairs=pair_markers(sigs['jpeg_soi_ffd8'], sigs['jpeg_eoi_ffd9'], min_size=100, max_size=250000)
    for n,(s,e) in enumerate(jpg_pairs):
        blob=data[s:e]
        name=f'protected_jpeg_{n:03d}_{s}_{len(blob)}.bin'
        (blobdir/name).write_bytes(blob)
        entries.append({'type':'protected_jpeg','offset':s,'size':len(blob),'file':str(Path('protected_blobs')/name),'sha256':sha256(blob),'head_hex':blob[:24].hex(),'tail_hex':blob[-24:].hex()})
    # MP3-like windows. These are not validated audio yet; they are reproducible candidates.
    mp3_starts=sorted(set(sigs['mp3_frame_fffb'] + sigs['mp3_frame_fff3']))
    for n,s in enumerate(mp3_starts[:80]):
        next_s=mp3_starts[n+1] if n+1 < len(mp3_starts) else len(data)
        e=min(next_s, s+262144, len(data))
        if e-s < 256: continue
        blob=data[s:e]
        name=f'protected_mp3win_{n:03d}_{s}_{len(blob)}.bin'
        (blobdir/name).write_bytes(blob)
        entries.append({'type':'protected_mp3_window','offset':s,'size':len(blob),'file':str(Path('protected_blobs')/name),'sha256':sha256(blob),'head_hex':blob[:24].hex()})
    return entries


def header_info(data: bytes):
    out={'magic_hex':data[:16].hex(), 'file_size':len(data)}
    if len(data)>=8:
        out['u32be_at_4']=struct.unpack('>I',data[4:8])[0]
        out['u32le_at_4']=struct.unpack('<I',data[4:8])[0]
        out['size_field_matches_be_at_4'] = out['u32be_at_4'] == len(data)
    return out


def make_site(outdir: Path, manifest: dict):
    site=outdir/'site'/'open-english'
    lesson=site/'nce'/'book1'/'lesson-001'
    lesson.mkdir(parents=True, exist_ok=True)
    (site/'index.html').write_text(f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Open English Learning Archive</title><style>body{{font-family:Arial,"Noto Sans SC",sans-serif;max-width:960px;margin:40px auto;padding:0 20px;line-height:1.75;color:#222}}.card{{border:1px solid #ddd;border-radius:14px;padding:20px;margin:20px 0;background:#fafafa}}code{{background:#f5f5f5;padding:2px 5px;border-radius:4px}}a{{color:#0645ad}}</style></head><body><h1>Open English Learning Archive</h1><h2>公益英语学习档案馆</h2><div class="card"><p><b>Phase 1:</b> NCE1A embeddb → HTML / JPG / MP3 / JSON.</p><p>v0.4 已生成开放保存工作区：资源路径 <b>{manifest['resource_path_count']}</b> 个，唯一资源 <b>{manifest['unique_resource_path_count']}</b> 个，保护流候选 <b>{len(manifest['protected_blob_candidates'])}</b> 个。</p><p><a href="./nce/book1/lesson-001/">Lesson 1 示例页</a></p></div><div class="card"><h3>Policy</h3><p>公开页面优先发布原创学习笔记、AI 朗读、词汇、语法解析；原版权内容只在法律允许范围内展示。</p></div></body></html>''',encoding='utf-8')
    targets=[p for p in manifest['paths'] if '/1-5.files/' in p['path'] or p['path'].endswith('/1-5.htm')]
    rows=''.join(f'<tr><td>{html.escape(t["kind"])}</td><td><code>{html.escape(t["path"])}</code></td><td>{t["offset"]}</td></tr>' for t in targets)
    (lesson/'index.html').write_text(f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NCE Book1 Lesson 1</title><style>body{{font-family:Arial,"Noto Sans SC",sans-serif;max-width:960px;margin:40px auto;padding:0 20px;line-height:1.75}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px}}code{{background:#f5f5f5;padding:2px 5px}}</style></head><body><p><a href="../../../">← Open English</a></p><h1>NCE Book 1 · Lesson 1</h1><p>v0.4 进入保护流拆解阶段。网页骨架、JSON 清单和候选 BLOB 已输出；下一步是把 MyEbook payload codec 解开，生成真正的 <code>lesson.html</code>、<code>image001.jpg</code>、<code>image002.jpg</code> 和音频。</p><h2>Lesson 1 目标资源</h2><table><tr><th>类型</th><th>路径</th><th>路径偏移</th></tr>{rows}</table><h2>开放格式目标</h2><ul><li>lesson.html</li><li>image001.jpg / image002.jpg</li><li>audio-ai.mp3</li><li>manifest.json</li></ul></body></html>''',encoding='utf-8')
    (lesson/'manifest.json').write_text(json.dumps({'lesson':'book1/lesson-001','targets':targets,'status':'protected_payload_codec_pending'},ensure_ascii=False,indent=2),encoding='utf-8')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('embeddb')
    ap.add_argument('outdir')
    args=ap.parse_args()
    src=Path(args.embeddb); out=Path(args.outdir)
    if not src.exists():
        raise SystemExit(f'embeddb not found: {src}')
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)
    data=src.read_bytes()
    paths=collect_paths(data)
    unique=[]; seen=set()
    for p in paths:
        if p['path'] not in seen:
            unique.append(p); seen.add(p['path'])
    sigs=scan_signatures(data)
    zpos=sigs['zlib_7801']+sigs['zlib_785e']+sigs['zlib_789c']+sigs['zlib_78da']
    codec_lab={
        'header':header_info(data),
        'schema_marker_offsets':{m.decode('ascii','replace'):data.find(m) for m in SCHEMA_MARKERS},
        'signature_counts':{k:len(v) for k,v in sigs.items()},
        'signature_offsets_sample':{k:v[:50] for k,v in sigs.items()},
        'zlib_probe_hits':zlib_probe(data, sorted(set(zpos))),
        'observation':'JPEG SOI/EOI and MP3-frame-like markers occur, but payload interiors are protected/encoded; no direct HTML/JPG/MP3 payload has been validated yet.'
    }
    protected=write_protected_blobs(data,out,sigs)
    manifest={
        'tool':'extract_nce_embeddb_v04.py',
        'created_at':datetime.now(timezone.utc).isoformat(),
        'source_file':str(src),'source_size':len(data),'source_sha256':sha256(data),
        'format':'ShineSoft/MyEbook embeddb',
        'resource_path_count':len(paths),'unique_resource_path_count':len(unique),
        'paths':paths,'unique_paths':unique,
        'codec_lab':codec_lab,
        'protected_blob_candidates':protected,
        'status':'open_workspace_generated__protected_payload_codec_pending',
        'next':'Reverse the MyEbook protected payload codec, then write decoded HTML/JPG/MP3 into site/open-english.'
    }
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'codec_lab.json').write_text(json.dumps(codec_lab,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'paths.tsv').write_text('\n'.join(f"{p['offset']}\t{p['kind']}\t{p['lesson']}\t{p['path']}" for p in paths),encoding='utf-8')
    (out/'unique_paths.tsv').write_text('\n'.join(f"{p['kind']}\t{p['lesson']}\t{p['path']}" for p in unique),encoding='utf-8')
    make_site(out,manifest)
    print('[OK] v0.4 workspace generated')
    print(f'[OK] paths: {len(paths)} total / {len(unique)} unique')
    print(f'[OK] protected blob candidates: {len(protected)}')
    print(f'[OK] site: {out/"site"/"open-english"}')

if __name__ == '__main__':
    main()
