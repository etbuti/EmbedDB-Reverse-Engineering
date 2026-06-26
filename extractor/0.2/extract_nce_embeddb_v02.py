#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Open English Learning Archive - NCE embeddb extractor v0.2

Purpose:
  1) Inspect ShineSoft/MyEbook embeddb resource databases.
  2) Extract all visible resource names into manifest.json.
  3) Build a clean GitHub Pages skeleton under site/open-english/.
  4) Dump forensic binary ranges for the next parser stage.

Usage:
  python extract_nce_embeddb_v02.py embeddb out

Notes:
  v0.2 does NOT claim final payload decoding yet. It maps the container
  and prepares a clean website tree. v0.3 will decode realfiles offset/size
  and embedded BLOB payloads once the packed table format is finalized.
"""

from __future__ import annotations
import argparse, json, re, hashlib, html
from pathlib import Path
from datetime import datetime, timezone

GBK_PATH = re.compile(rb'g:/nceproject/[^\x00]+')
HTML_NAME = re.compile(rb'(?:nce1|help|\d+-\d+)\.htm')
SCHEMA = b'_catalog[caption:S,value:S,childnum:S,icon:S,selicon:S],binfiles[filename:S,bindata:B],realfiles[filename:S,offset:I,size:I]'


def decode_gbk(bs: bytes) -> str:
    return bs.decode('gbk', errors='replace')


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect_paths(data: bytes):
    paths = []
    for m in GBK_PATH.finditer(data):
        raw = m.group(0)
        s = decode_gbk(raw)
        rel = s.replace('g:/nceproject/', '')
        paths.append({
            'offset': m.start(),
            'raw_hex': raw[:16].hex(),
            'path': s,
            'relative_path': rel,
            'kind': classify(rel),
        })
    return paths


def collect_html_names(data: bytes):
    names = []
    # only from catalog area near tail; include offsets
    for m in HTML_NAME.finditer(data):
        val = m.group(0).decode('ascii', errors='replace')
        if not any(x['name'] == val and abs(x['offset'] - m.start()) < 5 for x in names):
            names.append({'offset': m.start(), 'name': val})
    return names


def classify(path: str) -> str:
    p = path.lower()
    if p.endswith('.htm') or p.endswith('.html'):
        return 'html'
    if p.endswith('.jpg') or p.endswith('.jpeg'):
        return 'image'
    if p.endswith('.xml'):
        return 'xml'
    if p.endswith('.mp3'):
        return 'audio'
    if p.endswith('.js'):
        return 'javascript'
    return 'other'


def signature_scan(data: bytes):
    sigs = {
        'jpeg_soi': b'\xff\xd8',
        'jpeg_eoi': b'\xff\xd9',
        'mp3_frame_like': b'\xff\xfb',
        'id3': b'ID3',
        'riff': b'RIFF',
        'png': b'\x89PNG',
        'zip': b'PK\x03\x04',
        'zlib_78_9c': b'\x78\x9c',
        'zlib_78_da': b'\x78\xda',
        'ebookmm': b'ebookmm',
        'ebook_mm_file': b'ebook mm file',
        'schema': b'realfiles[filename:S,offset:I,size:I]',
    }
    out = {}
    for name, sig in sigs.items():
        hits = []
        start = 0
        while True:
            i = data.find(sig, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
            if len(hits) >= 1000:
                break
        out[name] = hits
    return out


def write_context_dumps(data: bytes, outdir: Path, offsets: list[int], radius=256):
    dumpdir = outdir / 'forensics' / 'context'
    dumpdir.mkdir(parents=True, exist_ok=True)
    for off in sorted(set(o for o in offsets if isinstance(o, int) and o >= 0)):
        start = max(0, off - radius)
        end = min(len(data), off + radius)
        (dumpdir / f'offset_{off:08d}.bin').write_bytes(data[start:end])


def create_site(outdir: Path, paths: list[dict], html_names: list[dict], manifest: dict):
    site = outdir / 'site' / 'open-english'
    lesson = site / 'nce' / 'book1' / 'lesson-001'
    lesson.mkdir(parents=True, exist_ok=True)

    (site / 'index.html').write_text(f'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Open English Learning Archive | 公益英语学习档案馆</title>
<style>
body{{font-family:Arial,"Noto Sans SC",sans-serif;max-width:920px;margin:40px auto;padding:0 20px;line-height:1.75;color:#222}}
.card{{border:1px solid #ddd;border-radius:14px;padding:20px;margin:20px 0;background:#fafafa}}
a{{color:#0645ad}} code{{background:#f3f3f3;padding:2px 5px;border-radius:5px}}
.small{{color:#666;font-size:14px}}
</style>
</head>
<body>
<h1>Open English Learning Archive</h1>
<h2>公益英语学习档案馆</h2>
<p>一个面向英语学习者的公益学习档案项目。第一阶段：把旧式课件资源转换成现代开放格式。</p>
<div class="card">
<h3>NCE Book 1 · NCE1A Conversion</h3>
<p>当前状态：已识别 <b>{len(paths)}</b> 个资源路径，正在解析 embeddb 的真实 payload 编码。</p>
<p><a href="./nce/book1/lesson-001/">进入 Lesson 1 示例页</a></p>
</div>
<div class="card">
<h3>Project Scope</h3>
<ul><li>HTML / JPG / MP3 / JSON 开放格式</li><li>AI 朗读</li><li>重点单词</li><li>语法解析</li><li>学习心得</li></ul>
</div>
<p class="small">Copyright note: original copyrighted materials will only be displayed where legally permitted.</p>
</body></html>''', encoding='utf-8')

    lesson_targets = [p for p in paths if '/1-5.files/' in p['relative_path'] or p['relative_path'].endswith('/1-5.htm')]
    rows = '\n'.join(f'<tr><td>{html.escape(x["kind"])}</td><td><code>{html.escape(x["relative_path"])}</code></td><td>{x["offset"]}</td></tr>' for x in lesson_targets)
    if not rows:
        rows = '<tr><td colspan="3">1-5 相关路径尚未在路径表中定位；请查看 manifest.json。</td></tr>'

    (lesson / 'index.html').write_text(f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lesson 1 | Open English Learning Archive</title>
<style>body{{font-family:Arial,"Noto Sans SC",sans-serif;max-width:900px;margin:40px auto;padding:0 20px;line-height:1.7}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px}}code{{background:#f5f5f5;padding:2px 5px}}</style></head>
<body>
<p><a href="../../../">← Open English Learning Archive</a></p>
<h1>Lesson 1 · 示例页</h1>
<p>这一页是转换工程的占位示例。v0.2 已经整理路径；v0.3 继续导出真实 HTML/JPG/MP3 文件体。</p>
<h2>已定位的 Lesson 1 相关资源</h2>
<table><tr><th>类型</th><th>路径</th><th>embeddb 偏移</th></tr>{rows}</table>
<h2>下一步</h2>
<p>解析 <code>realfiles[filename:S,offset:I,size:I]</code> 与 <code>binfiles[filename:S,bindata:B]</code> 的 packed table，把资源体写出为 HTML/JPG/MP3。</p>
</body></html>''', encoding='utf-8')

    (lesson / 'manifest.json').write_text(json.dumps({
        'project': 'Open English Learning Archive',
        'lesson': 'book1/lesson-001',
        'targets': lesson_targets,
        'status': 'mapped_paths_payload_decoder_pending',
    }, ensure_ascii=False, indent=2), encoding='utf-8')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('embeddb', help='path to embeddb')
    ap.add_argument('outdir', help='output directory')
    args = ap.parse_args()
    src = Path(args.embeddb)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()

    paths = collect_paths(data)
    html_names = collect_html_names(data)
    sigs = signature_scan(data)

    manifest = {
        'tool': 'extract_nce_embeddb_v02.py',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'source_file': str(src),
        'source_size': len(data),
        'source_sha256': sha256(data),
        'format_markers': {
            'has_schema': SCHEMA in data,
            'schema_offset': data.find(SCHEMA),
            'ebookmm_offset': data.find(b'ebookmm'),
            'ebook_mm_file_offset': data.find(b'ebook mm file'),
        },
        'resource_path_count': len(paths),
        'html_name_count': len(html_names),
        'paths': paths,
        'html_names': html_names,
        'signature_scan': sigs,
        'status': 'container_mapped_payload_decoder_pending',
        'next': 'Decode packed table for realfiles offset/size and binfiles bindata, then write HTML/JPG/MP3 payloads.'
    }

    (outdir / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    (outdir / 'paths.txt').write_text('\n'.join(f'{p["offset"]}\t{p["kind"]}\t{p["relative_path"]}' for p in paths), encoding='utf-8')
    (outdir / 'html_names.txt').write_text('\n'.join(f'{x["offset"]}\t{x["name"]}' for x in html_names), encoding='utf-8')

    interesting = []
    interesting += [data.find(SCHEMA), data.find(b'ebookmm'), data.find(b'ebook mm file')]
    interesting += [p['offset'] for p in paths[:10]] + [p['offset'] for p in paths[-10:]]
    for key in ('jpeg_soi','mp3_frame_like','zlib_78_9c','zlib_78_da'):
        interesting += sigs.get(key, [])[:10]
    write_context_dumps(data, outdir, interesting)
    create_site(outdir, paths, html_names, manifest)

    print(f'[OK] source: {src} ({len(data)} bytes)')
    print(f'[OK] resource paths: {len(paths)}')
    print(f'[OK] html names: {len(html_names)}')
    print(f'[OK] manifest: {outdir / "manifest.json"}')
    print(f'[OK] site skeleton: {outdir / "site" / "open-english"}')

if __name__ == '__main__':
    main()
