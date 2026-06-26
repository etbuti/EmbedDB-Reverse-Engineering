#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Open English Learning Archive - NCE embeddb extractor v0.3

Goal:
  Map ShineSoft/MyEbook embeddb into open preservation structure.
  v0.3 fixes path extraction, separates table zones, identifies encoded payload
  candidates, and builds a clean GitHub Pages site tree.

Usage:
  python3 extract_nce_embeddb_v03.py embeddb out

Status:
  This version maps HTML/JPG/MP3 resource records and encoded payload starts.
  The remaining hard part is the MyEbook protected payload codec used for BLOBs.
"""
from __future__ import annotations
import argparse, json, re, hashlib, html, shutil
from pathlib import Path
from datetime import datetime, timezone

PATH_RE = re.compile(b'g:/nceproject/[^\x00]+')
HTML_RE = re.compile(b'(?:nce1|help|\d+-\d+)\.htm')
SCHEMA_MARKERS = [b'binfiles[filename:S,bindata:B]', b'realfiles[filename:S,offset:I,size:I]', b'ebookmm', b'ebook mm file']


def dec_gbk(b: bytes) -> str:
    return b.decode('gbk', errors='replace')


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def classify(path: str) -> str:
    p = path.lower()
    if p.endswith(('.htm', '.html')): return 'html'
    if p.endswith(('.jpg', '.jpeg')): return 'image'
    if p.endswith('.xml'): return 'xml'
    if p.endswith('.mp3'): return 'audio'
    if p.endswith('.js'): return 'javascript'
    if 'addons/' in p: return 'addon'
    return 'other'


def lesson_id(path: str) -> str:
    m = re.search(r'/1-(\d+)(?:\.htm|\.files/)', path)
    return f'lesson-{int(m.group(1)):03d}' if m else ('index' if '/nce1.' in path or path.endswith('/nce1.htm') else 'misc')


def collect_paths(data: bytes):
    items=[]
    seen=set()
    for m in PATH_RE.finditer(data):
        raw=m.group(0)
        s=dec_gbk(raw)
        if s in seen: dup=True
        else: dup=False; seen.add(s)
        rel=s.replace('g:/nceproject/','')
        items.append({'offset':m.start(),'path':s,'relative_path':rel,'kind':classify(rel),'lesson':lesson_id(s),'duplicate':dup})
    return items


def collect_html_names(data: bytes):
    return [{'offset':m.start(),'name':m.group(0).decode('ascii','replace')} for m in HTML_RE.finditer(data)]


def find_all(data: bytes, sig: bytes, limit=5000):
    out=[]; pos=0
    while True:
        i=data.find(sig,pos)
        if i<0: break
        out.append(i); pos=i+1
        if len(out)>=limit: break
    return out


def signature_scan(data: bytes):
    sigs={
        'myebook_encoded_jpeg_soi_ffd8': b'\xff\xd8',
        'mp3_frame_like_fffb': b'\xff\xfb',
        'id3': b'ID3',
        'riff': b'RIFF',
        'png': b'\x89PNG',
        'zip': b'PK\x03\x04',
        'zlib_789c': b'\x78\x9c',
        'zlib_78da': b'\x78\xda',
        'ebookmm': b'ebookmm',
        'ebook_mm_file': b'ebook mm file',
        'binfiles_schema': b'binfiles[filename:S,bindata:B]',
        'realfiles_schema': b'realfiles[filename:S,offset:I,size:I]',
    }
    return {k:find_all(data,v) for k,v in sigs.items()}


def write_blob_candidates(data: bytes, outdir: Path, sigs: dict):
    cand_dir=outdir/'forensics'/'payload_candidates'
    cand_dir.mkdir(parents=True, exist_ok=True)
    candidates=[]
    # MyEbook appears to preserve first bytes of JPEG/MP3-like streams but protects the body.
    for typ,key,ext,max_len in [
        ('encoded_image','myebook_encoded_jpeg_soi_ffd8','.bin',256*1024),
        ('mp3_frame_like','mp3_frame_like_fffb','.bin',512*1024),
    ]:
        for n,off in enumerate(sigs.get(key,[])[:200]):
            # end before next same signature, capped
            nexts=[x for x in sigs.get(key,[]) if x>off]
            end=min(nexts[0] if nexts else len(data), off+max_len, len(data))
            blob=data[off:end]
            fn=f'{typ}_{n:03d}_{off}{ext}'
            (cand_dir/fn).write_bytes(blob)
            candidates.append({'type':typ,'offset':off,'size':len(blob),'file':str(Path('forensics')/'payload_candidates'/fn),'sha256':sha256(blob)})
    return candidates


def make_site(outdir: Path, manifest: dict):
    site=outdir/'site'/'open-english'
    lesson=site/'nce'/'book1'/'lesson-001'
    lesson.mkdir(parents=True, exist_ok=True)
    (site/'index.html').write_text(f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Open English Learning Archive</title><style>body{{font-family:Arial,"Noto Sans SC",sans-serif;max-width:940px;margin:40px auto;padding:0 20px;line-height:1.75;color:#222}}.card{{border:1px solid #ddd;border-radius:14px;padding:20px;margin:20px 0;background:#fafafa}}code{{background:#f5f5f5;padding:2px 5px;border-radius:4px}}a{{color:#0645ad}}</style></head><body><h1>Open English Learning Archive</h1><h2>公益英语学习档案馆</h2><div class="card"><p>Phase 1: NCE1A embeddb → HTML / JPG / MP3 / JSON.</p><p>当前已识别资源路径：<b>{manifest['resource_path_count']}</b> 个；唯一资源：<b>{manifest['unique_resource_path_count']}</b> 个。</p><p><a href="./nce/book1/lesson-001/">Lesson 1 示例页</a></p></div><div class="card"><h3>Project Policy</h3><p>公开页面优先发布原创学习笔记、AI 朗读、词汇和语法解析；原版权内容只在法律允许范围内展示。</p></div></body></html>''',encoding='utf-8')
    targets=[p for p in manifest['paths'] if '/1-5.files/' in p['path'] or p['path'].endswith('/1-5.htm')]
    rows=''.join(f'<tr><td>{html.escape(t["kind"])}</td><td><code>{html.escape(t["path"])}</code></td><td>{t["offset"]}</td></tr>' for t in targets)
    (lesson/'index.html').write_text(f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NCE Book1 Lesson 1</title><style>body{{font-family:Arial,"Noto Sans SC",sans-serif;max-width:940px;margin:40px auto;padding:0 20px;line-height:1.75}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px}}code{{background:#f5f5f5;padding:2px 5px}}</style></head><body><p><a href="../../../">← Open English</a></p><h1>NCE Book 1 · Lesson 1</h1><p>v0.3 已完成资源地图与 payload 候选定位；下一版进入 MyEbook 保护流解码。</p><h2>Lesson 1 目标资源</h2><table><tr><th>类型</th><th>路径</th><th>偏移</th></tr>{rows}</table><h2>开放格式目标</h2><ul><li>lesson.html</li><li>image001.jpg / image002.jpg</li><li>audio-ai.mp3</li><li>manifest.json</li></ul></body></html>''',encoding='utf-8')
    (lesson/'manifest.json').write_text(json.dumps({'lesson':'book1/lesson-001','targets':targets,'status':'mapped_payload_codec_pending'},ensure_ascii=False,indent=2),encoding='utf-8')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('embeddb')
    ap.add_argument('outdir')
    args=ap.parse_args()
    src=Path(args.embeddb); out=Path(args.outdir)
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)
    data=src.read_bytes()
    paths=collect_paths(data)
    unique=[]; seen=set()
    for p in paths:
        if p['path'] not in seen:
            unique.append(p); seen.add(p['path'])
    html_names=collect_html_names(data)
    sigs=signature_scan(data)
    candidates=write_blob_candidates(data,out,sigs)
    manifest={
        'tool':'extract_nce_embeddb_v03.py',
        'created_at':datetime.now(timezone.utc).isoformat(),
        'source_file':str(src),
        'source_size':len(data),
        'source_sha256':sha256(data),
        'format':'ShineSoft/MyEbook embeddb (protected payloads)',
        'markers':{m.decode('ascii','replace'):data.find(m) for m in SCHEMA_MARKERS},
        'resource_path_count':len(paths),
        'unique_resource_path_count':len(unique),
        'paths':paths,
        'unique_paths':unique,
        'html_names':html_names,
        'signature_scan':sigs,
        'payload_candidates':candidates,
        'status':'resource_map_complete__myebook_payload_codec_pending',
        'next':'Reverse MyEbook protected BLOB codec, then emit real HTML/JPG/MP3 payloads.'
    }
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'paths.tsv').write_text('\n'.join(f"{p['offset']}\t{p['kind']}\t{p['lesson']}\t{p['path']}" for p in paths),encoding='utf-8')
    (out/'unique_paths.tsv').write_text('\n'.join(f"{p['kind']}\t{p['lesson']}\t{p['path']}" for p in unique),encoding='utf-8')
    make_site(out,manifest)
    print('[OK] embeddb mapped')
    print(f'[OK] paths: {len(paths)} total / {len(unique)} unique')
    print(f'[OK] payload candidates: {len(candidates)}')
    print(f'[OK] site: {out/"site"/"open-english"}')

if __name__=='__main__': main()
