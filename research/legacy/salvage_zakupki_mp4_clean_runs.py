from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import os
import re
import sys
from pathlib import Path

os.environ["RECOVER_FOLDER"] = "ЗАКУПКИ"
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


ENC_ROOT = Path(_case_value('8df57692b42e1f6f68e0'))
OUT_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORT_ROOT = OUT_ROOT / "_technical_reports" / "zakupki_salvage_previews" / "mp4_clean_runs_mass"
EXT = ".xzg9VRelb"
CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf"}
FTYP = bytes.fromhex(_case_value('cfbf6ef8699e798e434a'))


def safe_name(rel: Path) -> str:
    return re.sub(r"[^0-9A-Za-zА-Яа-я._-]+", "_", str(rel))[:160]


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def iter_boxes(buf: bytes):
    pos = 0
    while pos + 8 <= len(buf):
        size = int.from_bytes(buf[pos : pos + 4], "big")
        typ = buf[pos + 4 : pos + 8]
        head = 8
        if size == 1:
            if pos + 16 > len(buf):
                break
            size = int.from_bytes(buf[pos + 8 : pos + 16], "big")
            head = 16
        if size < head or pos + size > len(buf):
            break
        yield typ, pos, size, head, buf[pos : pos + size]
        pos += size


def parse_tree(buf: bytes):
    return [
        (typ, bytearray(box), parse_tree(box[head:size]) if typ in CONTAINERS else None, head)
        for typ, pos, size, head, box in iter_boxes(buf)
    ]


def build_tree(nodes) -> bytes:
    out = bytearray()
    for typ, box, children, head in nodes:
        if children is None:
            out += bytes(box)
        else:
            payload = build_tree(children)
            new = bytearray(box[:head]) + payload
            new[:4] = len(new).to_bytes(4, "big")
            out += new
    return bytes(out)


def get_child(nodes, typ: bytes):
    return next(n for n in nodes if n[0] == typ)


def get_stbl(trak):
    return get_child(get_child(get_child(trak[2], b"mdia")[2], b"minf")[2], b"stbl")


def find_box_node(node, path: list[bytes]):
    cur = node
    for typ in path:
        cur = get_child(cur[2], typ)
    return cur


def make_box(typ: bytes, payload: bytes) -> bytearray:
    return bytearray((8 + len(payload)).to_bytes(4, "big") + typ + payload)


def box_stsz(sizes: list[int]) -> bytearray:
    return make_box(
        b"stsz",
        b"\0\0\0\0"
        + (0).to_bytes(4, "big")
        + len(sizes).to_bytes(4, "big")
        + b"".join(s.to_bytes(4, "big") for s in sizes),
    )


def box_stss(keys: list[int]) -> bytearray:
    return make_box(
        b"stss",
        b"\0\0\0\0" + len(keys).to_bytes(4, "big") + b"".join(k.to_bytes(4, "big") for k in keys),
    )


def box_stsc() -> bytearray:
    return make_box(
        b"stsc",
        b"\0\0\0\0"
        + (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big"),
    )


def box_co64(offsets: list[int]) -> bytearray:
    return make_box(
        b"co64",
        b"\0\0\0\0" + len(offsets).to_bytes(4, "big") + b"".join(o.to_bytes(8, "big") for o in offsets),
    )


def box_stts(entries: list[tuple[int, int]]) -> bytearray:
    return make_box(
        b"stts",
        b"\0\0\0\0"
        + len(entries).to_bytes(4, "big")
        + b"".join(c.to_bytes(4, "big") + d.to_bytes(4, "big") for c, d in entries),
    )


def patch_duration(box_node, duration: int, timescale: int | None = None) -> None:
    b = box_node[1]
    version = b[8]
    if box_node[0] == b"mvhd":
        if version == 0:
            if timescale is not None:
                b[20:24] = timescale.to_bytes(4, "big")
            b[24:28] = duration.to_bytes(4, "big")
        else:
            if timescale is not None:
                b[28:32] = timescale.to_bytes(4, "big")
            b[32:40] = duration.to_bytes(8, "big")
    elif box_node[0] in {b"tkhd", b"mdhd"}:
        if version == 0:
            if box_node[0] == b"mdhd" and timescale is not None:
                b[20:24] = timescale.to_bytes(4, "big")
            b[24:28] = duration.to_bytes(4, "big")
        else:
            if box_node[0] == b"mdhd" and timescale is not None:
                b[28:32] = timescale.to_bytes(4, "big")
            b[32:40] = duration.to_bytes(8, "big")


def parse_tables(stbl):
    boxes = {n[0]: bytes(n[1]) for n in stbl[2]}
    needed = {b"stsd", b"stsz", b"stsc", b"co64", b"stts"}
    if not needed.issubset(boxes) or b"stss" not in boxes:
        raise ValueError("missing video tables")
    stsz = boxes[b"stsz"]
    sample_size = int.from_bytes(stsz[12:16], "big")
    n = int.from_bytes(stsz[16:20], "big")
    sizes = [sample_size] * n if sample_size else [int.from_bytes(stsz[20 + i * 4 : 24 + i * 4], "big") for i in range(n)]
    co = boxes[b"co64"]
    cn = int.from_bytes(co[12:16], "big")
    chunks = [int.from_bytes(co[16 + i * 8 : 24 + i * 8], "big") for i in range(cn)]
    stsc = boxes[b"stsc"]
    rn = int.from_bytes(stsc[12:16], "big")
    runs = []
    for i in range(rn):
        runs.append((int.from_bytes(stsc[16 + i * 12 : 20 + i * 12], "big"), int.from_bytes(stsc[20 + i * 12 : 24 + i * 12], "big")))
    offsets = []
    sample = 0
    for ci, ch in enumerate(chunks, 1):
        spc = next(r[1] for j, r in enumerate(runs) if ci >= r[0] and (j == len(runs) - 1 or ci < runs[j + 1][0]))
        off = ch
        for _ in range(spc):
            if sample >= n:
                break
            offsets.append(off)
            off += sizes[sample]
            sample += 1
    stss = boxes[b"stss"]
    kn = int.from_bytes(stss[12:16], "big")
    keys = [int.from_bytes(stss[16 + i * 4 : 20 + i * 4], "big") for i in range(kn)]
    stts = boxes[b"stts"]
    tn = int.from_bytes(stts[12:16], "big")
    stts_entries = []
    for i in range(tn):
        stts_entries.append((int.from_bytes(stts[16 + i * 8 : 20 + i * 8], "big"), int.from_bytes(stts[20 + i * 8 : 24 + i * 8], "big")))
    return sizes, offsets, keys, stts_entries


def trim_stts(entries: list[tuple[int, int]], selected_indices: list[int]) -> list[tuple[int, int]]:
    vals = []
    for c, d in entries:
        vals.extend([d] * c)
    selected = [vals[i] for i in selected_indices if i < len(vals)]
    if not selected:
        return [(len(selected_indices), 1001)]
    out = []
    cur = selected[0]
    cnt = 0
    for v in selected:
        if v == cur:
            cnt += 1
        else:
            out.append((cnt, cur))
            cur = v
            cnt = 1
    out.append((cnt, cur))
    return out


def encrypted_windows(body_end: int, before: int, after: int, skipped: int) -> list[tuple[int, int]]:
    wins = []
    cur = 0
    decrypt_chunks = before
    while cur < body_end:
        for _ in range(max(0, decrypt_chunks)):
            if cur >= body_end:
                break
            s = cur
            e = min(body_end, cur + 0x20000)
            wins.append((s, e))
            cur = e
        if cur >= body_end:
            break
        cur = min(body_end, cur + max(0, skipped))
        decrypt_chunks = after
        if after <= 0:
            break
    return wins


def clean_gops(sizes: list[int], offsets: list[int], keys: list[int], wins: list[tuple[int, int]], data_len: int) -> list[tuple[int, int]]:
    out = []
    for idx, key in enumerate(keys):
        next_key = keys[idx + 1] if idx + 1 < len(keys) else len(sizes) + 1
        start_i = key - 1
        end_i = next_key - 1
        if start_i < 0 or end_i <= start_i or end_i > len(sizes):
            continue
        a = offsets[start_i]
        b = offsets[end_i - 1] + sizes[end_i - 1]
        if b > data_len:
            continue
        if any(max(a, s) < min(b, e) for s, e in wins):
            continue
        # IDR sanity: AVC samples here use 4-byte NAL sizes.
        sample = data_global[a : a + min(sizes[start_i], 200000)]
        if not sample or nal_types(sample)[:1] != [5]:
            continue
        out.append((key, next_key))
    return out


def nal_types(sample: bytes) -> list[int]:
    types = []
    pos = 0
    while pos + 4 <= len(sample):
        n = int.from_bytes(sample[pos : pos + 4], "big")
        pos += 4
        if n <= 0 or pos + n > len(sample):
            break
        types.append(sample[pos] & 0x1F)
        pos += n
    return types


def build_clip(data: bytes, moov: bytes, video_trak_index: int, sample_ranges: list[tuple[int, int]], output: Path) -> tuple[int, float, int]:
    tree = parse_tree(moov)
    moov_node = tree[0]
    traks = [n for n in moov_node[2] if n[0] == b"trak"]
    video = traks[video_trak_index]
    stbl = get_stbl(video)
    sizes, offsets, keys, stts_entries = parse_tables(stbl)
    selected = []
    key_positions = []
    pos = 1
    for start_sample, next_sample in sample_ranges:
        start_i = start_sample - 1
        end_i = next_sample - 1
        key_positions.append(pos)
        selected.extend(range(start_i, end_i))
        pos += end_i - start_i
    seg_sizes = [sizes[i] for i in selected]
    media = bytearray()
    new_offsets = []
    cur = 40
    for i in selected:
        new_offsets.append(cur)
        media += data[offsets[i] : offsets[i] + sizes[i]]
        cur += sizes[i]
    children = [n for n in stbl[2] if n[0] == b"stsd"]
    stts = trim_stts(stts_entries, selected)
    children += [
        (b"stts", box_stts(stts), None, 8),
        (b"stss", box_stss(key_positions), None, 8),
        (b"stsz", box_stsz(seg_sizes), None, 8),
        (b"stsc", box_stsc(), None, 8),
        (b"co64", box_co64(new_offsets), None, 8),
    ]
    stbl[2][:] = children
    moov_node[2][:] = [n for n in moov_node[2] if n[0] != b"trak"] + [video]
    duration = sum(c * d for c, d in stts)
    patch_duration(get_child(moov_node[2], b"mvhd"), duration, 30000)
    patch_duration(find_box_node(video, [b"tkhd"]), duration)
    patch_duration(find_box_node(video, [b"mdia", b"mdhd"]), duration, 30000)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(FTYP + (8 + len(media)).to_bytes(4, "big") + b"mdat" + bytes(media) + build_tree(tree))
    return len(seg_sizes), duration / 30000, len(media)


def choose_video_track(moov: bytes) -> tuple[int, object] | None:
    tree = parse_tree(moov)
    traks = [n for n in tree[0][2] if n[0] == b"trak"]
    for idx, trak in enumerate(traks):
        try:
            stbl = get_stbl(trak)
            parse_tables(stbl)
        except Exception:
            continue
        return idx, stbl
    return None


data_global = b""


def process_mp4(item: lr.EncryptedFile) -> dict[str, str]:
    global data_global
    enc = Path(item.path)
    rel = out_rel_for(enc)
    fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
    data = enc.read_bytes()[:body_end]
    data_global = data
    moov_pos = data.rfind(b"moov")
    if moov_pos < 4:
        return {"rel": str(rel), "status": "NO_MOOV"}
    moov_start = moov_pos - 4
    moov_size = int.from_bytes(data[moov_start:moov_start + 4], "big")
    if moov_size <= 8 or moov_start + moov_size > body_end:
        return {"rel": str(rel), "status": "BAD_MOOV"}
    moov = data[moov_start:moov_start + moov_size]
    chosen = choose_video_track(moov)
    if not chosen:
        return {"rel": str(rel), "status": "NO_VIDEO_TABLE"}
    video_idx, stbl = chosen
    sizes, offsets, keys, _ = parse_tables(stbl)
    before, after, skipped, source = rdt.chunking_params_for(item, {})
    wins = encrypted_windows(body_end, before, after, skipped)
    gops = clean_gops(sizes, offsets, keys, wins, moov_start)
    if not gops:
        return {"rel": str(rel), "status": "NO_CLEAN_GOPS", "keys": str(keys)}
    out_dir = REPORT_ROOT / safe_name(rel)
    rows = []
    for start_sample, next_sample in gops:
        out = out_dir / f"gop_{start_sample:03d}_{next_sample - 1:03d}.mp4"
        frames, seconds, media_bytes = build_clip(data, moov, video_idx, [(start_sample, next_sample)], out)
        rows.append((out.name, start_sample, next_sample - 1, frames, seconds, media_bytes))
    seq = out_dir / _case_value('f57f8f5bbb3dd6721fac')
    frames, seconds, media_bytes = build_clip(data, moov, video_idx, gops, seq)
    readme = out_dir / "README_salvage_segments.txt"
    with readme.open("w", encoding="utf-8") as f:
        f.write(f"Source: {enc}\n")
        f.write(f"Chunking: before={before} after={after} skipped=0x{skipped:x} source={source}\n")
        f.write("Only GOPs fully outside encrypted windows are included. No audio.\n\n")
        for row in rows:
            f.write(f"{row[0]} samples {row[1]}-{row[2]} frames {row[3]} seconds {row[4]:.3f} media_bytes {row[5]}\n")
        f.write(f"\nSequence: {seq.name} frames {frames} seconds {seconds:.3f} media_bytes {media_bytes}\n")
    return {"rel": str(rel), "status": "RECOVERED_CLEAN_RUNS", "gops": str(len(gops)), "seconds": f"{seconds:.3f}", "out": str(out_dir)}


def main() -> int:
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    items = []
    for files in groups.values():
        for item in files:
            enc = Path(item.path)
            rel = out_rel_for(enc)
            if rel.suffix.lower() == ".mp4" and not (OUT_ROOT / "ЗАКУПКИ" / rel).exists():
                items.append(item)
    print(f"mp4_remaining={len(items)}")
    results = []
    for item in sorted(items, key=lambda it: Path(it.path).stat().st_size):
        try:
            row = process_mp4(item)
        except Exception as exc:
            row = {"rel": str(out_rel_for(Path(item.path))), "status": "ERROR_" + type(exc).__name__, "detail": str(exc)}
        results.append(row)
        print(row, flush=True)
    summary = REPORT_ROOT / "summary.txt"
    with summary.open("w", encoding="utf-8") as f:
        for row in results:
            f.write(str(row) + "\n")
    print(f"summary={summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
