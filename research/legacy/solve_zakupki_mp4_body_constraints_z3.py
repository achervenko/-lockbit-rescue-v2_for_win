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
import shutil
import sys
import tempfile
from pathlib import Path

os.environ["RECOVER_FOLDER"] = "ЗАКУПКИ"
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import z3
import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes


ENC_ROOT = Path(_case_value('8df57692b42e1f6f68e0'))
OUT_ROOT = Path(_case_value('6bd784b051ab83e84361'))
EXT = ".xzg9VRelb"
CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf"}
FTYP_ISOM32 = bytes.fromhex(_case_value('cfbf6ef8699e798e434a'))


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def iter_boxes(buf: bytes):
    pos = 0
    while pos + 8 <= len(buf):
        size = int.from_bytes(buf[pos:pos + 4], "big")
        typ = buf[pos + 4:pos + 8]
        head = 8
        if size == 1:
            if pos + 16 > len(buf):
                break
            size = int.from_bytes(buf[pos + 8:pos + 16], "big")
            head = 16
        if size < head or pos + size > len(buf):
            break
        yield typ, pos, size, head, buf[pos:pos + size]
        pos += size


def parse_tree(buf: bytes):
    return [
        (typ, box, parse_tree(box[head:size]) if typ in CONTAINERS else None, head)
        for typ, pos, size, head, box in iter_boxes(buf)
    ]


def child(nodes, typ: bytes):
    return next(n for n in nodes if n[0] == typ)


def get_stbl(trak):
    return child(child(child(trak[2], b"mdia")[2], b"minf")[2], b"stbl")


def parse_tables(stbl):
    boxes = {n[0]: n[1] for n in stbl[2]}
    stsz = boxes[b"stsz"]
    n = int.from_bytes(stsz[16:20], "big")
    sizes = [int.from_bytes(stsz[20 + i * 4:24 + i * 4], "big") for i in range(n)]
    co = boxes[b"co64"]
    cn = int.from_bytes(co[12:16], "big")
    chunks = [int.from_bytes(co[16 + i * 8:24 + i * 8], "big") for i in range(cn)]
    stsc = boxes[b"stsc"]
    rn = int.from_bytes(stsc[12:16], "big")
    runs = []
    for i in range(rn):
        runs.append((int.from_bytes(stsc[16 + i * 12:20 + i * 12], "big"), int.from_bytes(stsc[20 + i * 12:24 + i * 12], "big")))
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
    keys = [int.from_bytes(stss[16 + i * 4:20 + i * 4], "big") for i in range(kn)]
    return sizes, offsets, set(keys)


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


def body_to_stream_index(body_off: int, wins: list[tuple[int, int]]) -> int | None:
    stream_base = 0
    for start, end in wins:
        if start <= body_off < end:
            return stream_base + (body_off - start)
        stream_base += end - start
    return None


def overlaps_windows(start: int, end: int, wins: list[tuple[int, int]]) -> bool:
    return any(max(start, s) < min(end, e) for s, e in wins)


def stable_sample_templates(
    data: bytes,
    sizes: list[int],
    offsets: list[int],
    keyset: set[int],
    wins: list[tuple[int, int]],
    max_header: int = 16,
    min_sources: int = 12,
    threshold: float = 0.98,
) -> tuple[dict[bool, dict[int, int]], dict[str, int]]:
    samples: dict[bool, list[bytes]] = {True: [], False: []}
    for sample_no, (off, size) in enumerate(zip(offsets, sizes), start=1):
        end = off + min(size, 4 + max_header)
        if size <= 4 + max_header or end > len(data):
            continue
        if overlaps_windows(off, end, wins):
            continue
        sample = data[off + 4:end]
        # These MP4s store AVC samples with length-prefixed NAL units.
        n = int.from_bytes(data[off:off + 4], "big")
        if n <= 0 or n + 4 > size:
            continue
        is_key = sample_no in keyset
        samples[is_key].append(sample[:max_header])

    templates: dict[bool, dict[int, int]] = {True: {}, False: {}}
    stats = {
        "key_sources": len(samples[True]),
        "delta_sources": len(samples[False]),
        "key_bytes": 0,
        "delta_bytes": 0,
    }
    for is_key, rows in samples.items():
        if len(rows) < min_sources:
            continue
        usable = min(len(row) for row in rows)
        for pos in range(usable):
            counts: dict[int, int] = {}
            for row in rows:
                counts[row[pos]] = counts.get(row[pos], 0) + 1
            value, count = max(counts.items(), key=lambda kv: kv[1])
            if count / len(rows) >= threshold:
                templates[is_key][pos] = value
        stats["key_bytes" if is_key else "delta_bytes"] = len(templates[is_key])
    return templates, stats


def byte_from_word(word: z3.BitVecRef, idx: int) -> z3.BitVecRef:
    shift = 8 * (idx % 4)
    return z3.Extract(shift + 7, shift, word)


def block_words_for(fek_bytes, block_index: int):
    state = [word_from_bytes(fek_bytes[i * 4:i * 4 + 4]) for i in range(16)]
    # direct-decrypt increments Salsa state words 8/9 per 64-byte block.
    state[8] = state[8] + z3.BitVecVal(block_index, 32)
    return salsa20_words_z3(state)


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        _case_value('c01db03684a5b67e39af')
    )
    timeout_ms = int(sys.argv[2]) if len(sys.argv) > 2 else 600000
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    item = None
    files = None
    for fs in groups.values():
        for it in fs:
            if Path(it.path) == target:
                item = it
                files = fs
                break
        if item:
            break
    if item is None or files is None:
        print("target_not_found")
        return 2
    ks = build_group_keystream(files)
    cov = rdt.contiguous(ks)
    fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(target)
    start = fei_len - 64
    missing = [off for off in range(start, fei_len) if off not in ks]
    print(f"target={out_rel_for(target)} fei={fei_len} cov={cov} missing_count={len(missing)} missing={missing}", flush=True)

    data = target.read_bytes()[:body_end]
    moov_pos = data.rfind(b"moov")
    if moov_pos < 4:
        print("no_moov")
        return 2
    moov_start = moov_pos - 4
    moov_size = int.from_bytes(data[moov_start:moov_start + 4], "big")
    moov = data[moov_start:moov_start + moov_size]
    traks = [n for n in parse_tree(moov)[0][2] if n[0] == b"trak"]
    video_parse = None
    for trak in traks:
        try:
            parsed = parse_tables(get_stbl(trak))
        except Exception:
            continue
        video_parse = parsed
        break
    if video_parse is None:
        print("no_video_tables")
        return 2
    sizes, offsets, keyset = video_parse

    unknown = {off: z3.BitVec(f"ks_{off}", 8) for off in missing}
    fek_bytes = []
    for i in range(64):
        off = start + i
        if off in ks:
            fek_bytes.append(fei_ct[off] ^ ks[off])
        else:
            fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown[off])

    before, after, skipped, source = rdt.chunking_params_for(item, ks)
    wins = encrypted_windows(body_end, before, after, skipped)
    print(f"chunking={before}/{after}/0x{skipped:x}/{source} encrypted_windows={len(wins)} first_windows={wins[:4]}", flush=True)

    constraints: dict[int, int] = {}
    # Exact MP4 header and mdat header. For these videos co64 tells first media byte is at 40.
    header = FTYP_ISOM32 + (moov_start - 32).to_bytes(4, "big") + b"mdat"
    for off, val in enumerate(header):
        if body_to_stream_index(off, wins) is not None:
            constraints[off] = val
    # AVC samples in every encrypted window. Length prefix is exactly sample_size - 4.
    templates, template_stats = stable_sample_templates(data, sizes, offsets, keyset, wins)
    templated_constraints = 0
    for sample_no, (off, size) in enumerate(zip(offsets, sizes), start=1):
        ln = size - 4
        if ln <= 0:
            continue
        for j, val in enumerate(ln.to_bytes(4, "big")):
            if body_to_stream_index(off + j, wins) is not None:
                constraints[off + j] = val
        if body_to_stream_index(off + 4, wins) is not None:
            constraints[off + 4] = 0x65 if sample_no in keyset else 0x41
        for pos, val in templates[sample_no in keyset].items():
            body_off = off + 4 + pos
            if body_to_stream_index(body_off, wins) is not None:
                if body_off not in constraints:
                    templated_constraints += 1
                constraints[body_off] = val
    print(f"sample_template_stats={template_stats} templated_constraints={templated_constraints}", flush=True)
    print(f"body_constraints={len(constraints)} first_offsets={sorted(constraints)[:20]} last_offsets={sorted(constraints)[-20:]}", flush=True)

    blocks: dict[int, list[z3.BitVecRef]] = {}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    enc = data
    for off, plain in sorted(constraints.items()):
        stream_off = body_to_stream_index(off, wins)
        if stream_off is None:
            continue
        block = stream_off // 64
        idx = stream_off % 64
        if block not in blocks:
            blocks[block] = block_words_for(fek_bytes, block)
        stream_byte = byte_from_word(blocks[block][idx // 4], idx)
        solver.add(stream_byte == z3.BitVecVal(enc[off] ^ plain, 8))
    print(f"z3_blocks={len(blocks)}", flush=True)
    status = solver.check()
    print(f"z3_status={status}", flush=True)
    if status != z3.sat:
        return 2
    model = solver.model()
    learned = dict(ks)
    for off, var in unknown.items():
        learned[off] = model.eval(var).as_long()
    fek = bytes(fei_ct[start + i] ^ learned[start + i] for i in range(64))

    # Verify all constraints with Python Salsa20.
    state = [int.from_bytes(fek[i * 4:i * 4 + 4], "little") for i in range(16)]
    stream = bytearray()
    max_block = max(blocks)
    for block in range(max_block + 1):
        st = state[:]
        st[8] = (st[8] + block) & 0xFFFFFFFF
        stream.extend(rdt.salsa20_block(b"".join(x.to_bytes(4, "little") for x in st)))
    bad = [(off, plain, enc[off] ^ stream[off]) for off, plain in constraints.items() if off < len(stream) and (enc[off] ^ stream[off]) != plain]
    print(f"python_bad_constraints={len(bad)}", flush=True)
    if bad:
        print(bad[:10])
        return 2

    with tempfile.TemporaryDirectory(prefix="zak_mp4_body_z3_") as td:
        tmp = Path(td) / out_rel_for(target).name
        with rdt.helper_path(target, "direct") as direct_path:
            ok = rdt.direct_decrypt_with_timeout(
                rdt.REPO / "direct-decrypt.exe",
                direct_path,
                tmp,
                fek.hex(),
                max(0, before - 1),
                max(0, after - 1),
                hex(skipped),
            )
        valid = ok and rdt.validate_recovered(tmp, "mp4")
        print(f"direct_ok={ok} valid={valid} params={before}/{after}/0x{skipped:x}/{source}", flush=True)
        if not valid:
            if tmp.exists():
                print(f"head={tmp.read_bytes()[:64].hex()}", flush=True)
            return 2
        out = OUT_ROOT / out_rel_for(target)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp, out)
    print(f"RECOVERED_FULL_MP4 {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
