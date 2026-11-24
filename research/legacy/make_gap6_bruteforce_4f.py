from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import sys
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
EXT = ".xzg9VRelb"
TARGET = SRC_ROOT / "СКЛАД" / "Сканы документов" / "2025" / "2511" / _case_value('586dece1bf9289e9b4e7')
OUT_C = Path(_project_path('research/legacy/gap6_bruteforce_4f.c'))


def output_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def find_group():
    groups, _, _ = lr.scan_source(
        SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    for kek, files in groups.items():
        for item in files:
            if Path(item.path) == TARGET:
                return kek, files, item
    raise RuntimeError("target not found")


def c_array(name: str, data: bytes) -> str:
    rows = []
    for i in range(0, len(data), 16):
        rows.append("    " + ", ".join(f"0x{b:02x}" for b in data[i : i + 16]))
    return f"static const uint8_t {name}[{len(data)}] = {{\n" + ",\n".join(rows) + "\n};\n"


def c_string(text: object) -> str:
    return str(text).encode("unicode_escape").decode("ascii").replace('"', r'\"')


def main() -> int:
    kek, files, item = find_group()
    ks = {i: b for i, b in enumerate(rdt.run_dump_ks(max(files, key=lambda f: f.coverage)) or b"")}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    cov = rdt.contiguous(ks)
    fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(TARGET)
    out = output_path_for(TARGET)
    if not out.exists() or out.stat().st_size != body_end:
        raise RuntimeError("known pair missing")
    missing_offsets = [off for off in range(fei_len - 64, fei_len) if off not in ks]
    if len(missing_offsets) != 6:
        raise RuntimeError(f"expected 6 missing bytes, got {missing_offsets}")
    with TARGET.open("rb") as ef, out.open("rb") as pf:
        enc_head = ef.read(64)
        plain_head = pf.read(64)
    expected = bytes(a ^ b for a, b in zip(enc_head, plain_head))

    fek_start = fei_len - 64
    known_fek = bytearray(64)
    known_mask = bytearray(64)
    for i in range(64):
        off = fek_start + i
        if off in ks:
            known_fek[i] = fei_ct[off] ^ ks[off]
            known_mask[i] = 1

    source = f'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))

{c_array("KNOWN_FEK", bytes(known_fek))}
{c_array("KNOWN_MASK", bytes(known_mask))}
{c_array("EXPECTED", expected)}

static void salsa20_block(const uint8_t key[64], uint8_t out[64]) {{
    uint32_t x[16], z[16];
    for (int i=0;i<16;i++) {{
        x[i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1]<<8) | ((uint32_t)key[i*4+2]<<16) | ((uint32_t)key[i*4+3]<<24);
        z[i] = x[i];
    }}
    for (int i=0;i<10;i++) {{
        z[4] ^= ROTL32(z[0] + z[12], 7); z[8] ^= ROTL32(z[4] + z[0], 9); z[12] ^= ROTL32(z[8] + z[4], 13); z[0] ^= ROTL32(z[12] + z[8], 18);
        z[9] ^= ROTL32(z[5] + z[1], 7); z[13] ^= ROTL32(z[9] + z[5], 9); z[1] ^= ROTL32(z[13] + z[9], 13); z[5] ^= ROTL32(z[1] + z[13], 18);
        z[14] ^= ROTL32(z[10] + z[6], 7); z[2] ^= ROTL32(z[14] + z[10], 9); z[6] ^= ROTL32(z[2] + z[14], 13); z[10] ^= ROTL32(z[6] + z[2], 18);
        z[3] ^= ROTL32(z[15] + z[11], 7); z[7] ^= ROTL32(z[3] + z[15], 9); z[11] ^= ROTL32(z[7] + z[3], 13); z[15] ^= ROTL32(z[11] + z[7], 18);
        z[1] ^= ROTL32(z[0] + z[3], 7); z[2] ^= ROTL32(z[1] + z[0], 9); z[3] ^= ROTL32(z[2] + z[1], 13); z[0] ^= ROTL32(z[3] + z[2], 18);
        z[6] ^= ROTL32(z[5] + z[4], 7); z[7] ^= ROTL32(z[6] + z[5], 9); z[4] ^= ROTL32(z[7] + z[6], 13); z[5] ^= ROTL32(z[4] + z[7], 18);
        z[11] ^= ROTL32(z[10] + z[9], 7); z[8] ^= ROTL32(z[11] + z[10], 9); z[9] ^= ROTL32(z[8] + z[11], 13); z[10] ^= ROTL32(z[9] + z[8], 18);
        z[12] ^= ROTL32(z[15] + z[14], 7); z[13] ^= ROTL32(z[12] + z[15], 9); z[14] ^= ROTL32(z[13] + z[12], 13); z[15] ^= ROTL32(z[14] + z[13], 18);
    }}
    for (int i=0;i<16;i++) {{
        uint32_t v = z[i] + x[i];
        out[i*4] = v & 0xff; out[i*4+1] = (v>>8)&0xff; out[i*4+2] = (v>>16)&0xff; out[i*4+3] = (v>>24)&0xff;
    }}
}}

int main(int argc, char **argv) {{
    uint64_t start = 0;
    uint64_t limit = (argc > 1) ? strtoull(argv[1], NULL, 0) : (1ULL<<32);
    if (argc > 2) start = strtoull(argv[2], NULL, 0);
    uint64_t end = start + limit;
    if (end < start) end = UINT64_MAX;
    volatile int found = 0;
    uint64_t found_guess = 0;
    clock_t t0 = clock();
    fprintf(stderr, "target={c_string(TARGET)}\\n");
    fprintf(stderr, "kek={kek} cov={cov} fei_len={fei_len} missing_offsets={','.join(map(str, missing_offsets))}\\n");
    fprintf(stderr, "range start=%llu limit=%llu\\n", (unsigned long long)start, (unsigned long long)limit);
#ifdef _OPENMP
    fprintf(stderr, "threads=%d\\n", omp_get_max_threads());
#endif
#pragma omp parallel
    {{
        uint8_t fek[64], block[64];
#pragma omp for schedule(static)
        for (int64_t signed_i = 0; signed_i < (int64_t)limit; signed_i++) {{
            uint64_t guess = start + (uint64_t)signed_i;
            if (found) continue;
            memcpy(fek, KNOWN_FEK, 64);
            fek[58] = guess & 0xff;
            fek[59] = (guess >> 8) & 0xff;
            fek[60] = (guess >> 16) & 0xff;
            fek[61] = (guess >> 24) & 0xff;
            fek[62] = (guess >> 32) & 0xff;
            fek[63] = (guess >> 40) & 0xff;
            salsa20_block(fek, block);
            if (*(uint64_t*)block != *(const uint64_t*)EXPECTED) continue;
            if (memcmp(block, EXPECTED, 64) == 0) {{
                found = 1;
                found_guess = guess;
            }}
        }}
    }}
    double sec = (double)(clock() - t0) / CLOCKS_PER_SEC;
    fprintf(stderr, "checked=%llu elapsed=%.3f iter_per_sec=%.0f\\n", (unsigned long long)limit, sec, limit/sec);
    if (found) {{
        printf("FOUND guess=0x%012llx\\n", (unsigned long long)found_guess);
        return 0;
    }}
    printf("NOT_FOUND\\n");
    return 2;
}}
'''
    OUT_C.write_text(source, encoding="utf-8")
    print(f"kek={kek} cov={cov} fei_len={fei_len} missing_offsets={missing_offsets}")
    print(f"wrote={OUT_C}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
