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
OUT_C = Path(_project_path('research/legacy/gap6_bruteforce_4f_fast.c'))


def output_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def c_words(name: str, words: list[int]) -> str:
    vals = ", ".join(f"0x{w:08x}u" for w in words)
    return f"static const uint32_t {name}[16] = {{{vals}}};\n"


def c_string(text: object) -> str:
    return str(text).encode("unicode_escape").decode("ascii").replace('"', r'\"')


def find_group():
    groups, _, _ = lr.scan_source(
        SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    for kek, files in groups.items():
        for item in files:
            if Path(item.path) == TARGET:
                return kek, files, item
    raise RuntimeError("target not found")


def main() -> int:
    kek, files, item = find_group()
    oracle = max(files, key=lambda f: f.coverage)
    base = rdt.run_dump_ks(oracle)
    if not base:
        raise RuntimeError("cannot dump oracle")
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    cov = rdt.contiguous(ks)

    fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(TARGET)
    out = output_path_for(TARGET)
    if not out.exists() or out.stat().st_size != body_end:
        raise RuntimeError("known pair missing")

    fek_start = fei_len - 64
    missing_offsets = [off for off in range(fek_start, fei_len) if off not in ks]
    if missing_offsets != [108, 109, 110, 111, 112, 113]:
        raise RuntimeError(f"unexpected missing offsets: {missing_offsets}")

    # Build FEK/state words with unknown bytes zeroed. Unknown bytes are:
    # byte 58..63 => state word14 high 16 bits, state word15 all 32 bits.
    state_bytes = bytearray(64)
    for i in range(64):
        off = fek_start + i
        state_bytes[i] = fei_ct[off] ^ ks[off] if off in ks else 0
    state_words = [int.from_bytes(state_bytes[i * 4 : i * 4 + 4], "little") for i in range(16)]

    with TARGET.open("rb") as ef, out.open("rb") as pf:
        expected = bytes(a ^ b for a, b in zip(ef.read(64), pf.read(64)))
    expected_words = [int.from_bytes(expected[i * 4 : i * 4 + 4], "little") for i in range(16)]

    source = f'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))

{c_words("BASE_STATE", state_words)}
{c_words("EXPECTED", expected_words)}

static inline int salsa20_check(uint32_t word14, uint32_t word15) {{
    uint32_t x0=BASE_STATE[0], x1=BASE_STATE[1], x2=BASE_STATE[2], x3=BASE_STATE[3];
    uint32_t x4=BASE_STATE[4], x5=BASE_STATE[5], x6=BASE_STATE[6], x7=BASE_STATE[7];
    uint32_t x8=BASE_STATE[8], x9=BASE_STATE[9], x10=BASE_STATE[10], x11=BASE_STATE[11];
    uint32_t x12=BASE_STATE[12], x13=BASE_STATE[13], x14=word14, x15=word15;
    uint32_t z0=x0,z1=x1,z2=x2,z3=x3,z4=x4,z5=x5,z6=x6,z7=x7,z8=x8,z9=x9,z10=x10,z11=x11,z12=x12,z13=x13,z14=x14,z15=x15;
    for (int i=0;i<10;i++) {{
        z4 ^= ROTL32(z0 + z12, 7); z8 ^= ROTL32(z4 + z0, 9); z12 ^= ROTL32(z8 + z4, 13); z0 ^= ROTL32(z12 + z8, 18);
        z9 ^= ROTL32(z5 + z1, 7); z13 ^= ROTL32(z9 + z5, 9); z1 ^= ROTL32(z13 + z9, 13); z5 ^= ROTL32(z1 + z13, 18);
        z14 ^= ROTL32(z10 + z6, 7); z2 ^= ROTL32(z14 + z10, 9); z6 ^= ROTL32(z2 + z14, 13); z10 ^= ROTL32(z6 + z2, 18);
        z3 ^= ROTL32(z15 + z11, 7); z7 ^= ROTL32(z3 + z15, 9); z11 ^= ROTL32(z7 + z3, 13); z15 ^= ROTL32(z11 + z7, 18);
        z1 ^= ROTL32(z0 + z3, 7); z2 ^= ROTL32(z1 + z0, 9); z3 ^= ROTL32(z2 + z1, 13); z0 ^= ROTL32(z3 + z2, 18);
        z6 ^= ROTL32(z5 + z4, 7); z7 ^= ROTL32(z6 + z5, 9); z4 ^= ROTL32(z7 + z6, 13); z5 ^= ROTL32(z4 + z7, 18);
        z11 ^= ROTL32(z10 + z9, 7); z8 ^= ROTL32(z11 + z10, 9); z9 ^= ROTL32(z8 + z11, 13); z10 ^= ROTL32(z9 + z8, 18);
        z12 ^= ROTL32(z15 + z14, 7); z13 ^= ROTL32(z12 + z15, 9); z14 ^= ROTL32(z13 + z12, 13); z15 ^= ROTL32(z14 + z13, 18);
    }}
    if ((z0 + x0) != EXPECTED[0]) return 0;
    if ((z1 + x1) != EXPECTED[1]) return 0;
    if ((z2 + x2) != EXPECTED[2]) return 0;
    if ((z3 + x3) != EXPECTED[3]) return 0;
    if ((z4 + x4) != EXPECTED[4]) return 0;
    if ((z5 + x5) != EXPECTED[5]) return 0;
    if ((z6 + x6) != EXPECTED[6]) return 0;
    if ((z7 + x7) != EXPECTED[7]) return 0;
    if ((z8 + x8) != EXPECTED[8]) return 0;
    if ((z9 + x9) != EXPECTED[9]) return 0;
    if ((z10 + x10) != EXPECTED[10]) return 0;
    if ((z11 + x11) != EXPECTED[11]) return 0;
    if ((z12 + x12) != EXPECTED[12]) return 0;
    if ((z13 + x13) != EXPECTED[13]) return 0;
    if ((z14 + x14) != EXPECTED[14]) return 0;
    if ((z15 + x15) != EXPECTED[15]) return 0;
    return 1;
}}

int main(int argc, char **argv) {{
    uint64_t limit = (argc > 1) ? strtoull(argv[1], NULL, 0) : (1ULL << 32);
    uint64_t start = (argc > 2) ? strtoull(argv[2], NULL, 0) : 0;
    uint64_t report_every = (argc > 3) ? strtoull(argv[3], NULL, 0) : 0;
    uint32_t base14 = BASE_STATE[14] & 0x0000ffffu;
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
#pragma omp for schedule(static)
        for (int64_t signed_i = 0; signed_i < (int64_t)limit; signed_i++) {{
            uint64_t guess = start + (uint64_t)signed_i;
            if (found) continue;
            uint32_t word14 = base14 | ((uint32_t)(guess & 0xffffu) << 16);
            uint32_t word15 = (uint32_t)(guess >> 16);
            if (salsa20_check(word14, word15)) {{
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
    print(f"base_state14=0x{state_words[14]:08x} base_state15=0x{state_words[15]:08x}")
    print(f"wrote={OUT_C}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
