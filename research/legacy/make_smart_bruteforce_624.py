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
import subprocess
import sys
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
WORK = Path(_project_path('research/legacy'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"
KEK = _case_value('4906e8c091d91acf1ae1')
TARGET_NAMES = [
    _case_value('ead1978dcb73daa78266'),
    _case_value('ca4654a354defcfd2811'),
    _case_value('48790c62a64487ceaf58'),
    _case_value('5c07ea283dc6dabd8389'),
]
BLOCKS = [0, 1, 2, 3]


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def c_u8_array(name: str, data: bytes) -> str:
    vals = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const uint8_t {name}[{len(data)}] = {{{vals}}};"


def c_str_array(name: str, values: list[str]) -> str:
    vals = ", ".join('"' + v.encode("unicode_escape").decode("ascii").replace('"', r'\"') + '"' for v in values)
    return f"static const char *{name}[PAIR_COUNT] = {{{vals}}};"


def main() -> int:
    groups, _, _ = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = {item.original_name: item for item in groups[KEK]}
    pair_names: list[str] = []
    base_feks: list[bytes] = []
    fei_tails: list[bytes] = []
    expected_blocks: list[bytes] = []

    for name in TARGET_NAMES:
        item = files[name]
        enc = Path(item.path)
        out = output_path_for(item)
        fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
        if out.stat().st_size != body_end:
            raise RuntimeError(f"pair size mismatch: {name}")
        start = fei_len - 64
        if fei_len != 117 or start != 53:
            raise RuntimeError(f"unexpected FEI layout: {name} fei_len={fei_len}")
        # Known FEK bytes 0..52 are covered by seed coverage 106. Unknown FEK
        # bytes 53..63 are fei_ct[106..116] xor guessed FEI keystream.
        base = bytearray(64)
        for pos in range(53):
            off = start + pos
            # recover_desktop_tree seed knows offsets 0..105 contiguously.
            # Rebuild via dump/metadata so this generator is self-contained.
            pass
        pair_names.append(name)
        # Build current group keystream once outside the loop.

    oracle = max(groups[KEK], key=lambda f: f.coverage)
    base_ks = rdt.run_dump_ks(oracle)
    if not base_ks:
        raise RuntimeError("cannot dump base ks")
    ks = {i: b for i, b in enumerate(base_ks)}
    rdt.learn_name_len_metadata(ks, groups[KEK])
    rdt.learn_stable_metadata_profiles(ks, groups[KEK])
    if rdt.contiguous(ks) != 106:
        raise RuntimeError(f"unexpected coverage {rdt.contiguous(ks)}")

    pair_names.clear()
    for name in TARGET_NAMES:
        item = files[name]
        enc = Path(item.path)
        out = output_path_for(item)
        fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
        start = fei_len - 64
        base = bytearray(64)
        for pos in range(53):
            off = start + pos
            base[pos] = fei_ct[off] ^ ks[off]
        pair_names.append(name)
        base_feks.append(bytes(base))
        fei_tails.append(bytes(fei_ct[106:117]))

        enc_body = enc.read_bytes()[:body_end]
        plain_body = out.read_bytes()
        stream = bytes(a ^ b for a, b in zip(enc_body, plain_body))
        for block in BLOCKS:
            expected_blocks.append(stream[block * 64 : block * 64 + 64])

    arrays = []
    for idx, data in enumerate(base_feks):
        arrays.append(c_u8_array(f"BASE_FEK_{idx}", data))
    for idx, data in enumerate(fei_tails):
        arrays.append(c_u8_array(f"FEI_TAIL_{idx}", data))
    for idx, data in enumerate(expected_blocks):
        arrays.append(c_u8_array(f"EXPECTED_{idx}", data))
    base_ptrs = ", ".join(f"BASE_FEK_{i}" for i in range(len(base_feks)))
    tail_ptrs = ", ".join(f"FEI_TAIL_{i}" for i in range(len(fei_tails)))
    exp_ptrs = ", ".join(f"EXPECTED_{i}" for i in range(len(expected_blocks)))
    block_vals = ", ".join(str(v) for v in BLOCKS)

    source = f'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define PAIR_COUNT {len(TARGET_NAMES)}
#define BLOCK_COUNT {len(BLOCKS)}
#define UNKNOWN_COUNT 11
#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))

{chr(10).join(arrays)}
static const uint8_t *BASE_FEK[PAIR_COUNT] = {{{base_ptrs}}};
static const uint8_t *FEI_TAIL[PAIR_COUNT] = {{{tail_ptrs}}};
static const uint8_t *EXPECTED[PAIR_COUNT * BLOCK_COUNT] = {{{exp_ptrs}}};
static const uint32_t BLOCK_INDEX[BLOCK_COUNT] = {{{block_vals}}};
{c_str_array("PAIR_NAME", pair_names)}

static inline void salsa20_block(const uint8_t key[64], uint32_t block_index, uint8_t out[64]) {{
    uint32_t x[16], z[16];
    for (int i = 0; i < 16; i++) {{
        x[i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) | ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }}
    x[8] += block_index;
    memcpy(z, x, sizeof(x));
    for (int i = 0; i < 10; i++) {{
        z[4] ^= ROTL32(z[0] + z[12], 7); z[8] ^= ROTL32(z[4] + z[0], 9); z[12] ^= ROTL32(z[8] + z[4], 13); z[0] ^= ROTL32(z[12] + z[8], 18);
        z[9] ^= ROTL32(z[5] + z[1], 7); z[13] ^= ROTL32(z[9] + z[5], 9); z[1] ^= ROTL32(z[13] + z[9], 13); z[5] ^= ROTL32(z[1] + z[13], 18);
        z[14] ^= ROTL32(z[10] + z[6], 7); z[2] ^= ROTL32(z[14] + z[10], 9); z[6] ^= ROTL32(z[2] + z[14], 13); z[10] ^= ROTL32(z[6] + z[2], 18);
        z[3] ^= ROTL32(z[15] + z[11], 7); z[7] ^= ROTL32(z[3] + z[15], 9); z[11] ^= ROTL32(z[7] + z[3], 13); z[15] ^= ROTL32(z[11] + z[7], 18);
        z[1] ^= ROTL32(z[0] + z[3], 7); z[2] ^= ROTL32(z[1] + z[0], 9); z[3] ^= ROTL32(z[2] + z[1], 13); z[0] ^= ROTL32(z[3] + z[2], 18);
        z[6] ^= ROTL32(z[5] + z[4], 7); z[7] ^= ROTL32(z[6] + z[5], 9); z[4] ^= ROTL32(z[7] + z[6], 13); z[5] ^= ROTL32(z[4] + z[7], 18);
        z[11] ^= ROTL32(z[10] + z[9], 7); z[8] ^= ROTL32(z[11] + z[10], 9); z[9] ^= ROTL32(z[8] + z[11], 13); z[10] ^= ROTL32(z[9] + z[8], 18);
        z[12] ^= ROTL32(z[15] + z[14], 7); z[13] ^= ROTL32(z[12] + z[15], 9); z[14] ^= ROTL32(z[13] + z[12], 13); z[15] ^= ROTL32(z[14] + z[13], 18);
    }}
    for (int i = 0; i < 16; i++) {{
        uint32_t v = z[i] + x[i];
        out[i*4+0] = (uint8_t)(v);
        out[i*4+1] = (uint8_t)(v >> 8);
        out[i*4+2] = (uint8_t)(v >> 16);
        out[i*4+3] = (uint8_t)(v >> 24);
    }}
}}

static inline int check_candidate(const uint8_t ks_tail[UNKNOWN_COUNT]) {{
    uint8_t key[64], out[64];
    for (int p = 0; p < PAIR_COUNT; p++) {{
        memcpy(key, BASE_FEK[p], 64);
        for (int i = 0; i < UNKNOWN_COUNT; i++) key[53+i] = FEI_TAIL[p][i] ^ ks_tail[i];
        for (int b = 0; b < BLOCK_COUNT; b++) {{
            salsa20_block(key, BLOCK_INDEX[b], out);
            if (memcmp(out, EXPECTED[p * BLOCK_COUNT + b], 64) != 0) return 0;
        }}
    }}
    return 1;
}}

static int parse_hex_tail(const char *hex, uint8_t out[UNKNOWN_COUNT]) {{
    size_t n = strlen(hex);
    if (n != UNKNOWN_COUNT * 2) return 0;
    for (int i = 0; i < UNKNOWN_COUNT; i++) {{
        unsigned int v;
        if (sscanf(hex + i*2, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }}
    return 1;
}}

int main(int argc, char **argv) {{
    if (argc < 2) {{
        fprintf(stderr, "usage: %s bench <var_bytes> <limit> [fixed_tail_hex] [start]\\n", argv[0]);
        fprintf(stderr, "   or: %s check <tail11_hex>\\n", argv[0]);
        return 1;
    }}
    if (strcmp(argv[1], "check") == 0) {{
        uint8_t tail[UNKNOWN_COUNT];
        if (argc < 3 || !parse_hex_tail(argv[2], tail)) return 2;
        printf("%s\\n", check_candidate(tail) ? "MATCH" : "NO_MATCH");
        return check_candidate(tail) ? 0 : 3;
    }}
    if (strcmp(argv[1], "bench") != 0) return 1;
    int var_bytes = argc > 2 ? atoi(argv[2]) : 4;
    uint64_t limit = argc > 3 ? strtoull(argv[3], NULL, 0) : (1ULL << 24);
    uint64_t start = argc > 5 ? strtoull(argv[5], NULL, 0) : 0;
    if (var_bytes < 1 || var_bytes > 8) return 2;
    uint8_t fixed[UNKNOWN_COUNT] = {{0}};
    if (argc > 4 && strlen(argv[4]) > 0 && strcmp(argv[4], "-") != 0) {{
        if (!parse_hex_tail(argv[4], fixed)) return 3;
    }}
    volatile int found = 0;
    uint64_t found_guess = 0;
    clock_t t0 = clock();
#pragma omp parallel
    {{
        uint8_t tail[UNKNOWN_COUNT];
#pragma omp for schedule(static)
        for (int64_t si = 0; si < (int64_t)limit; si++) {{
            uint64_t guess = start + (uint64_t)si;
            memcpy(tail, fixed, UNKNOWN_COUNT);
            for (int j = 0; j < var_bytes; j++) tail[j] = (uint8_t)(guess >> (8*j));
            if (found) continue;
            if (check_candidate(tail)) {{
                found = 1;
                found_guess = guess;
            }}
        }}
    }}
    double sec = (double)(clock() - t0) / CLOCKS_PER_SEC;
    fprintf(stderr, "pairs=%d blocks=%d var_bytes=%d checked=%llu elapsed=%.3f rate=%.0f/s\\n", PAIR_COUNT, BLOCK_COUNT, var_bytes, (unsigned long long)limit, sec, limit/sec);
    if (found) {{
        uint8_t tail[UNKNOWN_COUNT];
        memcpy(tail, fixed, UNKNOWN_COUNT);
        for (int j = 0; j < var_bytes; j++) tail[j] = (uint8_t)(found_guess >> (8*j));
        printf("FOUND guess=0x%llx tail=", (unsigned long long)found_guess);
        for (int i = 0; i < UNKNOWN_COUNT; i++) printf("%02x", tail[i]);
        printf("\\n");
        return 0;
    }}
    printf("NOT_FOUND\\n");
    return 4;
}}
'''
    c_path = WORK / "smart_bruteforce_624.c"
    exe_path = WORK / "smart_bruteforce_624.exe"
    c_path.write_text(source, encoding="utf-8")
    cmd = ["gcc", "-O3", "-fopenmp", "-march=native", str(c_path), "-o", str(exe_path)]
    subprocess.run(cmd, check=True)
    print(c_path)
    print(exe_path)
    print("pairs:", ", ".join(pair_names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
