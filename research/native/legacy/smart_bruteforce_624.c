#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define PAIR_COUNT 4
#define BLOCK_COUNT 4
#define UNKNOWN_COUNT 11
#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))

#include "private_case.h"





























static inline void salsa20_block(const uint8_t key[64], uint32_t block_index, uint8_t out[64]) {
    uint32_t x[16], z[16];
    for (int i = 0; i < 16; i++) {
        x[i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) | ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    x[8] += block_index;
    memcpy(z, x, sizeof(x));
    for (int i = 0; i < 10; i++) {
        z[4] ^= ROTL32(z[0] + z[12], 7); z[8] ^= ROTL32(z[4] + z[0], 9); z[12] ^= ROTL32(z[8] + z[4], 13); z[0] ^= ROTL32(z[12] + z[8], 18);
        z[9] ^= ROTL32(z[5] + z[1], 7); z[13] ^= ROTL32(z[9] + z[5], 9); z[1] ^= ROTL32(z[13] + z[9], 13); z[5] ^= ROTL32(z[1] + z[13], 18);
        z[14] ^= ROTL32(z[10] + z[6], 7); z[2] ^= ROTL32(z[14] + z[10], 9); z[6] ^= ROTL32(z[2] + z[14], 13); z[10] ^= ROTL32(z[6] + z[2], 18);
        z[3] ^= ROTL32(z[15] + z[11], 7); z[7] ^= ROTL32(z[3] + z[15], 9); z[11] ^= ROTL32(z[7] + z[3], 13); z[15] ^= ROTL32(z[11] + z[7], 18);
        z[1] ^= ROTL32(z[0] + z[3], 7); z[2] ^= ROTL32(z[1] + z[0], 9); z[3] ^= ROTL32(z[2] + z[1], 13); z[0] ^= ROTL32(z[3] + z[2], 18);
        z[6] ^= ROTL32(z[5] + z[4], 7); z[7] ^= ROTL32(z[6] + z[5], 9); z[4] ^= ROTL32(z[7] + z[6], 13); z[5] ^= ROTL32(z[4] + z[7], 18);
        z[11] ^= ROTL32(z[10] + z[9], 7); z[8] ^= ROTL32(z[11] + z[10], 9); z[9] ^= ROTL32(z[8] + z[11], 13); z[10] ^= ROTL32(z[9] + z[8], 18);
        z[12] ^= ROTL32(z[15] + z[14], 7); z[13] ^= ROTL32(z[12] + z[15], 9); z[14] ^= ROTL32(z[13] + z[12], 13); z[15] ^= ROTL32(z[14] + z[13], 18);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = z[i] + x[i];
        out[i*4+0] = (uint8_t)(v);
        out[i*4+1] = (uint8_t)(v >> 8);
        out[i*4+2] = (uint8_t)(v >> 16);
        out[i*4+3] = (uint8_t)(v >> 24);
    }
}

static inline int check_candidate(const uint8_t ks_tail[UNKNOWN_COUNT]) {
    uint8_t key[64], out[64];
    for (int p = 0; p < PAIR_COUNT; p++) {
        memcpy(key, BASE_FEK[p], 64);
        for (int i = 0; i < UNKNOWN_COUNT; i++) key[53+i] = FEI_TAIL[p][i] ^ ks_tail[i];
        for (int b = 0; b < BLOCK_COUNT; b++) {
            salsa20_block(key, BLOCK_INDEX[b], out);
            if (memcmp(out, EXPECTED[p * BLOCK_COUNT + b], 64) != 0) return 0;
        }
    }
    return 1;
}

static inline int hamming_bytes(const uint8_t *a, const uint8_t *b, int n) {
    int same = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] == b[i]) same++;
    }
    return same;
}

static inline void score_candidate(const uint8_t ks_tail[UNKNOWN_COUNT], int *same_first_block, int *same_all_blocks, int *pass1, int *pass2, int *pass4, int *pass_word0) {
    uint8_t key[64], out[64];
    int total_first = 0, total_all = 0;
    int p1 = 1, p2 = 1, p4 = 1, pw = 1;
    for (int p = 0; p < PAIR_COUNT; p++) {
        memcpy(key, BASE_FEK[p], 64);
        for (int i = 0; i < UNKNOWN_COUNT; i++) key[53+i] = FEI_TAIL[p][i] ^ ks_tail[i];
        for (int b = 0; b < BLOCK_COUNT; b++) {
            salsa20_block(key, BLOCK_INDEX[b], out);
            const uint8_t *exp = EXPECTED[p * BLOCK_COUNT + b];
            int same = hamming_bytes(out, exp, 64);
            total_all += same;
            if (b == 0) total_first += same;
            if (out[0] != exp[0]) p1 = 0;
            if (memcmp(out, exp, 2) != 0) p2 = 0;
            if (memcmp(out, exp, 4) != 0) p4 = 0;
            if (memcmp(out, exp, 4) != 0) pw = 0;
        }
    }
    *same_first_block = total_first;
    *same_all_blocks = total_all;
    *pass1 = p1;
    *pass2 = p2;
    *pass4 = p4;
    *pass_word0 = pw;
}

static int parse_hex_tail(const char *hex, uint8_t out[UNKNOWN_COUNT]) {
    size_t n = strlen(hex);
    if (n != UNKNOWN_COUNT * 2) return 0;
    for (int i = 0; i < UNKNOWN_COUNT; i++) {
        unsigned int v;
        if (sscanf(hex + i*2, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s bench <var_bytes> <limit> [fixed_tail_hex] [start]\n", argv[0]);
        fprintf(stderr, "   or: %s meter <var_bytes> <limit> [fixed_tail_hex] [start]\n", argv[0]);
        fprintf(stderr, "   or: %s check <tail11_hex>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "check") == 0) {
        uint8_t tail[UNKNOWN_COUNT];
        if (argc < 3 || !parse_hex_tail(argv[2], tail)) return 2;
        printf("%s\n", check_candidate(tail) ? "MATCH" : "NO_MATCH");
        return check_candidate(tail) ? 0 : 3;
    }
    if (strcmp(argv[1], "meter") == 0) {
        int var_bytes = argc > 2 ? atoi(argv[2]) : 4;
        uint64_t limit = argc > 3 ? strtoull(argv[3], NULL, 0) : (1ULL << 24);
        uint64_t start = argc > 5 ? strtoull(argv[5], NULL, 0) : 0;
        uint8_t fixed[UNKNOWN_COUNT] = {0};
        if (argc > 4 && strlen(argv[4]) > 0 && strcmp(argv[4], "-") != 0) {
            if (!parse_hex_tail(argv[4], fixed)) return 3;
        }
        uint64_t pass1 = 0, pass2 = 0, pass4 = 0, passw = 0;
        int best_first = -1, best_all = -1;
        uint64_t best_guess_first = 0, best_guess_all = 0;
        clock_t t0 = clock();
        for (uint64_t i = 0; i < limit; i++) {
            uint64_t guess = start + i;
            uint8_t tail[UNKNOWN_COUNT];
            memcpy(tail, fixed, UNKNOWN_COUNT);
            for (int j = 0; j < var_bytes; j++) tail[j] = (uint8_t)(guess >> (8*j));
            int sf = 0, sa = 0, p1 = 0, p2 = 0, p4 = 0, pw = 0;
            score_candidate(tail, &sf, &sa, &p1, &p2, &p4, &pw);
            pass1 += p1; pass2 += p2; pass4 += p4; passw += pw;
            if (sf > best_first) { best_first = sf; best_guess_first = guess; }
            if (sa > best_all) { best_all = sa; best_guess_all = guess; }
        }
        double sec = (double)(clock() - t0) / CLOCKS_PER_SEC;
        printf("METER checked=%llu elapsed=%.3f rate=%.0f/s\n", (unsigned long long)limit, sec, limit/sec);
        printf("PASS first_byte_all_checks=%llu first_2_bytes=%llu first_4_bytes=%llu word0=%llu\n", (unsigned long long)pass1, (unsigned long long)pass2, (unsigned long long)pass4, (unsigned long long)passw);
        printf("BEST first_blocks_same=%d/%d guess=0x%llx all_blocks_same=%d/%d guess=0x%llx\n",
               best_first, PAIR_COUNT * 64, (unsigned long long)best_guess_first,
               best_all, PAIR_COUNT * BLOCK_COUNT * 64, (unsigned long long)best_guess_all);
        return 0;
    }
    if (strcmp(argv[1], "bench") != 0) return 1;
    int var_bytes = argc > 2 ? atoi(argv[2]) : 4;
    uint64_t limit = argc > 3 ? strtoull(argv[3], NULL, 0) : (1ULL << 24);
    uint64_t start = argc > 5 ? strtoull(argv[5], NULL, 0) : 0;
    if (var_bytes < 1 || var_bytes > 8) return 2;
    uint8_t fixed[UNKNOWN_COUNT] = {0};
    if (argc > 4 && strlen(argv[4]) > 0 && strcmp(argv[4], "-") != 0) {
        if (!parse_hex_tail(argv[4], fixed)) return 3;
    }
    volatile int found = 0;
    uint64_t found_guess = 0;
    clock_t t0 = clock();
#pragma omp parallel
    {
        uint8_t tail[UNKNOWN_COUNT];
#pragma omp for schedule(static)
        for (int64_t si = 0; si < (int64_t)limit; si++) {
            uint64_t guess = start + (uint64_t)si;
            memcpy(tail, fixed, UNKNOWN_COUNT);
            for (int j = 0; j < var_bytes; j++) tail[j] = (uint8_t)(guess >> (8*j));
            if (found) continue;
            if (check_candidate(tail)) {
                found = 1;
                found_guess = guess;
            }
        }
    }
    double sec = (double)(clock() - t0) / CLOCKS_PER_SEC;
    fprintf(stderr, "pairs=%d blocks=%d var_bytes=%d checked=%llu elapsed=%.3f rate=%.0f/s\n", PAIR_COUNT, BLOCK_COUNT, var_bytes, (unsigned long long)limit, sec, limit/sec);
    if (found) {
        uint8_t tail[UNKNOWN_COUNT];
        memcpy(tail, fixed, UNKNOWN_COUNT);
        for (int j = 0; j < var_bytes; j++) tail[j] = (uint8_t)(found_guess >> (8*j));
        printf("FOUND guess=0x%llx tail=", (unsigned long long)found_guess);
        for (int i = 0; i < UNKNOWN_COUNT; i++) printf("%02x", tail[i]);
        printf("\n");
        return 0;
    }
    printf("NOT_FOUND\n");
    return 4;
}
