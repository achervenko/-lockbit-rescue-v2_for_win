#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))

#include "private_case.h"






static void salsa20_block(const uint8_t key[64], uint8_t out[64]) {
    uint32_t x[16], z[16];
    for (int i=0;i<16;i++) {
        x[i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1]<<8) | ((uint32_t)key[i*4+2]<<16) | ((uint32_t)key[i*4+3]<<24);
        z[i] = x[i];
    }
    for (int i=0;i<10;i++) {
        z[4] ^= ROTL32(z[0] + z[12], 7); z[8] ^= ROTL32(z[4] + z[0], 9); z[12] ^= ROTL32(z[8] + z[4], 13); z[0] ^= ROTL32(z[12] + z[8], 18);
        z[9] ^= ROTL32(z[5] + z[1], 7); z[13] ^= ROTL32(z[9] + z[5], 9); z[1] ^= ROTL32(z[13] + z[9], 13); z[5] ^= ROTL32(z[1] + z[13], 18);
        z[14] ^= ROTL32(z[10] + z[6], 7); z[2] ^= ROTL32(z[14] + z[10], 9); z[6] ^= ROTL32(z[2] + z[14], 13); z[10] ^= ROTL32(z[6] + z[2], 18);
        z[3] ^= ROTL32(z[15] + z[11], 7); z[7] ^= ROTL32(z[3] + z[15], 9); z[11] ^= ROTL32(z[7] + z[3], 13); z[15] ^= ROTL32(z[11] + z[7], 18);
        z[1] ^= ROTL32(z[0] + z[3], 7); z[2] ^= ROTL32(z[1] + z[0], 9); z[3] ^= ROTL32(z[2] + z[1], 13); z[0] ^= ROTL32(z[3] + z[2], 18);
        z[6] ^= ROTL32(z[5] + z[4], 7); z[7] ^= ROTL32(z[6] + z[5], 9); z[4] ^= ROTL32(z[7] + z[6], 13); z[5] ^= ROTL32(z[4] + z[7], 18);
        z[11] ^= ROTL32(z[10] + z[9], 7); z[8] ^= ROTL32(z[11] + z[10], 9); z[9] ^= ROTL32(z[8] + z[11], 13); z[10] ^= ROTL32(z[9] + z[8], 18);
        z[12] ^= ROTL32(z[15] + z[14], 7); z[13] ^= ROTL32(z[12] + z[15], 9); z[14] ^= ROTL32(z[13] + z[12], 13); z[15] ^= ROTL32(z[14] + z[13], 18);
    }
    for (int i=0;i<16;i++) {
        uint32_t v = z[i] + x[i];
        out[i*4] = v & 0xff; out[i*4+1] = (v>>8)&0xff; out[i*4+2] = (v>>16)&0xff; out[i*4+3] = (v>>24)&0xff;
    }
}

int main(int argc, char **argv) {
    uint64_t start = 0;
    uint64_t limit = (argc > 1) ? strtoull(argv[1], NULL, 0) : (1ULL<<32);
    if (argc > 2) start = strtoull(argv[2], NULL, 0);
    uint64_t end = start + limit;
    if (end < start) end = UINT64_MAX;
    volatile int found = 0;
    uint64_t found_guess = 0;
    clock_t t0 = clock();
    fprintf(stderr, "target=<private case>\n");
    fprintf(stderr, "kek=4f77497c716d cov=108 fei_len=114 missing_offsets=108,109,110,111,112,113\n");
    fprintf(stderr, "range start=%llu limit=%llu\n", (unsigned long long)start, (unsigned long long)limit);
#ifdef _OPENMP
    fprintf(stderr, "threads=%d\n", omp_get_max_threads());
#endif
#pragma omp parallel
    {
        uint8_t fek[64], block[64];
#pragma omp for schedule(static)
        for (int64_t signed_i = 0; signed_i < (int64_t)limit; signed_i++) {
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
            if (memcmp(block, EXPECTED, 64) == 0) {
                found = 1;
                found_guess = guess;
            }
        }
    }
    double sec = (double)(clock() - t0) / CLOCKS_PER_SEC;
    fprintf(stderr, "checked=%llu elapsed=%.3f iter_per_sec=%.0f\n", (unsigned long long)limit, sec, limit/sec);
    if (found) {
        printf("FOUND guess=0x%012llx\n", (unsigned long long)found_guess);
        return 0;
    }
    printf("NOT_FOUND\n");
    return 2;
}
