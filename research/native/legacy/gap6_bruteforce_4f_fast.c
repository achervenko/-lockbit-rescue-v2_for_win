#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))

#include "private_case.h"




static inline int salsa20_check(uint32_t word14, uint32_t word15) {
    uint32_t x0=BASE_STATE[0], x1=BASE_STATE[1], x2=BASE_STATE[2], x3=BASE_STATE[3];
    uint32_t x4=BASE_STATE[4], x5=BASE_STATE[5], x6=BASE_STATE[6], x7=BASE_STATE[7];
    uint32_t x8=BASE_STATE[8], x9=BASE_STATE[9], x10=BASE_STATE[10], x11=BASE_STATE[11];
    uint32_t x12=BASE_STATE[12], x13=BASE_STATE[13], x14=word14, x15=word15;
    uint32_t z0=x0,z1=x1,z2=x2,z3=x3,z4=x4,z5=x5,z6=x6,z7=x7,z8=x8,z9=x9,z10=x10,z11=x11,z12=x12,z13=x13,z14=x14,z15=x15;
    for (int i=0;i<10;i++) {
        z4 ^= ROTL32(z0 + z12, 7); z8 ^= ROTL32(z4 + z0, 9); z12 ^= ROTL32(z8 + z4, 13); z0 ^= ROTL32(z12 + z8, 18);
        z9 ^= ROTL32(z5 + z1, 7); z13 ^= ROTL32(z9 + z5, 9); z1 ^= ROTL32(z13 + z9, 13); z5 ^= ROTL32(z1 + z13, 18);
        z14 ^= ROTL32(z10 + z6, 7); z2 ^= ROTL32(z14 + z10, 9); z6 ^= ROTL32(z2 + z14, 13); z10 ^= ROTL32(z6 + z2, 18);
        z3 ^= ROTL32(z15 + z11, 7); z7 ^= ROTL32(z3 + z15, 9); z11 ^= ROTL32(z7 + z3, 13); z15 ^= ROTL32(z11 + z7, 18);
        z1 ^= ROTL32(z0 + z3, 7); z2 ^= ROTL32(z1 + z0, 9); z3 ^= ROTL32(z2 + z1, 13); z0 ^= ROTL32(z3 + z2, 18);
        z6 ^= ROTL32(z5 + z4, 7); z7 ^= ROTL32(z6 + z5, 9); z4 ^= ROTL32(z7 + z6, 13); z5 ^= ROTL32(z4 + z7, 18);
        z11 ^= ROTL32(z10 + z9, 7); z8 ^= ROTL32(z11 + z10, 9); z9 ^= ROTL32(z8 + z11, 13); z10 ^= ROTL32(z9 + z8, 18);
        z12 ^= ROTL32(z15 + z14, 7); z13 ^= ROTL32(z12 + z15, 9); z14 ^= ROTL32(z13 + z12, 13); z15 ^= ROTL32(z14 + z13, 18);
    }
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
}

int main(int argc, char **argv) {
    uint64_t limit = (argc > 1) ? strtoull(argv[1], NULL, 0) : (1ULL << 32);
    uint64_t start = (argc > 2) ? strtoull(argv[2], NULL, 0) : 0;
    uint64_t report_every = (argc > 3) ? strtoull(argv[3], NULL, 0) : 0;
    uint32_t base14 = BASE_STATE[14] & 0x0000ffffu;
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
#pragma omp for schedule(static)
        for (int64_t signed_i = 0; signed_i < (int64_t)limit; signed_i++) {
            uint64_t guess = start + (uint64_t)signed_i;
            if (found) continue;
            uint32_t word14 = base14 | ((uint32_t)(guess & 0xffffu) << 16);
            uint32_t word15 = (uint32_t)(guess >> 16);
            if (salsa20_check(word14, word15)) {
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
