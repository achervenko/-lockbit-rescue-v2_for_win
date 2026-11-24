#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <iconv.h>
#endif

#include "aplib.h"

static int utf8_to_utf16le(const char *utf8_str, uint8_t *out_buf, size_t out_max) {
    char *decoded_hex = NULL;
    if (strncmp(utf8_str, "hex:", 4) == 0) {
        const char *hex = utf8_str + 4;
        size_t hex_len = strlen(hex);
        if ((hex_len % 2) != 0) return -1;
        decoded_hex = (char *)calloc(hex_len / 2 + 1, 1);
        if (!decoded_hex) return -1;
        for (size_t i = 0; i < hex_len / 2; i++) {
            unsigned int v;
            if (sscanf(hex + i * 2, "%2x", &v) != 1) {
                free(decoded_hex);
                return -1;
            }
            decoded_hex[i] = (char)v;
        }
        utf8_str = decoded_hex;
    }

#ifdef _WIN32
    UINT codepage = CP_UTF8;
    int flags = MB_ERR_INVALID_CHARS;
    int input_len = (int)strlen(utf8_str);
    int wchars = MultiByteToWideChar(codepage, flags, utf8_str, input_len, NULL, 0);
    if (wchars <= 0) {
        codepage = CP_ACP;
        flags = 0;
        wchars = MultiByteToWideChar(codepage, flags, utf8_str, input_len, NULL, 0);
    }
    if (wchars <= 0) { free(decoded_hex); return -1; }

    wchar_t *wide = (wchar_t *)calloc((size_t)wchars + 1, sizeof(wchar_t));
    if (!wide) { free(decoded_hex); return -1; }

    int result = MultiByteToWideChar(codepage, flags, utf8_str, input_len, wide, wchars);
    if (result <= 0) { free(wide); free(decoded_hex); return -1; }

    size_t byte_len = (size_t)(wchars * sizeof(wchar_t));
    if (byte_len > out_max) { free(wide); free(decoded_hex); return -1; }
    memcpy(out_buf, wide, byte_len);

    free(wide);
    free(decoded_hex);
    return (int)byte_len;
#else
    iconv_t cd = iconv_open("UTF-16LE", "UTF-8");
    if (cd == (iconv_t)-1) return -1;

    size_t source_len = strlen(utf8_str);
    size_t buffer_size = source_len * 2 + 4;
    if (buffer_size > out_max) { iconv_close(cd); free(decoded_hex); return -1; }

    char *utf16_buffer = (char *)calloc(buffer_size, sizeof(char));
    if (!utf16_buffer) { iconv_close(cd); free(decoded_hex); return -1; }

    char *inbuf = (char *)utf8_str;
    char *outbuf = utf16_buffer;
    size_t inbytesleft = source_len;
    size_t outbytesleft = buffer_size;

    if (iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft) == (size_t)-1) {
        iconv_close(cd);
        free(utf16_buffer);
        free(decoded_hex);
        return -1;
    }
    iconv_close(cd);

    size_t byte_len = buffer_size - outbytesleft;
    memcpy(out_buf, utf16_buffer, byte_len);
    free(utf16_buffer);
    free(decoded_hex);
    return (int)byte_len;
#endif
}

static int compress_filename_utf16le(const char *long_name, uint8_t *output,
                                     int output_max, uint16_t *filename_size,
                                     int workmem_mode) {
    size_t max_conv = strlen(long_name) * 4 + 16;
    uint8_t *utf16_buffer = (uint8_t *)calloc(max_conv, 1);
    if (!utf16_buffer) return -1;

    int conv_len = utf8_to_utf16le(long_name, utf16_buffer, max_conv);
    if (conv_len < 0) { free(utf16_buffer); return -1; }

    int final_len = conv_len + 2;
    if (filename_size) {
        *filename_size = (uint16_t)(final_len - 2);
    }

    unsigned int work_len = workmem_mode ? aP_workmem_size((unsigned int)final_len) : aP_workmem_size(0);
    void *workmem = malloc(work_len);
    if (!workmem) { free(utf16_buffer); return -1; }

    unsigned int sz = aP_pack(utf16_buffer, output, (unsigned int)final_len, workmem, NULL, NULL);
    free(workmem);
    free(utf16_buffer);
    if (sz == APLIB_ERROR || sz > (unsigned int)output_max) return -1;
    return (int)sz;
}

static int print_pack_line(const char *arg, int workmem_mode) {
    uint8_t out[4096];
    uint16_t filename_size = 0;
    int sz = compress_filename_utf16le(arg, out, (int)sizeof(out), &filename_size, workmem_mode);
    if (sz < 0) {
        printf("ERR\t0\t\n");
        return 1;
    }
    printf("OK\t%d\t%u\t", sz, (unsigned int)filename_size);
    for (int i = 0; i < sz; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: aplib_name_pack <hex:utf8-name> [workmem-final]\n");
        fprintf(stderr, "       aplib_name_pack --batch [workmem-final] < names.txt\n");
        return 2;
    }

    if (strcmp(argv[1], "--batch") == 0) {
        int workmem_mode = argc == 3 && strcmp(argv[2], "workmem-final") == 0;
        char line[8192];
        int any_error = 0;
        while (fgets(line, sizeof(line), stdin)) {
            size_t n = strlen(line);
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
                line[--n] = '\0';
            }
            any_error |= print_pack_line(line, workmem_mode);
        }
        return any_error ? 1 : 0;
    }

    int workmem_mode = argc == 3 && strcmp(argv[2], "workmem-final") == 0;
    uint8_t out[4096];
    uint16_t filename_size = 0;
    int sz = compress_filename_utf16le(argv[1], out, (int)sizeof(out), &filename_size, workmem_mode);
    if (sz < 0) {
        fprintf(stderr, "ERROR: pack failed\n");
        return 1;
    }
    printf("SIZE:%d\n", sz);
    printf("FILENAME_SIZE:%u\n", (unsigned int)filename_size);
    printf("HEX:");
    for (int i = 0; i < sz; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
    return 0;
}
