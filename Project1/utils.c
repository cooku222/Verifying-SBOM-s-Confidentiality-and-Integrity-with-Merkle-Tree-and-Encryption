#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "utils.h"

void hex_dump(const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex_to_bytes(const char* hex, uint8_t* out, size_t outlen) {
    size_t n = strlen(hex);
    if (n % 2 != 0 || outlen * 2 < n) return false;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hexval(hex[i]), lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

void bytes_to_hex(const uint8_t* in, size_t inlen, char* out, size_t outlen) {
    static const char* H = "0123456789abcdef";
    if (outlen < inlen * 2 + 1) return;
    for (size_t i = 0; i < inlen; i++) {
        out[2 * i] = H[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = H[in[i] & 0xF];
    }
    out[inlen * 2] = '\0';
}

void* xmalloc(size_t n) {
    void* p = malloc(n);
    if (!p) die("malloc failed");
    return p;
}

void* xcalloc(size_t n, size_t sz) {
    void* p = calloc(n, sz);
    if (!p) die("calloc failed");
    return p;
}

char* xstrdup(const char* s) {
    size_t n = strlen(s) + 1;
    char* p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}
