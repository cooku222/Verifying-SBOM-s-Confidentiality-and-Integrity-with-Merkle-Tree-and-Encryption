#pragma once
#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define die(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); exit(1);} while(0)

void hex_dump(const uint8_t* buf, size_t len);
bool hex_to_bytes(const char* hex, uint8_t* out, size_t outlen);  // returns true on success
void bytes_to_hex(const uint8_t* in, size_t inlen, char* out, size_t outlen); // out needs 2*inlen+1
void* xmalloc(size_t n);
void* xcalloc(size_t n, size_t sz);
char* xstrdup(const char* s);

#endif
