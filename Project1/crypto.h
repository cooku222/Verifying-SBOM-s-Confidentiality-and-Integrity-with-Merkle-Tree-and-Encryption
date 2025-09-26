#pragma once
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define AES_GCM_KEYLEN 32
#define AES_GCM_IVLEN  12
#define AES_GCM_TAGLEN 16

bool rng_bytes(uint8_t* out, size_t len);
bool sha256(const uint8_t* data, size_t len, uint8_t out32[32]);

bool aes_gcm_encrypt(const uint8_t key[AES_GCM_KEYLEN],
    const uint8_t iv[AES_GCM_IVLEN],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t tag[AES_GCM_TAGLEN]);

bool aes_gcm_decrypt(const uint8_t key[AES_GCM_KEYLEN],
    const uint8_t iv[AES_GCM_IVLEN],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[AES_GCM_TAGLEN],
    uint8_t* pt);

#endif
