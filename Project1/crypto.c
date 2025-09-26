#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "crypto.h"

bool rng_bytes(uint8_t* out, size_t len) {
    return RAND_bytes(out, (int)len) == 1;
}

bool sha256(const uint8_t* data, size_t len, uint8_t out32[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto end;
    if (EVP_DigestUpdate(ctx, data, len) != 1) goto end;
    unsigned int outlen = 0;
    if (EVP_DigestFinal_ex(ctx, out32, &outlen) != 1 || outlen != 32) goto end;
    ok = true;
end:
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool aes_gcm_encrypt(const uint8_t key[AES_GCM_KEYLEN],
    const uint8_t iv[AES_GCM_IVLEN],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t tag[AES_GCM_TAGLEN]) {
    bool ok = false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IVLEN, NULL) != 1) goto end;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto end;

    int len;
    if (aad && aad_len) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto end;
    }
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto end;
    int ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &len) != 1) goto end;
    ct_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAGLEN, tag) != 1) goto end;

    ok = true;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aes_gcm_decrypt(const uint8_t key[AES_GCM_KEYLEN],
    const uint8_t iv[AES_GCM_IVLEN],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[AES_GCM_TAGLEN],
    uint8_t* pt) {
    bool ok = false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IVLEN, NULL) != 1) goto end;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto end;

    int len;
    if (aad && aad_len) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto end;
    }
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) goto end;
    int pt_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAGLEN, (void*)tag) != 1) goto end;
    if (EVP_DecryptFinal_ex(ctx, pt + pt_len, &len) != 1) goto end;

    ok = true;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
