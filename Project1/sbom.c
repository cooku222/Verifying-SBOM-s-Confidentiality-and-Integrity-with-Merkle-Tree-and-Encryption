#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "sbom.h"
#include "utils.h"

static void pack_fields(const sbom_node_t* n, const char* name_in, const char* ver_in,
    uint8_t** out, size_t* outlen) {
    // 단순한 TLV 유사 포맷: "name=<...>\nversion=<...>\n"
    const char* name = name_in ? name_in : "";
    const char* ver = ver_in ? ver_in : "";
    size_t ln = strlen(name), lv = strlen(ver);
    size_t total = 6 + ln + 9 + lv + 2; // "name=" + name + "\nversion=" + ver + "\n"
    uint8_t* buf = xmalloc(total);
    int off = snprintf((char*)buf, total, "name=%s\nversion=%s\n", name, ver);
    (void)off;
    *out = buf; *outlen = total - 1; // exclude null terminator for hashing/enc
}

bool sbom_node_pack(sbom_node_t* n) {
    if (!n) return false;
    // redaction: 실제 암호화 여부는 encrypt 단계에서 결정.
    const char* name = n->redact_name ? "[REDACTED]" : n->name;
    const char* ver = n->redact_version ? "[REDACTED]" : n->version;
    uint8_t* buf = NULL; size_t blen = 0;
    pack_fields(n, name, ver, &buf, &blen);
    if (n->blob) free(n->blob);
    n->blob = buf; n->blob_len = blen;
    return true;
}

bool sbom_node_encrypt(sbom_node_t* n, const uint8_t key[AES_GCM_KEYLEN]) {
    if (!n) return false;
    if (!n->redact_name && !n->redact_version) {
        n->encrypted = false;
        return true; // nothing to encrypt
    }
    if (!rng_bytes(n->iv, AES_GCM_IVLEN)) return false;
    uint8_t* ct = xmalloc(n->blob_len);
    // AAD: id 고정
    if (!aes_gcm_encrypt(key, n->iv, (const uint8_t*)n->id, strlen(n->id),
        n->blob, n->blob_len, ct, n->tag)) {
        free(ct); return false;
    }
    free(n->blob);
    n->blob = ct;
    n->encrypted = true;
    return true;
}

bool sbom_node_decrypt(sbom_node_t* n, const uint8_t key[AES_GCM_KEYLEN]) {
    if (!n || !n->encrypted) return true; // nothing
    uint8_t* pt = xmalloc(n->blob_len);
    if (!aes_gcm_decrypt(key, n->iv, (const uint8_t*)n->id, strlen(n->id),
        n->blob, n->blob_len, n->tag, pt)) {
        free(pt); return false;
    }
    free(n->blob);
    n->blob = pt;
    n->encrypted = false;
    return true;
}

bool sbom_leaf_hash(const sbom_node_t* n, uint8_t out32[32]) {
    // H( id || mode || blob || iv || tag )
    size_t idlen = strlen(n->id);
    const char* mode = n->encrypted ? "ENC" : "PT";
    size_t mlen = 3;

    size_t total = idlen + mlen + n->blob_len + AES_GCM_IVLEN + AES_GCM_TAGLEN;
    uint8_t* buf = xmalloc(total);
    size_t off = 0;
    memcpy(buf + off, n->id, idlen); off += idlen;
    memcpy(buf + off, mode, mlen); off += mlen;
    memcpy(buf + off, n->blob, n->blob_len); off += n->blob_len;
    memcpy(buf + off, n->iv, AES_GCM_IVLEN); off += AES_GCM_IVLEN;
    memcpy(buf + off, n->tag, AES_GCM_TAGLEN); off += AES_GCM_TAGLEN;

    bool ok = sha256(buf, total, out32);
    free(buf);
    return ok;
}

bool sbom_save_redacted(const char* path, const sbom_t* s) {
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    // 아주 단순한 바이너리 덤프(데모 목적)
    // [count][per node: id(64) name_flag version_flag encrypted iv tag blob_len blob]
    fwrite(&s->count, sizeof(size_t), 1, f);
    for (size_t i = 0; i < s->count; i++) {
        const sbom_node_t* n = &s->nodes[i];
        char idbuf[64] = { 0 };
        strncpy(idbuf, n->id, 63);
        fwrite(idbuf, 64, 1, f);

        uint8_t flags = (n->redact_name ? 1 : 0) | (n->redact_version ? 2 : 0) | (n->encrypted ? 4 : 0);
        fwrite(&flags, 1, 1, f);
        fwrite(n->iv, AES_GCM_IVLEN, 1, f);
        fwrite(n->tag, AES_GCM_TAGLEN, 1, f);
        fwrite(&n->blob_len, sizeof(size_t), 1, f);
        fwrite(n->blob, n->blob_len, 1, f);
    }
    fclose(f);
    return true;
}

bool sbom_dump_human(const sbom_t* s, bool with_secret) {
    printf("==== SBOM DUMP (with_secret=%s) ====\n", with_secret ? "yes" : "no");
    for (size_t i = 0; i < s->count; i++) {
        const sbom_node_t* n = &s->nodes[i];
        printf("[%zu] id=%s enc=%d flags(name=%d,ver=%d)\n",
            i, n->id, n->encrypted, n->redact_name, n->redact_version);
        printf("    IV: "); hex_dump(n->iv, AES_GCM_IVLEN);
        printf("    TAG: "); hex_dump(n->tag, AES_GCM_TAGLEN);
        if (!n->encrypted || with_secret) {
            // blob 내부 그대로 출력
            fwrite(n->blob, 1, n->blob_len, stdout);
            printf("\n");
        }
        else {
            printf("    (ciphertext %zu bytes)\n", n->blob_len);
        }
    }
    return true;
}
