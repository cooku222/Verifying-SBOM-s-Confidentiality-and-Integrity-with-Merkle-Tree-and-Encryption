#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "merkle.h"
#include "crypto.h"
#include "utils.h"

// Helper: hash concat of two 32-byte nodes
static bool hash_pair(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    uint8_t buf[64];
    memcpy(buf, a, 32);
    memcpy(buf + 32, b, 32);
    return sha256(buf, sizeof(buf), out);
}

merkle_tree_t* merkle_build(const uint8_t* leaf_hashes, size_t leaf_count) {
    if (leaf_count == 0) return NULL;
    merkle_tree_t* t = xcalloc(1, sizeof(*t));
    t->leaf_count = leaf_count;
    t->leaves = xmalloc(leaf_count * 32);
    memcpy(t->leaves, leaf_hashes, leaf_count * 32);
    return t;
}

void merkle_free(merkle_tree_t* t) {
    if (!t) return;
    free(t->leaves);
    free(t);
}

bool merkle_root(const merkle_tree_t* t, uint8_t out32[32]) {
    if (!t || t->leaf_count == 0) return false;

    size_t cur_n = t->leaf_count;
    uint8_t* cur = xmalloc(cur_n * 32);
    memcpy(cur, t->leaves, cur_n * 32);

    while (cur_n > 1) {
        size_t next_n = (cur_n + 1) / 2;
        uint8_t* next = xmalloc(next_n * 32);
        for (size_t i = 0; i < next_n; i++) {
            size_t i0 = 2 * i;
            size_t i1 = (i0 + 1 < cur_n) ? i0 + 1 : i0; // duplicate last if odd
            if (!hash_pair(cur + i0 * 32, cur + i1 * 32, next + i * 32)) {
                free(cur); free(next); return false;
            }
        }
        free(cur);
        cur = next;
        cur_n = next_n;
    }
    memcpy(out32, cur, 32);
    free(cur);
    return true;
}

bool merkle_gen_proof(const merkle_tree_t* t, size_t leaf_index, merkle_proof_t* out) {
    if (!t || leaf_index >= t->leaf_count || !out) return false;

    // We recompute all levels to collect siblings.
    size_t capacity = 0, path_len = 0;
    uint8_t* siblings = NULL;
    uint8_t* dirs = NULL;

    size_t cur_n = t->leaf_count;
    uint8_t* cur = xmalloc(cur_n * 32);
    memcpy(cur, t->leaves, cur_n * 32);

    size_t idx = leaf_index;

    while (cur_n > 1) {
        size_t next_n = (cur_n + 1) / 2;
        uint8_t* next = xmalloc(next_n * 32);

        // sibling index:
        size_t sib = (idx ^ 1); // toggle last bit
        if (sib >= cur_n) sib = idx; // odd: duplicate self

        // push sibling
        if (path_len + 1 > capacity) {
            capacity = capacity ? capacity * 2 : 4;
            siblings = realloc(siblings, capacity * 32);
            dirs = realloc(dirs, capacity);
            if (!siblings || !dirs) die("realloc failed");
        }
        memcpy(siblings + path_len * 32, cur + sib * 32, 32);
        dirs[path_len] = (idx & 1) ? 1 : 0; // our position: 0=left,1=right
        path_len++;

        // build next level
        for (size_t i = 0; i < next_n; i++) {
            size_t i0 = 2 * i;
            size_t i1 = (i0 + 1 < cur_n) ? i0 + 1 : i0;
            if (!hash_pair(cur + i0 * 32, cur + i1 * 32, next + i * 32)) {
                free(cur); free(next); free(siblings); free(dirs); return false;
            }
        }

        // move to parent index
        idx /= 2;
        free(cur);
        cur = next;
        cur_n = next_n;
    }

    free(cur);
    out->path_len = path_len;
    out->sibling_hashes = siblings;
    out->directions = dirs;
    return true;
}

void merkle_free_proof(merkle_proof_t* p) {
    if (!p) return;
    free(p->sibling_hashes);
    free(p->directions);
    p->path_len = 0;
}

bool merkle_verify(const uint8_t leaf[32], const merkle_proof_t* proof, const uint8_t root[32]) {
    uint8_t cur[32];
    memcpy(cur, leaf, 32);
    for (size_t i = 0; i < proof->path_len; i++) {
        uint8_t next[32];
        const uint8_t* sib = proof->sibling_hashes + i * 32;
        if (proof->directions[i] == 0) {
            // we are left; hash(cur||sib)
            if (!sha256(NULL, 0, next)) {} // placeholder to satisfy style
            uint8_t buf[64];
            memcpy(buf, cur, 32);
            memcpy(buf + 32, sib, 32);
            if (!sha256(buf, sizeof(buf), next)) return false;
            memcpy(cur, next, 32);
        }
        else {
            // we are right; hash(sib||cur)
            uint8_t buf[64];
            memcpy(buf, sib, 32);
            memcpy(buf + 32, cur, 32);
            if (!sha256(buf, sizeof(buf), next)) return false;
            memcpy(cur, next, 32);
        }
    }
    return memcmp(cur, root, 32) == 0;
}
