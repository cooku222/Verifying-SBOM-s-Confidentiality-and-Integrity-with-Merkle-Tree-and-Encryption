#ifndef MERKLE_H
#define MERKLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    size_t leaf_count;
    // level 0 = leaves, then up; flat array of nodes per level can be computed on the fly
    // we store only leaves and the root-building routine recomputes upper levels when needed.
    uint8_t* leaves; // leaf_count * 32 bytes
} merkle_tree_t;

typedef struct {
    size_t path_len;         // number of sibling hashes
    uint8_t* sibling_hashes; // path_len * 32
    uint8_t* directions;     // path_len bytes: 0=left,1=right (sibling position relative to current)
} merkle_proof_t;

merkle_tree_t* merkle_build(const uint8_t* leaf_hashes, size_t leaf_count);
void merkle_free(merkle_tree_t* t);

bool merkle_root(const merkle_tree_t* t, uint8_t out32[32]);
bool merkle_gen_proof(const merkle_tree_t* t, size_t leaf_index, merkle_proof_t* out);
void merkle_free_proof(merkle_proof_t* p);
bool merkle_verify(const uint8_t leaf[32], const merkle_proof_t* proof, const uint8_t root[32]);

#endif
#pragma once
