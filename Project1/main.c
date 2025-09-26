#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "utils.h"
#include "crypto.h"
#include "merkle.h"
#include "sbom.h"

/*
 * 데모 시나리오
 * 1) SBOM 3개 노드 생성 (name/version 중 일부 민감 처리)
 * 2) redact 플래그에 따라 blob 생성 -> AES-GCM 선택적 암호화
 * 3) 각 노드 해시로 머클트리 생성, 루트 출력
 * 4) 특정 노드에 대해 Merkle proof 생성 및 검증
 * 5) 속성 기반 접근(아주 단순 모사): argv[1] 문자열에 'role=auditor'가 있어야 복호화 진행
 */

static void fill_node(sbom_node_t* n, const char* id, const char* name, const char* ver,
    bool r_name, bool r_ver) {
    memset(n, 0, sizeof(*n));
    strncpy(n->id, id, sizeof(n->id) - 1);
    strncpy(n->name, name, sizeof(n->name) - 1);
    strncpy(n->version, ver, sizeof(n->version) - 1);
    n->redact_name = r_name;
    n->redact_version = r_ver;
}

static bool has_auditor_role(const char* attr) {
    return attr && strstr(attr, "role=auditor") != NULL;
}

int main(int argc, char** argv) {
    const char* attr = (argc > 1) ? argv[1] : "role=guest";
    printf("User attributes: %s\n", attr);

    sbom_t sb = { 0 };
    sb.count = 3;
    sb.nodes = xcalloc(sb.count, sizeof(sbom_node_t));

    // 데모 키(랜덤 생성). 실제에선 KMS/ABE를 통해 분배.
    if (!rng_bytes(sb.key, AES_GCM_KEYLEN)) die("rng failed");

    fill_node(&sb.nodes[0], "corelib", "internal-core", "1.2.3", true, false);
    fill_node(&sb.nodes[1], "openssl", "openssl", "3.3.1", false, false);
    fill_node(&sb.nodes[2], "vendorX", "secret-lib", "9.1.0", true, true);

    // 1) pack -> 2) selective encrypt
    for (size_t i = 0; i < sb.count; i++) {
        if (!sbom_node_pack(&sb.nodes[i])) die("pack fail");
        if (!sbom_node_encrypt(&sb.nodes[i], sb.key)) die("encrypt fail");
    }

    // 3) merkle leaves
    uint8_t* leaves = xmalloc(sb.count * 32);
    for (size_t i = 0; i < sb.count; i++) {
        if (!sbom_leaf_hash(&sb.nodes[i], leaves + 32 * i)) die("leaf hash fail");
    }
    merkle_tree_t* tree = merkle_build(leaves, sb.count);
    free(leaves);

    uint8_t root[32];
    if (!merkle_root(tree, root)) die("root fail");
    printf("Merkle Root: "); hex_dump(root, 32);

    // 4) 특정 노드(예: index 0)에 대한 증명
    size_t target = 0;
    merkle_proof_t proof = { 0 };
    if (!merkle_gen_proof(tree, target, &proof)) die("proof gen fail");

    // 검증 쪽에서 leaf 해시 재계산(소비자)
    // 소비자 관점: 복호화 권한이 없어도(=ciphertext 상태) 동일한 leaf 해시가 나와야 함.
    uint8_t leaf0[32];
    if (!sbom_leaf_hash(&sb.nodes[target], leaf0)) die("leaf0 hash fail");
    printf("Leaf[0] hash: "); hex_dump(leaf0, 32);

    bool ok = merkle_verify(leaf0, &proof, root);
    printf("Inclusion proof verify (without decryption): %s\n", ok ? "OK" : "FAIL");

    // 5) 접근 속성으로 복호화 시도(감사자만)
    if (has_auditor_role(attr)) {
        printf("\n[Auditor] Decrypting redacted nodes...\n");
        for (size_t i = 0; i < sb.count; i++) {
            if (!sbom_node_decrypt(&sb.nodes[i], sb.key)) {
                printf("Node %zu decrypt failed (tag mismatch)\n", i);
            }
            else {
                // 복호화 후 내용 보기 위해 pack을 다시 할 필요 없음(이미 PT blob)
            }
        }
        sbom_dump_human(&sb, true);
    }
    else {
        printf("\n[Guest] No decryption allowed. Show redacted SBOM only.\n");
        sbom_dump_human(&sb, false);
    }

    // redacted(암호문 포함) 아티팩트 저장
    if (!sbom_save_redacted("redacted_sbom.bin", &sb)) {
        printf("Save failed\n");
    }
    else {
        printf("Saved: redacted_sbom.bin\n");
    }

    merkle_free_proof(&proof);
    merkle_free(tree);

    // cleanup
    for (size_t i = 0; i < sb.count; i++) free(sb.nodes[i].blob);
    free(sb.nodes);
    return 0;
}
