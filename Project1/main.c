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
 * ���� �ó�����
 * 1) SBOM 3�� ��� ���� (name/version �� �Ϻ� �ΰ� ó��)
 * 2) redact �÷��׿� ���� blob ���� -> AES-GCM ������ ��ȣȭ
 * 3) �� ��� �ؽ÷� ��ŬƮ�� ����, ��Ʈ ���
 * 4) Ư�� ��忡 ���� Merkle proof ���� �� ����
 * 5) �Ӽ� ��� ����(���� �ܼ� ���): argv[1] ���ڿ��� 'role=auditor'�� �־�� ��ȣȭ ����
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

    // ���� Ű(���� ����). �������� KMS/ABE�� ���� �й�.
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

    // 4) Ư�� ���(��: index 0)�� ���� ����
    size_t target = 0;
    merkle_proof_t proof = { 0 };
    if (!merkle_gen_proof(tree, target, &proof)) die("proof gen fail");

    // ���� �ʿ��� leaf �ؽ� ����(�Һ���)
    // �Һ��� ����: ��ȣȭ ������ ���(=ciphertext ����) ������ leaf �ؽð� ���;� ��.
    uint8_t leaf0[32];
    if (!sbom_leaf_hash(&sb.nodes[target], leaf0)) die("leaf0 hash fail");
    printf("Leaf[0] hash: "); hex_dump(leaf0, 32);

    bool ok = merkle_verify(leaf0, &proof, root);
    printf("Inclusion proof verify (without decryption): %s\n", ok ? "OK" : "FAIL");

    // 5) ���� �Ӽ����� ��ȣȭ �õ�(�����ڸ�)
    if (has_auditor_role(attr)) {
        printf("\n[Auditor] Decrypting redacted nodes...\n");
        for (size_t i = 0; i < sb.count; i++) {
            if (!sbom_node_decrypt(&sb.nodes[i], sb.key)) {
                printf("Node %zu decrypt failed (tag mismatch)\n", i);
            }
            else {
                // ��ȣȭ �� ���� ���� ���� pack�� �ٽ� �� �ʿ� ����(�̹� PT blob)
            }
        }
        sbom_dump_human(&sb, true);
    }
    else {
        printf("\n[Guest] No decryption allowed. Show redacted SBOM only.\n");
        sbom_dump_human(&sb, false);
    }

    // redacted(��ȣ�� ����) ��Ƽ��Ʈ ����
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
