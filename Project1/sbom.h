
#ifndef SBOM_H
#define SBOM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "crypto.h"

typedef struct {
    char id[64];
    char name[128];
    char version[64];

    // �ΰ� �÷���: �̸�/���� �� ������ ������
    bool redact_name;
    bool redact_version;

    // ���� ������(��ȣȭ ��/�� ���� ���� ���)
    uint8_t* blob;       // ����ȭ�� �ʵ�(payload)
    size_t   blob_len;

    bool     encrypted;
    uint8_t  iv[AES_GCM_IVLEN];
    uint8_t  tag[AES_GCM_TAGLEN];
} sbom_node_t;

typedef struct {
    sbom_node_t* nodes;
    size_t count;

    // ���� ��ĪŰ (���𿡼��� ����; �������� KMS/ABE�� Ű ����)
    uint8_t key[AES_GCM_KEYLEN];
} sbom_t;

// �����: �ʵ���� �ܼ� ����ȭ�ؼ� blob ���� (name,version ����)
bool sbom_node_pack(sbom_node_t* n);
// ������ ��ȣȭ ����(redact_*�� true�� �ʵ尡 ���Ե� blob ��ü�� AES-GCM���� ��ȣȭ)
bool sbom_node_encrypt(sbom_node_t* n, const uint8_t key[AES_GCM_KEYLEN]);
// ��ȣȭ �õ�(���� ������ ȣ�� ��ü�� �� �Ѵٰ� ����)
bool sbom_node_decrypt(sbom_node_t* n, const uint8_t key[AES_GCM_KEYLEN]);

// ���� �ؽ� ���: [id || (encrypted? "ENC" : "PT") || blob || iv || tag]
bool sbom_leaf_hash(const sbom_node_t* n, uint8_t out32[32]);

// ���� ����ȭ(���Ͽ� ����) / ������ȭ(���⼱ ���𿡼��� ����)
bool sbom_save_redacted(const char* path, const sbom_t* s);
bool sbom_dump_human(const sbom_t* s, bool with_secret);

#endif
#pragma once
