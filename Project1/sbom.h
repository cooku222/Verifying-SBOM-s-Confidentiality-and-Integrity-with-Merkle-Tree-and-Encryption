
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

    // 민감 플래그: 이름/버전 중 무엇을 가릴지
    bool redact_name;
    bool redact_version;

    // 저장 데이터(암호화 전/후 동일 버퍼 사용)
    uint8_t* blob;       // 직렬화된 필드(payload)
    size_t   blob_len;

    bool     encrypted;
    uint8_t  iv[AES_GCM_IVLEN];
    uint8_t  tag[AES_GCM_TAGLEN];
} sbom_node_t;

typedef struct {
    sbom_node_t* nodes;
    size_t count;

    // 전역 대칭키 (데모에서는 고정; 실제에선 KMS/ABE로 키 배포)
    uint8_t key[AES_GCM_KEYLEN];
} sbom_t;

// 데모용: 필드들을 단순 직렬화해서 blob 생성 (name,version 포함)
bool sbom_node_pack(sbom_node_t* n);
// 선택적 암호화 수행(redact_*가 true인 필드가 포함된 blob 전체를 AES-GCM으로 암호화)
bool sbom_node_encrypt(sbom_node_t* n, const uint8_t key[AES_GCM_KEYLEN]);
// 복호화 시도(권한 없으면 호출 자체를 안 한다고 가정)
bool sbom_node_decrypt(sbom_node_t* n, const uint8_t key[AES_GCM_KEYLEN]);

// 리프 해시 계산: [id || (encrypted? "ENC" : "PT") || blob || iv || tag]
bool sbom_leaf_hash(const sbom_node_t* n, uint8_t out32[32]);

// 간단 직렬화(파일에 저장) / 역직렬화(여기선 데모에서만 저장)
bool sbom_save_redacted(const char* path, const sbom_t* s);
bool sbom_dump_human(const sbom_t* s, bool with_secret);

#endif
#pragma once
