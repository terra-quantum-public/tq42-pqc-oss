#pragma once

#include <stdint.h>

#include "common.h"

#define PQC_CIPHER_AES 1

// Encryption modes

#define PQC_AES_M_CBC 2
#define PQC_AES_M_ECB 3
#define PQC_AES_M_OFB 4
#define PQC_AES_M_CTR 6

// Fixed for all modes
#define PQC_AES_BLOCKLEN 16 // 128 bits

// Depends on AES modification
#define PQC_AES_KEYLEN 32
#define PQC_AES_IVLEN PQC_AES_BLOCKLEN
#define PQC_AES_keyExpSize 240
#define PQC_AES_CTR_counterIncrement 1

struct pqc_aes_key
{
    uint8_t key[PQC_AES_KEYLEN];
};

struct pqc_aes_iv
{
    uint8_t iv[PQC_AES_IVLEN];
};
