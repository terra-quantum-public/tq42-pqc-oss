#pragma once

#include <stdint.h>

#define PQC_CIPHER_SLH_DSA_SHAKE_256F 0xCD0C

#define PQC_SLH_DSA_PUBLIC_KEY_LEN 64
#define PQC_SLH_DSA_PRIVATE_KEY_LEN 128
#define PQC_SLH_DSA_SIGNATURE_LEN 49856

typedef struct pqc_slh_dsa_private_key
{
    uint8_t private_key[PQC_SLH_DSA_PRIVATE_KEY_LEN];
} pqc_slh_dsa_private_key;

typedef struct pqc_slh_dsa_public_key
{
    uint8_t public_key[PQC_SLH_DSA_PUBLIC_KEY_LEN];
} pqc_slh_dsa_public_key;

typedef struct pqc_slh_dsa_signature
{
    uint8_t signature[PQC_SLH_DSA_SIGNATURE_LEN];
} pqc_slh_dsa_signature;

typedef struct pqc_slh_dsa_context
{
    pqc_slh_dsa_private_key private_key;
} pqc_slh_dsa_context;
