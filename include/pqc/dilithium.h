#pragma once

#include <stdint.h>

#define PQC_CIPHER_DILITHIUM 6

#define DILITHIUM_MODE 5
#define DILITHIUM_RANDOMIZED_SIGNING

#if DILITHIUM_MODE == 2
#define PQC_DILITHIUM_PUBLIC_KEY_LEN 1312
#define PQC_DILITHIUM_PRIVATE_KEY_LEN 2544
#define PQC_DILITHIUM_SIGNATURE_LEN 2420

#elif DILITHIUM_MODE == 3
#define PQC_DILITHIUM_PUBLIC_KEY_LEN 1952
#define PQC_DILITHIUM_PRIVATE_KEY_LEN 4016
#define PQC_DILITHIUM_SIGNATURE_LEN 3293

#elif DILITHIUM_MODE == 5
#define PQC_DILITHIUM_PUBLIC_KEY_LEN 2592
#define PQC_DILITHIUM_PRIVATE_KEY_LEN 4880
#define PQC_DILITHIUM_SIGNATURE_LEN 4595
#endif

typedef struct pqc_dilithium_private_key
{
    uint8_t private_key[PQC_DILITHIUM_PRIVATE_KEY_LEN];
} pqc_dilithium_private_key;

typedef struct pqc_dilithium_public_key
{
    uint8_t public_key[PQC_DILITHIUM_PUBLIC_KEY_LEN];
} pqc_dilithium_public_key;

typedef struct pqc_dilithium_signature
{
    uint8_t signature[PQC_DILITHIUM_SIGNATURE_LEN];
} pqc_dilithium_signature;

typedef struct pqc_dilithium_context
{
    pqc_dilithium_private_key private_key;
} pqc_dilithium_context;
