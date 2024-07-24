#pragma once

#include <stdint.h>

#define PQC_CIPHER_ML_KEM 17

#define PQC_ML_KEM_STRENGTH 4

#if PQC_ML_KEM_STRENGTH == 2
#define PQC_ML_KEM_POLYCOMPRESSEDBYTES 128
#define PQC_ML_KEM_POLYVECCOMPRESSEDBYTES (PQC_ML_KEM_STRENGTH * 320)
#elif PQC_ML_KEM_STRENGTH == 3
#define PQC_ML_KEM_POLYCOMPRESSEDBYTES 128
#define PQC_ML_KEM_POLYVECCOMPRESSEDBYTES (PQC_ML_KEM_STRENGTH * 320)
#elif PQC_ML_KEM_STRENGTH == 4
#define PQC_ML_KEM_POLYCOMPRESSEDBYTES 160
#define PQC_ML_KEM_POLYVECCOMPRESSEDBYTES (PQC_ML_KEM_STRENGTH * 352)
#endif

#define PQC_ML_KEM_PUBLIC_KEYLEN (PQC_ML_KEM_STRENGTH * 384 + 32)
#define PQC_ML_KEM_PRIVATE_KEYLEN (PQC_ML_KEM_STRENGTH * 384 * 2 + 96)
#define PQC_ML_KEM_MESSAGE_LENGTH (PQC_ML_KEM_POLYVECCOMPRESSEDBYTES + PQC_ML_KEM_POLYCOMPRESSEDBYTES)
#define PQC_ML_KEM_SHARED_LENGTH 32


typedef struct pqc_ml_kem_private_key
{
    uint8_t private_key[PQC_ML_KEM_PRIVATE_KEYLEN];
} pqc_ml_kem_private_key;

typedef struct pqc_ml_kem_public_key
{
    uint8_t public_key[PQC_ML_KEM_PUBLIC_KEYLEN];
} pqc_ml_kem_public_key;

typedef struct pqc_ml_kem_message
{
    uint8_t message[PQC_ML_KEM_MESSAGE_LENGTH];
} pqc_ml_kem_message;

typedef struct pqc_ml_kem_shared_secret
{
    uint8_t secret[PQC_ML_KEM_SHARED_LENGTH];
} pqc_ml_kem_shared_secret;
