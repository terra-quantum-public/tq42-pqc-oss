#pragma once

#include <stdint.h>

#define PQC_CIPHER_ML_DSA 16

#define PQC_ML_DSA_MODE 87
#define PQC_ML_DSA_RANDOMIZED_SIGNING

#if PQC_ML_DSA_MODE == 44
#define PQC_ML_DSA_PUBLIC_KEY_LEN 1312
#define PQC_ML_DSA_PRIVATE_KEY_LEN 2560
#define PQC_ML_DSA_SIGNATURE_LEN 2420

#elif PQC_ML_DSA_MODE == 65
#define PQC_ML_DSA_PUBLIC_KEY_LEN 1952
#define PQC_ML_DSA_PRIVATE_KEY_LEN 4032
#define PQC_ML_DSA_SIGNATURE_LEN 3309

#elif PQC_ML_DSA_MODE == 87
#define PQC_ML_DSA_PUBLIC_KEY_LEN 2592
#define PQC_ML_DSA_PRIVATE_KEY_LEN 4896
#define PQC_ML_DSA_SIGNATURE_LEN 4627
#endif

struct pqc_ml_dsa_private_key
{
    uint8_t private_key[PQC_ML_DSA_PRIVATE_KEY_LEN];
};

struct pqc_ml_dsa_public_key
{
    uint8_t public_key[PQC_ML_DSA_PUBLIC_KEY_LEN];
};

struct pqc_ml_dsa_signature
{
    uint8_t signature[PQC_ML_DSA_SIGNATURE_LEN];
};

struct pqc_ml_dsa_context
{
    pqc_ml_dsa_private_key private_key;
};
