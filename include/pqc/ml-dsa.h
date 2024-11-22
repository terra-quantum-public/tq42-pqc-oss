#pragma once

#include <stdint.h>

#define PQC_CIPHER_ML_DSA_87 1687
#define PQC_CIPHER_ML_DSA_65 1665
#define PQC_CIPHER_ML_DSA_44 1644

#define PQC_ML_DSA_RANDOMIZED_SIGNING

#define PQC_ML_DSA_PUBLIC_KEY_LEN_87 2592
#define PQC_ML_DSA_PRIVATE_KEY_LEN_87 4896
#define PQC_ML_DSA_SIGNATURE_LEN_87 4627


typedef struct pqc_ml_dsa_private_key_87
{
    uint8_t private_key[PQC_ML_DSA_PRIVATE_KEY_LEN_87];
} pqc_ml_dsa_private_key_87;

typedef struct pqc_ml_dsa_public_key_87
{
    uint8_t public_key[PQC_ML_DSA_PUBLIC_KEY_LEN_87];
} pqc_ml_dsa_public_key_87;

typedef struct pqc_ml_dsa_signature_87
{
    uint8_t signature[PQC_ML_DSA_SIGNATURE_LEN_87];
} pqc_ml_dsa_signature_87;

typedef struct pqc_ml_dsa_context_87
{
    pqc_ml_dsa_private_key_87 private_key;
} pqc_ml_dsa_context_87;

#define PQC_ML_DSA_PUBLIC_KEY_LEN_65 1952
#define PQC_ML_DSA_PRIVATE_KEY_LEN_65 4032
#define PQC_ML_DSA_SIGNATURE_LEN_65 3309

typedef struct pqc_ml_dsa_private_key_65
{
    uint8_t private_key[PQC_ML_DSA_PRIVATE_KEY_LEN_65];
} pqc_ml_dsa_private_key_65;

typedef struct pqc_ml_dsa_public_key_65
{
    uint8_t public_key[PQC_ML_DSA_PUBLIC_KEY_LEN_65];
} pqc_ml_dsa_public_key_65;

typedef struct pqc_ml_dsa_signature_65
{
    uint8_t signature[PQC_ML_DSA_SIGNATURE_LEN_65];
} pqc_ml_dsa_signature_65;

typedef struct pqc_ml_dsa_context_65
{
    pqc_ml_dsa_private_key_65 private_key;
} pqc_ml_dsa_context_65;


#define PQC_ML_DSA_PUBLIC_KEY_LEN_44 1312
#define PQC_ML_DSA_PRIVATE_KEY_LEN_44 2560
#define PQC_ML_DSA_SIGNATURE_LEN_44 2420

typedef struct pqc_ml_dsa_private_key_44
{
    uint8_t private_key[PQC_ML_DSA_PRIVATE_KEY_LEN_44];
} pqc_ml_dsa_private_key_44;

typedef struct pqc_ml_dsa_public_key_44
{
    uint8_t public_key[PQC_ML_DSA_PUBLIC_KEY_LEN_44];
} pqc_ml_dsa_public_key_44;

typedef struct pqc_ml_dsa_signature_44
{
    uint8_t signature[PQC_ML_DSA_SIGNATURE_LEN_44];
} pqc_ml_dsa_signature_44;

typedef struct pqc_ml_dsa_context_44
{
    pqc_ml_dsa_private_key_44 private_key;
} pqc_ml_dsa_context_44;
