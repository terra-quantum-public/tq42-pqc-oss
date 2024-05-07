#pragma once

#include <stdint.h>

#include "common.h"

#define PQC_CIPHER_MCELIECE 10

#define PQC_MCELIECE_PUBLICKEYBYTES 1357824
#define PQC_MCELIECE_SECRETKEYBYTES 14120
#define PQC_MCELIECE_CIPHERTEXTBYTES 208
#define PQC_MCELIECE_CRYPTO_BYTES 32

#define PQC_MCELIECE_PUBLIC_KEYLEN PQC_MCELIECE_PUBLICKEYBYTES
#define PQC_MCELIECE_PRIVATE_KEYLEN PQC_MCELIECE_SECRETKEYBYTES
#define PQC_MCELIECE_MESSAGE_LENGTH PQC_MCELIECE_CIPHERTEXTBYTES
#define PQC_MCELIECE_SHARED_LENGTH PQC_MCELIECE_CRYPTO_BYTES

typedef struct pqc_mceliece_private_key
{
    uint8_t private_key[PQC_MCELIECE_SECRETKEYBYTES];
} pqc_mceliece_private_key;

typedef struct pqc_mceliece_public_key
{
    uint8_t public_key[PQC_MCELIECE_PUBLICKEYBYTES];
} pqc_mceliece_public_key;

typedef struct pqc_mceliece_message
{
    uint8_t message[PQC_MCELIECE_CIPHERTEXTBYTES];
} pqc_mceliece_message;

typedef struct pqc_mceliece_context
{
    pqc_mceliece_private_key private_key;
} pqc_mceliece_context;

typedef struct pqc_mceliece_shared_secret
{
    uint8_t secret[PQC_MCELIECE_CRYPTO_BYTES];
} pqc_mceliece_shared_secret;
