#pragma once

#include <stdint.h>

#define PQC_CIPHER_KYBER 7

#define PQC_KYBER_STRENGTH 4

#if PQC_KYBER_STRENGTH == 2
#define PQC_KYBER_POLYCOMPRESSEDBYTES 128
#define PQC_KYBER_POLYVECCOMPRESSEDBYTES (PQC_KYBER_STRENGTH * 320)
#elif PQC_KYBER_STRENGTH == 3
#define PQC_KYBER_POLYCOMPRESSEDBYTES 128
#define PQC_KYBER_POLYVECCOMPRESSEDBYTES (PQC_KYBER_STRENGTH * 320)
#elif PQC_KYBER_STRENGTH == 4
#define PQC_KYBER_POLYCOMPRESSEDBYTES 160
#define PQC_KYBER_POLYVECCOMPRESSEDBYTES (PQC_KYBER_STRENGTH * 352)
#endif

#define PQC_KYBER_PUBLIC_KEYLEN (PQC_KYBER_STRENGTH * 384 + 32)
#define PQC_KYBER_PRIVATE_KEYLEN (PQC_KYBER_STRENGTH * 384 * 2 + 96)
#define PQC_KYBER_MESSAGE_LENGTH (PQC_KYBER_POLYVECCOMPRESSEDBYTES + PQC_KYBER_POLYCOMPRESSEDBYTES)
#define PQC_KYBER_SHARED_LENGTH 32


typedef struct pqc_kyber_private_key
{
    uint8_t private_key[PQC_KYBER_PRIVATE_KEYLEN];
} pqc_kyber_private_key;

typedef struct pqc_kyber_public_key
{
    uint8_t public_key[PQC_KYBER_PUBLIC_KEYLEN];
} pqc_kyber_public_key;

typedef struct pqc_kyber_message
{
    uint8_t message[PQC_KYBER_MESSAGE_LENGTH];
} pqc_kyber_message;

typedef struct pqc_kyber_shared_secret
{
    uint8_t secret[PQC_KYBER_SHARED_LENGTH];
} pqc_kyber_shared_secret;
