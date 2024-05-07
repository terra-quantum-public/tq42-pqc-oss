#pragma once
#include "common.h"
#include <stdint.h>


#define PQC_CIPHER_FALCON 5


#define PQC_FALCON_PRIVKEY_SIZE(logn)                                                                                   \
    (((logn) <= 3 ? (3u << (logn)) : ((10u - ((logn) >> 1)) << ((logn)-2)) + (1 << (logn))) + 1)

#define PQC_FALCON_PUBKEY_SIZE(logn) (((logn) <= 1 ? 4u : (7u << ((logn)-2))) + 1)

#define PQC_FALCON_SIG_COMPRESSED_MAXSIZE(logn) (((((11u << (logn)) + (101u >> (10 - (logn)))) + 7) >> 3) + 41)

#define PQC_FALCON_SIG_PADDED_SIZE(logn)                                                                                \
    (44u + 3 * (256u >> (10 - (logn))) + 2 * (128u >> (10 - (logn))) + 3 * (64u >> (10 - (logn))) +                    \
     2 * (16u >> (10 - (logn))) - 2 * (2u >> (10 - (logn))) - 8 * (1u >> (10 - (logn))))

#define PQC_FALCON_SIG_CT_SIZE(logn) ((3u << ((logn)-1)) - ((logn) == 3) + 41)

#define PQC_FALCON_TMPSIZE_KEYGEN(logn) (((logn) <= 3 ? 272u : (28u << (logn))) + (3u << (logn)) + 7)

#define PQC_FALCON_TMPSIZE_MAKEPUB(logn) ((6u << (logn)) + 1)


#define PQC_FALCON_TMPSIZE_SIGNDYN(logn) ((78u << (logn)) + 7)


#define PQC_FALCON_TMPSIZE_SIGNTREE(logn) ((50u << (logn)) + 7)


#define PQC_FALCON_TMPSIZE_EXPANDPRIV(logn) ((52u << (logn)) + 7)


#define PQC_FALCON_EXPANDEDKEY_SIZE(logn) (((8u * (logn) + 40) << (logn)) + 8)


#define PQC_FALCON_TMPSIZE_VERIFY(logn) ((8u << (logn)) + 1)


#define PQC_FALCON_PRIVATE_KEYLEN PQC_FALCON_PRIVKEY_SIZE(10)
#define PQC_FALCON_PUBLIC_KEYLEN PQC_FALCON_PUBKEY_SIZE(10)
#define PQC_FALCON_SIGNATURE_LEN PQC_FALCON_SIG_PADDED_SIZE(10)

struct pqc_falcon_private_key
{
    uint8_t private_key[PQC_FALCON_PRIVATE_KEYLEN];
};

struct pqc_falcon_public_key
{
    uint8_t public_key[PQC_FALCON_PUBLIC_KEYLEN];
};

struct pqc_falcon_signature
{
    uint8_t signature[PQC_FALCON_SIGNATURE_LEN];
};

struct pqc_falcon_context
{
    pqc_falcon_private_key private_key;
};