#pragma once

#include "common.h"

#define PQC_CIPHER_SHA3 4

enum
{
    PQC_SHA3_224 = 224,
    PQC_SHA3_256 = 256,
    PQC_SHA3_384 = 384,
    PQC_SHA3_512 = 512,
    PQC_SHAKE_256 = 32,
    PQC_SHAKE_128 = 16 // 16 - in bytes: 128 bit, 32 - in bytes: 256 bit. For no eq. to sha3
};
