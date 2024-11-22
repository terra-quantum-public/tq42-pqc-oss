#include "encrypt.h"

#include <array>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <core.h>
#include <mceliece/declassify.h>
#include <mceliece/params.h>
#include <mceliece/special_utils.h>
#include <rng/random_generator.h>

static int32_t crypto_uint_32_signed_negative_mask(int32_t crypto_uint32_signed_x)
{
    return crypto_uint32_signed_x >> 31;
}

static uint32_t crypto_uint_32_nonzero_mask(uint32_t crypto_uint32_x)
{
    return crypto_uint_32_signed_negative_mask(crypto_uint32_x) |
           crypto_uint_32_signed_negative_mask(~crypto_uint32_x + 1);
}

static uint32_t crypto_uint_32_unequal_mask(uint32_t crypto_uint32_x, uint32_t crypto_uint32_y)
{
    uint32_t crypto_uint32_xy = crypto_uint32_x ^ crypto_uint32_y;
    return crypto_uint_32_nonzero_mask(crypto_uint32_xy);
}

static uint32_t crypto_uint_32_equal_mask(uint32_t crypto_uint32_x, uint32_t crypto_uint32_y)
{
    return ~crypto_uint_32_unequal_mask(crypto_uint32_x, crypto_uint32_y);
}

static inline uint32_t uint_32_is_equal_declassify(uint32_t t, uint32_t u)
{
    uint32_t mask = crypto_uint_32_equal_mask(t, u);
    crypto_declassify(&mask, sizeof mask);
    return mask;
}

static inline uint8_t same_mask(uint16_t a, uint16_t b)
{
    uint32_t msk;

    msk = a ^ b;
    msk -= 1;
    msk >>= 31;
    msk = ~msk + 1;

    return static_cast<uint8_t>(msk);
}

static void e_gen(unsigned char * errVec, IRandomGenerator * rng)
{
    std::array<uint16_t, SYS_T> id;
    unsigned char val[SYS_T];

    while (true)
    {
        rng->random_bytes(id);

        for (size_t i = 0; i < SYS_T; ++i)
        {
            id[i] &= GFMASK;
        }

        int a = 0;

        for (size_t i = 1; i < SYS_T; ++i)
        {
            for (size_t j = 0; j < i; ++j)
            {
                if (uint_32_is_equal_declassify(id[i], id[j]))
                {
                    a = 1;
                }
            }
        }

        if (a == 0)
        {
            break;
        }
    }

    for (size_t j = 0; j < SYS_T; ++j)
    {
        val[j] = 1 << (id[j] & 7);
    }

    for (size_t i = 0; i < SYS_N / 8; ++i)
    {
        errVec[i] = 0;

        for (size_t j = 0; j < SYS_T; ++j)
        {
            uint8_t msk = same_mask((uint16_t)i, (id[j] >> 3));

            errVec[i] |= val[j] & msk;
        }
    }
}

static void syndrome(unsigned char * sndrm, const unsigned char * pubKey, const unsigned char * errVec)
{
    uint8_t row[SYS_N / 8];
    const unsigned char * pubKey_ptr = pubKey;

    for (size_t i = 0; i < SYND_BYTES; ++i)
    {
        sndrm[i] = 0;
    }

    for (size_t i = 0; i < PK_NROWS; ++i)
    {
        for (size_t j = 0; j < SYS_N / 8; ++j)
        {
            row[j] = 0;
        }

        for (size_t j = 0; j < PK_ROW_BYTES; ++j)
        {
            row[SYS_N / 8 - PK_ROW_BYTES + j] = pubKey_ptr[j];
        }

        row[i / 8] |= 1 << (i % 8);

        uint8_t b = 0;
        for (size_t j = 0; j < SYS_N / 8; ++j)
        {
            b ^= row[j] & errVec[j];
        }

        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        b &= 1;

        sndrm[i / 8] |= (b << (i % 8));

        pubKey_ptr += PK_ROW_BYTES;
    }
}

void mceliece_8192128_f_encrypt(
    unsigned char * sndrm, unsigned char * errVec, const unsigned char * pubKey, IRandomGenerator * rng
)
{
    e_gen(errVec, rng);

    syndrome(sndrm, pubKey, errVec);
}
