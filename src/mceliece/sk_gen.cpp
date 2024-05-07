#include "sk_gen.h"

#include <mceliece/controlbits.h>
#include <mceliece/declassify.h>
#include <mceliece/params.h>

static int16_t crypto_uint_16_signed_negative_mask(int16_t crypto_uint16_signed_x)
{
    return crypto_uint16_signed_x >> 15;
}

static uint16_t crypto_uint_16_nonzero_mask(uint16_t crypto_uint16_x)
{
    return crypto_uint_16_signed_negative_mask(crypto_uint16_x) | crypto_uint_16_signed_negative_mask(-crypto_uint16_x);
}

static uint16_t crypto_uint_16_zero_mask(uint16_t crypto_uint16_x)
{
    return ~crypto_uint_16_nonzero_mask(crypto_uint16_x);
}

inline static uint16_t gf_is_zero_declassify(uint16_t t)
{
    uint16_t mask = crypto_uint_16_zero_mask(t);
    crypto_declassify(&mask, sizeof mask);
    return mask;
}

bool mceliece_8192128_f_genpoly_gen(uint16_t * res, uint16_t * GFelem)
{
    int i, j, counter, a;

    uint16_t matrix[SYS_T + 1][SYS_T];
    uint16_t msk, inv, b;

    matrix[0][0] = 1;

    for (i = 1; i < SYS_T; ++i)
    {
        matrix[0][i] = 0;
    }

    for (i = 0; i < SYS_T; ++i)
    {
        matrix[1][i] = GFelem[i];
    }

    for (j = 2; j <= SYS_T; ++j)
    {
        crypto_mceliece_gf_mul(matrix[j], matrix[j - 1], GFelem);
    }

    for (j = 0; j < SYS_T; ++j)
    {
        for (counter = j + 1; counter < SYS_T; ++counter)
        {
            msk = crypto_mceliece_gf_iszero(matrix[j][j]);

            for (a = j; a < SYS_T + 1; ++a)
            {
                matrix[a][j] ^= matrix[a][counter] & msk;
            }
        }

        if (gf_is_zero_declassify(matrix[j][j]))
        {
            return false;
        }

        inv = crypto_mceliece_gf_inv(matrix[j][j]);

        for (a = j; a < SYS_T + 1; ++a)
        {
            matrix[a][j] = crypto_mceliece_gf_mul(matrix[a][j], inv);
        }

        for (counter = 0; counter < SYS_T; ++counter)
        {
            if (counter != j)
            {
                b = matrix[j][counter];

                for (a = j; a < SYS_T + 1; ++a)
                {
                    matrix[a][counter] ^= crypto_mceliece_gf_mul(matrix[a][j], b);
                }
            }
        }
    }

    for (i = 0; i < SYS_T; ++i)
    {
        res[i] = matrix[SYS_T][i];
    }

    return true;
}
