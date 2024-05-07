#include "benes.h"

#include <buffer.h>
#include <core.h>
#include <mceliece/params.h>


static void in_layer(uint64_t inp[2][64], uint64_t * bts, int log_a)
{
    int a;

    uint64_t b;

    a = 1 << log_a;

    for (int i = 0; i < 64; i += a * 2)
    {
        for (int j = i; j < i + a; j++)
        {

            b = (inp[0][j + 0] ^ inp[0][j + a]);
            b &= (*bts++);
            inp[0][j + 0] ^= b;
            inp[0][j + a] ^= b;

            b = (inp[1][j + 0] ^ inp[1][j + a]);
            b &= (*bts++);
            inp[1][j + 0] ^= b;
            inp[1][j + a] ^= b;
        }
    }
}

static void ex_layer(uint64_t * inp, uint64_t * bts, int log_a)
{
    int a;

    uint64_t b;

    a = 1 << log_a;

    for (int i = 0; i < 128; i += a * 2)
    {
        for (int j = i; j < i + a; j++)
        {

            b = (inp[j + 0] ^ inp[j + a]);
            b &= (*bts++);
            inp[j + 0] ^= b;
            inp[j + a] ^= b;
        }
    }
}

void mceliece_8192128_f_apply_benes(const BufferView & permBitSeq, const ConstBufferView & bts)
{
    size_t bts_offset = 0;

    uint64_t permBitSeq_int_v[2][64];
    uint64_t permBitSeq_int_h[2][64];
    uint64_t bts_int_v[64];
    uint64_t bts_int_h[64];

    for (int i = 0; i < 64; i++)
    {
        permBitSeq_int_v[0][i] = permBitSeq.load_64(i * 2);
        permBitSeq_int_v[1][i] = permBitSeq.load_64(i * 2 + 1);
    }

    crypto_mceliece_transpose_64_x_64(permBitSeq_int_h[0], permBitSeq_int_v[0]);
    crypto_mceliece_transpose_64_x_64(permBitSeq_int_h[1], permBitSeq_int_v[1]);

    for (int counter = 0; counter <= 6; ++counter)
    {
        for (int i = 0; i < 64; ++i, ++bts_offset)
        {
            bts_int_v[i] = bts.load_64(bts_offset);
        }

        crypto_mceliece_transpose_64_x_64(bts_int_h, bts_int_v);

        ex_layer(permBitSeq_int_h[0], bts_int_h, counter);
    }

    crypto_mceliece_transpose_64_x_64(permBitSeq_int_v[0], permBitSeq_int_h[0]);
    crypto_mceliece_transpose_64_x_64(permBitSeq_int_v[1], permBitSeq_int_h[1]);

    for (int counter = 0; counter <= 5; ++counter)
    {
        for (int i = 0; i < 64; ++i, ++bts_offset)
        {
            bts_int_v[i] = bts.load_64(bts_offset);
        }

        in_layer(permBitSeq_int_v, bts_int_v, counter);
    }

    for (int counter = 4; counter >= 0; --counter)
    {
        for (int i = 0; i < 64; ++i, ++bts_offset)
        {
            bts_int_v[i] = bts.load_64(bts_offset);
        }

        in_layer(permBitSeq_int_v, bts_int_v, counter);
    }

    crypto_mceliece_transpose_64_x_64(permBitSeq_int_h[0], permBitSeq_int_v[0]);
    crypto_mceliece_transpose_64_x_64(permBitSeq_int_h[1], permBitSeq_int_v[1]);

    for (int counter = 6; counter >= 0; --counter)
    {
        for (int i = 0; i < 64; ++i, ++bts_offset)
        {
            bts_int_v[i] = bts.load_64(bts_offset);
        }

        crypto_mceliece_transpose_64_x_64(bts_int_h, bts_int_v);

        ex_layer(permBitSeq_int_h[0], bts_int_h, counter);
    }

    crypto_mceliece_transpose_64_x_64(permBitSeq_int_v[0], permBitSeq_int_h[0]);
    crypto_mceliece_transpose_64_x_64(permBitSeq_int_v[1], permBitSeq_int_h[1]);

    for (int i = 0; i < 64; i++)
    {
        permBitSeq.store_64(i * 2, permBitSeq_int_v[0][i]);
        permBitSeq.store_64(i * 2 + 1, permBitSeq_int_v[1][i]);
    }
}

void mceliece_8192128_f_support_gen(uint16_t * sup, const ConstBufferView & condition)
{
    uint16_t a;
    unsigned char b[GFBITS][(1 << GFBITS) / 8];

    for (size_t i = 0; i < GFBITS; ++i)
    {
        for (size_t j = 0; j < (1 << GFBITS) / 8; ++j)
        {
            b[i][j] = 0;
        }
    }

    for (size_t i = 0; i < (1 << GFBITS); ++i)
    {
        a = crypto_mceliece_bitrev(static_cast<uint16_t>(i));

        for (size_t j = 0; j < GFBITS; ++j)
        {
            b[j][i / 8] |= ((a >> j) & 1) << (i % 8);
        }
    }

    for (size_t j = 0; j < GFBITS; ++j)
    {
        mceliece_8192128_f_apply_benes(BufferView(b[j], (1 << GFBITS) / 8), condition);
    }

    for (size_t i = 0; i < SYS_N; ++i)
    {
        sup[i] = 0;
        for (size_t j = GFBITS; j > 0; --j)
        {
            sup[i] <<= 1;
            sup[i] |= (b[j - 1][i / 8] >> (i % 8)) & 1;
        }
    }
}
