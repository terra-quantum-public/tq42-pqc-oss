#include "pk_gen.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#include <buffer.h>
#include <core.h>

#include <mceliece/benes.h>
#include <mceliece/controlbits.h>
#include <mceliece/declassify.h>
#include <mceliece/params.h>
#include <mceliece/sort.h>


class ByteMatrix
{
public:
    ByteMatrix(size_t n_rows, size_t n_cols, unsigned char value)
        : _data(n_cols * n_rows, value), _n_cols(n_cols)
#ifndef NDEBUG
          ,
          _n_rows(n_rows)
#endif
    {
    }

    BufferView operator[](size_t row)
    {
#ifndef NDEBUG
        if (row >= _n_rows)
        {
            throw std::out_of_range("row index out of range");
        }
#endif
        return BufferView(_data.data() + row * _n_cols, _n_cols);
    }

private:
    std::vector<unsigned char> _data;
    size_t _n_cols;
#ifndef NDEBUG
    size_t _n_rows;
#endif
};

static int64_t crypto_uint_64_signed_negative_mask(int64_t crypto_uint64_signed_x)
{
    return crypto_uint64_signed_x >> 63;
}

static uint64_t crypto_uint_64_nonzero_mask(uint64_t crypto_uint64_x)
{
    return crypto_uint_64_signed_negative_mask(crypto_uint64_x) |
           crypto_uint_64_signed_negative_mask(~crypto_uint64_x + 1);
}

static uint64_t crypto_uint_64_zero_mask(uint64_t crypto_uint64_x)
{
    return ~crypto_uint_64_nonzero_mask(crypto_uint64_x);
}

static uint64_t crypto_uint_64_unequal_mask(uint64_t crypto_uint64_x, uint64_t crypto_uint64_y)
{
    uint64_t crypto_uint64_xy = crypto_uint64_x ^ crypto_uint64_y;
    return crypto_uint_64_nonzero_mask(crypto_uint64_xy);
}

static uint64_t crypto_uint_64_equal_mask(uint64_t crypto_uint64_x, uint64_t crypto_uint64_y)
{
    return ~crypto_uint_64_unequal_mask(crypto_uint64_x, crypto_uint64_y);
}

static uint64_t uint_64_is_zero_declassify(uint64_t t)
{
    uint64_t mask = crypto_uint_64_zero_mask(t);
    crypto_declassify(&mask, sizeof mask);
    return mask;
}

static uint64_t uint_64_is_equal_declassify(uint64_t t, uint64_t u)
{
    uint64_t mask = crypto_uint_64_equal_mask(t, u);
    crypto_declassify(&mask, sizeof mask);
    return mask;
}

#include <iomanip>
#include <iostream>

static bool columns_mov(ByteMatrix & matrix, int16_t * pi, uint64_t & pivots)
{
    uint64_t buf[32];
    uint64_t ctzList[32];

    constexpr size_t row = PK_NROWS - 32;

    static_assert(PK_NROWS == GFBITS * SYS_T);
    static_assert((row & 7) == 0);
    const size_t blockIndx = row >> 3;

    for (size_t i = 0; i < 32; ++i)
    {
        buf[i] = matrix[row + i].load_64_offset(blockIndx);
    }

    pivots = 0;

    for (size_t i = 0; i < 32; ++i)
    {
        uint64_t w = buf[i];
        for (size_t j = i + 1; j < 32; ++j)
        {
            w |= buf[j];
        }

        if (uint_64_is_zero_declassify(w))
        {
            return false;
        }

        uint64_t k = 0;
        {
            uint64_t CC = 0;
            uint64_t w_bit = w;

            for (size_t II = 0; II < 64; ++II)
            {
                const uint64_t BB = w_bit & 1;
                CC |= BB;
                k += (CC ^ 1) & (BB ^ 1);
                w_bit >>= 1;
            }
        }

        ctzList[i] = k;
        pivots |= 1ull << k;

        for (size_t j = i + 1; j < 32; ++j)
        {
            uint64_t msk = (buf[i] >> k) & 1;
            msk -= 1;
            buf[i] ^= buf[j] & msk;
        }
        for (size_t j = i + 1; j < 32; ++j)
        {
            uint64_t msk = (buf[j] >> k) & 1;
            msk = ~msk + 1;
            buf[j] ^= buf[i] & msk;
        }
    }

    for (size_t j = 0; j < 32; ++j)
    {
        for (size_t u = j + 1; u < 64; ++u)
        {
            uint64_t l = pi[row + j] ^ pi[row + u];

            uint64_t msk = (uint16_t)u ^ (uint16_t)ctzList[j];
            msk -= 1;
            msk >>= 63;
            msk = ~msk + 1;
            l &= msk;

            pi[row + j] ^= l;
            pi[row + u] ^= l;
        }
    }

    for (size_t i = 0; i < PK_NROWS; ++i)
    {
        uint64_t t = matrix[i].load_64_offset(blockIndx);

        for (size_t j = 0; j < 32; ++j)
        {
            uint64_t l = t >> j;
            l ^= t >> ctzList[j];
            l &= 1;
            t ^= l << ctzList[j];
            t ^= l << j;
        }

        matrix[i].store_64_offset(blockIndx, t);
    }

    return true;
}

bool mceliece_8192128_f_pk_gen(
    const BufferView & pubKey, const uint32_t * perm, const ConstBufferView & secKey, int16_t * pi, uint64_t & pivots
)
{
    std::vector<uint64_t> buf(1 << GFBITS);

    static_assert(PK_NROWS == GFBITS * SYS_T);
    ByteMatrix matrix(PK_NROWS, SYS_N >> 3, 0);

    std::vector<uint16_t> gppa(SYS_T + 1);
    std::vector<uint16_t> sup(SYS_N);
    std::vector<uint16_t> inv(SYS_N);

    gppa[SYS_T] = 1;

    for (size_t i = 0; i < SYS_T; ++i)
    {
        gppa[i] = secKey.load_16(i) & GFMASK;
    }

    for (size_t i = 0; i < 1 << GFBITS; ++i)
    {
        buf[i] = perm[i];
        buf[i] <<= 31;
        buf[i] |= i;
    }

    uint_64_sort(buf.data(), 1 << GFBITS);

    for (size_t i = 1; i < (1 << GFBITS); ++i)
    {
        if (uint_64_is_equal_declassify(buf[i - 1] >> 31, buf[i] >> 31))
            return false;
    }

    static_assert(SYS_N == 1 << GFBITS);
    for (size_t i = 0; i < 1 << GFBITS; ++i)
    {
        pi[i] = buf[i] & GFMASK;
    }
    for (size_t i = 0; i < SYS_N; ++i)
    {
        sup[i] = crypto_mceliece_bitrev(pi[i]);
    }

    crypto_mceliece_root(inv.data(), gppa.data(), sup.data());

    for (size_t i = 0; i < SYS_N; ++i)
    {
        inv[i] = crypto_mceliece_gf_inv(inv[i]);
    }

    for (size_t i = 0; i < SYS_T; ++i)
    {
        for (size_t j = 0; j < SYS_N; j += 1 << 3)
        {
            for (size_t k = 0; k < GFBITS; ++k)
            {
                unsigned char b = (inv[j + 7] >> k) & 1;
                b <<= 1;
                b |= (inv[j + 6] >> k) & 1;
                b <<= 1;
                b |= (inv[j + 5] >> k) & 1;
                b <<= 1;
                b |= (inv[j + 4] >> k) & 1;
                b <<= 1;
                b |= (inv[j + 3] >> k) & 1;
                b <<= 1;
                b |= (inv[j + 2] >> k) & 1;
                b <<= 1;
                b |= (inv[j + 1] >> k) & 1;
                b <<= 1;
                b |= (inv[j + 0] >> k) & 1;

                matrix[i * GFBITS + k][j >> 3] = b;
            }
        }

        for (size_t j = 0; j < SYS_N; ++j)
        {
            inv[j] = crypto_mceliece_gf_mul(inv[j], sup[j]);
        }
    }

    static_assert((PK_NROWS & 7) == 0);
    for (size_t i = 0; i < PK_NROWS >> 3; ++i)
    {
        for (size_t j = 0; j < 8; ++j)
        {
            const size_t row = (i << 3) | j;

            if (row == PK_NROWS - 32)
            {
                if (!columns_mov(matrix, pi, pivots))
                {
                    return false;
                }
            }

            BufferView r = matrix[row];

            for (size_t k = row + 1; k < PK_NROWS; ++k)
            {
                BufferView row_k = matrix[k];
                unsigned char msk = r[i] ^ row_k[i];

                msk >>= j;
                msk &= 1;
                msk = -msk;

                for (size_t c = 0; c < SYS_N >> 3; ++c)
                {
                    r[c] ^= row_k[c] & msk;
                }
            }

            if (uint_64_is_zero_declassify((r[i] >> j) & 1))
            {
                return false;
            }

            for (size_t k = 0; k < PK_NROWS; ++k)
            {
                if (k != row)
                {
                    BufferView row_k = matrix[k];
                    unsigned char msk = row_k[i] >> j;

                    msk &= 1;
                    msk = -msk;

                    for (size_t c = 0; c < SYS_N >> 3; ++c)
                    {
                        row_k[c] ^= r[c] & msk;
                    }
                }
            }
        }
    }

    for (size_t i = 0; i < PK_NROWS; ++i)
    {
        pubKey.mid(i * PK_ROW_BYTES, PK_ROW_BYTES).store(matrix[i].mid(PK_NROWS >> 3, PK_ROW_BYTES));
    }

    return true;
}
