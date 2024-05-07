#include "controlbits.h"

#include <cstddef>
#include <vector>

#include <mceliece/declassify.h>
#include <mceliece/params.h>
#include <mceliece/sort.h>


inline static int32_t crypto_int_32_negative_mask(int32_t crypto_int32_x) { return crypto_int32_x >> 31; }

inline static int32_t crypto_int_32_min(int32_t crypto_int32_x, int32_t crypto_int32_y)
{
    int32_t crypto_int32_xy = crypto_int32_y ^ crypto_int32_x;
    int32_t crypto_int32_z = crypto_int32_y - crypto_int32_x;
    crypto_int32_z ^= crypto_int32_xy & (crypto_int32_z ^ crypto_int32_y);
    crypto_int32_z = crypto_int_32_negative_mask(crypto_int32_z);
    crypto_int32_z &= crypto_int32_xy;
    return crypto_int32_x ^ crypto_int32_z;
}

inline static int16_t crypto_int_16_negative_mask(int16_t crypto_int16_x) { return crypto_int16_x >> 15; }

inline static int16_t crypto_int_16_nonzero_mask(int16_t crypto_int16_x)
{
    return crypto_int_16_negative_mask(crypto_int16_x) | crypto_int_16_negative_mask(-crypto_int16_x);
}

static void cbrecursion(uint8_t * out, size_t pos, size_t step, const int16_t * pi, size_t w, size_t n, int32_t * temp)
{
    if (w == 1)
    {
        out[pos >> 3] ^= pi[0] << (pos & 7);
        return;
    }

    for (size_t x = 0; x < n; ++x)
        temp[x] = ((pi[x] ^ 1) << 16) | pi[x ^ 1];

    int_32_sort(temp, n);

    for (size_t x = 0; x < n; ++x)
    {
        int32_t Ax = temp[x];
        int32_t px = Ax & 0xffff;
        int32_t cx = crypto_int_32_min(px, static_cast<int32_t>(x));
        temp[n + x] = (px << 16) | cx;
    }

    for (size_t x = 0; x < n; ++x)
        temp[x] = (temp[x] << 16) | static_cast<int32_t>(x);

    int_32_sort(temp, n);

    for (size_t x = 0; x < n; ++x)
        temp[x] = (temp[x] << 16) + (temp[n + x] >> 16);

    int_32_sort(temp, n);

    if (w <= 10)
    {
        for (size_t x = 0; x < n; ++x)
            temp[n + x] = ((temp[x] & 0xffff) << 10) | (temp[n + x] & 0x3ff);

        for (size_t i = 1; i < w - 1; ++i)
        {
            for (size_t x = 0; x < n; ++x)
                temp[x] = ((temp[n + x] & ~0x3ff) << 6) | static_cast<int32_t>(x);

            int_32_sort(temp, n);

            for (size_t x = 0; x < n; ++x)
                temp[x] = (temp[x] << 20) | temp[n + x];

            int_32_sort(temp, n);

            for (size_t x = 0; x < n; ++x)
            {
                int32_t ppcpx = temp[x] & 0xfffff;
                int32_t ppcx = (temp[x] & 0xffc00) | (temp[n + x] & 0x3ff);
                temp[n + x] = crypto_int_32_min(ppcx, ppcpx);
            }
        }
        for (size_t x = 0; x < n; ++x)
            temp[n + x] &= 0x3ff;
    }
    else
    {
        for (size_t x = 0; x < n; ++x)
            temp[n + x] = (temp[x] << 16) | (temp[n + x] & 0xffff);

        for (size_t i = 1; i < w - 1; ++i)
        {
            for (size_t x = 0; x < n; ++x)
                temp[x] = (temp[n + x] & ~0xffff) | static_cast<int32_t>(x);

            int_32_sort(temp, n);

            for (size_t x = 0; x < n; ++x)
                temp[x] = (temp[x] << 16) | (temp[n + x] & 0xffff);

            if (i < w - 2)
            {
                for (size_t x = 0; x < n; ++x)
                    temp[n + x] = (temp[x] & ~0xffff) | (temp[n + x] >> 16);

                int_32_sort(temp + n, n);

                for (size_t x = 0; x < n; ++x)
                    temp[n + x] = (temp[n + x] << 16) | (temp[x] & 0xffff);
            }

            int_32_sort(temp, n);

            for (size_t x = 0; x < n; ++x)
            {
                int32_t cpx = (temp[n + x] & ~0xffff) | (temp[x] & 0xffff);
                temp[n + x] = crypto_int_32_min(temp[n + x], cpx);
            }
        }
        for (size_t x = 0; x < n; ++x)
            temp[n + x] &= 0xffff;
    }

    for (size_t x = 0; x < n; ++x)
        temp[x] = (((int32_t)pi[x]) << 16) + static_cast<int32_t>(x);

    int_32_sort(temp, n);

    for (size_t j = 0; j < n / 2; ++j)
    {
        size_t x = 2 * j;
        int32_t fj = temp[n + x] & 1;
        int32_t Fx = static_cast<int32_t>(x) + fj;
        int32_t Fx1 = Fx ^ 1;

        out[pos >> 3] ^= fj << (pos & 7);
        pos += step;

        temp[n + x] = (temp[x] << 16) | Fx;
        temp[n + x + 1] = (temp[x + 1] << 16) | Fx1;
    }

    int_32_sort(temp + n, n);

    pos += (2 * w - 3) * step * (n / 2);

    for (size_t k = 0; k < n / 2; ++k)
    {
        size_t y = 2 * k;
        int32_t lk = temp[n + y] & 1;
        int32_t Ly = static_cast<int32_t>(y) + lk;
        int32_t Ly1 = Ly ^ 1;

        out[pos >> 3] ^= lk << (pos & 7);
        pos += step;

        temp[y] = (Ly << 16) | (temp[n + y] & 0xffff);
        temp[y + 1] = (Ly1 << 16) | (temp[n + y + 1] & 0xffff);
    }

    int_32_sort(temp, n);

    pos -= (2 * w - 2) * step * (n / 2);

    for (size_t j = 0; j < n / 2; ++j)
    {
        ((int16_t *)(temp + n + n / 4))[j] = (temp[2 * j] & 0xffff) >> 1;
        ((int16_t *)(temp + n + n / 4))[j + n / 2] = (temp[2 * j + 1] & 0xffff) >> 1;
    }

    cbrecursion(out, pos, step * 2, ((int16_t *)(temp + n + n / 4)), w - 1, n / 2, temp);
    cbrecursion(out, pos + step, step * 2, ((int16_t *)(temp + n + n / 4)) + n / 2, w - 1, n / 2, temp);
}

static void layer(int16_t * p, const uint8_t * cb, size_t s, size_t n)
{
    const size_t stride = 1ull << s;
    size_t index = 0;

    for (size_t i = 0; i < n; i += stride * 2)
    {
        for (size_t j = 0; j < stride; ++j)
        {
            int16_t d = p[i + j] ^ p[i + j + stride];
            int16_t m = (cb[index >> 3] >> (index & 7)) & 1;
            m = -m;
            d &= m;
            p[i + j] ^= d;
            p[i + j + stride] ^= d;
            ++index;
        }
    }
}

void mceliece_8192128_f_controlbits_perm(uint8_t * b, const int16_t * perm)
{
    constexpr size_t aDegIndx = GFBITS;
    constexpr size_t a = 1 << GFBITS;

    while (true)
    {
        std::fill(b, b + (((2 * aDegIndx - 1) * a / 2) + 7) / 8, '\0');

        int32_t temp[2 * a];
        cbrecursion(b, 0, 1, perm, aDegIndx, a, temp);

        int16_t perm_test[a];
        for (size_t i = 0; i < a; ++i)
            perm_test[i] = static_cast<int16_t>(i);

        uint8_t * ptr = b; // FIXME buffer
        for (size_t i = 0; i < aDegIndx; ++i)
        {
            layer(perm_test, ptr, i, a);
            ptr += a >> 4;
        }

        for (size_t i = aDegIndx - 1; i > 0; --i)
        {
            layer(perm_test, ptr, i - 1, a);
            ptr += a >> 4;
        }

        int16_t diff = 0;
        for (size_t i = 0; i < a; ++i)
            diff |= perm[i] ^ perm_test[i];

        // FIXME faster exit?
        diff = crypto_int_16_nonzero_mask(diff);
        crypto_declassify(&diff, sizeof diff);
        if (diff == 0)
            break;
    }
}
