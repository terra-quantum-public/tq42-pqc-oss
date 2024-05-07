#include "special_utils.h"

#include <cstddef>
#include <vector>

#include <mceliece/params.h>


static inline void crypto_mceliece_special_cicle_operator(
    uint64_t * result, uint64_t value, int NUM, int par0, int par1, int par2, int par3
)
{
    for (int i = 0; i < NUM; i++)
    {
        (*result) ^= (value >> par0) ^ (value >> par1) ^ (value >> par2) ^ (value >> par3);
    }
}

static inline void crypto_mceliece_special_cicle_operator(
    uint64_t * result, const uint64_t * Array, uint64_t value, int NUM, int par0, int par1, int par2, int par3
)
{
    for (int i = 0; i < NUM; i++)
    {
        value = (*result) & Array[i];
        (*result) ^= (value >> par0) ^ (value >> par1) ^ (value >> par2) ^ (value >> par3);
    }
}

void crypto_mceliece_transpose_64_x_64(uint64_t * res, const uint64_t * GFmat)
{
    const uint64_t msks[6][2] = {{0x5555555555555555, 0xAAAAAAAAAAAAAAAA}, {0x3333333333333333, 0xCCCCCCCCCCCCCCCC},
                                 {0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0}, {0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00},
                                 {0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000}, {0x00000000FFFFFFFF, 0xFFFFFFFF00000000}};

    for (int i = 0; i < 64; i++)
    {
        res[i] = GFmat[i];
    }
    for (int b = 5; b >= 0; b--)
    {
        int a = 1 << b;

        for (int i = 0; i < 64; i += a * 2)
        {
            for (int j = i; j < i + a; j++)
            {
                const uint64_t c = (res[j] & msks[b][0]) | ((res[j + a] & msks[b][0]) << a);
                const uint64_t d = ((res[j] & msks[b][1]) >> a) | (res[j + a] & msks[b][1]);

                res[j + 0] = c;
                res[j + a] = d;
            }
        }
    }
}

uint16_t crypto_mceliece_eval(const uint16_t * poly, uint16_t felem)
{
    uint16_t res = poly[SYS_T];

    for (size_t i = SYS_T; i > 0; --i)
    {
        res = crypto_mceliece_gf_mul(res, felem);
        res = crypto_mceliece_gf_add(res, poly[i - 1]);
    }

    return res;
}

void crypto_mceliece_root(uint16_t * res, const uint16_t * poly, const uint16_t * a)
{
    for (size_t i = 0; i < SYS_N; ++i)
    {
        res[i] = crypto_mceliece_eval(poly, a[i]);
    }
}

uint16_t crypto_mceliece_bitrev(uint16_t use)
{
    use = ((use & 0x00FF) << 8) | ((use & 0xFF00) >> 8);
    use = ((use & 0x0F0F) << 4) | ((use & 0xF0F0) >> 4);
    use = ((use & 0x3333) << 2) | ((use & 0xCCCC) >> 2);
    use = ((use & 0x5555) << 1) | ((use & 0xAAAA) >> 1);

    return use >> 3;
}

uint16_t crypto_mceliece_gf_iszero(uint16_t a)
{
    uint32_t b = a;

    b -= 1;
    b >>= 19;

    return static_cast<uint16_t>(b);
}

uint16_t crypto_mceliece_gf_add(uint16_t inp0, uint16_t inp1) { return inp0 ^ inp1; }

uint16_t crypto_mceliece_gf_mul(uint16_t inp0, uint16_t inp1)
{
    uint64_t a0 = inp0;
    uint64_t a1 = inp1;
    uint64_t temp = a0 * (a1 & 1);

    for (size_t i = 1; i < GFBITS; ++i)
    {
        temp ^= (a0 * (a1 & ((uint64_t)1 << i)));
    }
    uint64_t a = temp & 0x1FF0000;
    crypto_mceliece_special_cicle_operator(&temp, a, 1, 9, 10, 12, 13);

    a = temp & 0x000E000;
    crypto_mceliece_special_cicle_operator(&temp, a, 1, 9, 10, 12, 13);

    return temp & GFMASK;
}


static inline uint16_t gf_sq_2(uint16_t fElem)
{
    const uint64_t A[] = {0x1111111111111111, 0x0303030303030303, 0x000F000F000F000F, 0x000000FF000000FF};
    const uint64_t C[] = {0x0001FF0000000000, 0x000000FF80000000, 0x000000007FC00000, 0x00000000003FE000};

    uint64_t a = fElem;
    uint64_t b = 0;

    a = (a | (a << 24)) & A[3];
    a = (a | (a << 12)) & A[2];
    a = (a | (a << 6)) & A[1];
    a = (a | (a << 3)) & A[0];

    crypto_mceliece_special_cicle_operator(&a, C, b, 4, 9, 10, 12, 13);

    return a & GFMASK;
}

static inline uint16_t gf_sqmul(uint16_t fElem, uint16_t x)
{
    uint64_t u;
    uint64_t a0;
    uint64_t a1;
    uint64_t a = 0;

    const uint64_t C[] = {0x0000001FF0000000, 0x000000000FF80000, 0x000000000007E000};

    a0 = fElem;
    a1 = x;

    u = (a1 << 6) * (a0 & (1 << 6));

    a0 ^= (a0 << 7);

    u ^= (a1 * (a0 & (0x04001)));
    u ^= (a1 * (a0 & (0x08002))) << 1;
    u ^= (a1 * (a0 & (0x10004))) << 2;
    u ^= (a1 * (a0 & (0x20008))) << 3;
    u ^= (a1 * (a0 & (0x40010))) << 4;
    u ^= (a1 * (a0 & (0x80020))) << 5;

    crypto_mceliece_special_cicle_operator(&u, C, a, 3, 9, 10, 12, 13);

    return u & GFMASK;
}

static inline uint16_t gf_sq_2_mul(uint16_t fElem, uint16_t x)
{
    uint64_t u;
    uint64_t a0;
    uint64_t a1;
    uint64_t a = 0ULL;

    const uint64_t C[] = {0x1FF0000000000000, 0x000FF80000000000, 0x000007FC00000000,
                          0x00000003FE000000, 0x0000000001FE0000, 0x000000000001E000};

    a0 = fElem;
    a1 = x;

    u = (a1 << 18) * (a0 & (1 << 6));

    a0 ^= (a0 << 21);

    u ^= (a1 * (a0 & (0x010000001)));
    u ^= (a1 * (a0 & (0x020000002))) << 3;
    u ^= (a1 * (a0 & (0x040000004))) << 6;
    u ^= (a1 * (a0 & (0x080000008))) << 9;
    u ^= (a1 * (a0 & (0x100000010))) << 12;
    u ^= (a1 * (a0 & (0x200000020))) << 15;

    crypto_mceliece_special_cicle_operator(&u, C, a, 6, 9, 10, 12, 13);

    return u & GFMASK;
}

uint16_t crypto_mceliece_gf_frac(uint16_t fElemDen, uint16_t num)
{
    uint16_t temp11;
    uint16_t temp1111;
    uint16_t res;

    temp11 = gf_sqmul(fElemDen, fElemDen);
    temp1111 = gf_sq_2_mul(temp11, temp11);
    res = gf_sq_2(temp1111);
    res = gf_sq_2_mul(res, temp1111);
    res = gf_sq_2(res);
    res = gf_sq_2_mul(res, temp1111);

    return gf_sqmul(res, num);
}

uint16_t crypto_mceliece_gf_inv(uint16_t fElem) { return crypto_mceliece_gf_frac(fElem, 1); }

void crypto_mceliece_gf_mul(uint16_t * res, const uint16_t * inp0, const uint16_t * inp1)
{
    uint16_t prd[SYS_T * 2 - 1];

    for (size_t i = 0; i < SYS_T * 2 - 1; ++i)
    {
        prd[i] = 0;
    }

    for (size_t i = 0; i < SYS_T; ++i)
    {
        for (size_t j = 0; j < SYS_T; ++j)
        {
            prd[i + j] ^= crypto_mceliece_gf_mul(inp0[i], inp1[j]);
        }
    }

    for (size_t i = (SYS_T - 1) * 2; i >= SYS_T; --i)
    {
        prd[i - SYS_T + 7] ^= prd[i];
        prd[i - SYS_T + 2] ^= prd[i];
        prd[i - SYS_T + 1] ^= prd[i];
        prd[i - SYS_T + 0] ^= prd[i];
    }

    for (size_t i = 0; i < SYS_T; ++i)
    {
        res[i] = prd[i];
    }
}


void crypto_mceliece_bm(uint16_t * res, const uint16_t * seq)
{
    uint16_t A = 0;

    uint16_t B[SYS_T + 1];
    uint16_t C[SYS_T + 1];
    uint16_t D[SYS_T + 1];

    uint16_t b = 1;

    for (size_t i = 0; i < SYS_T + 1; ++i)
    {
        C[i] = D[i] = 0;
    }

    D[1] = C[0] = 1;

    for (size_t counter = 0; counter < 2 * SYS_T; ++counter)
    {
        uint16_t d = 0;

        for (size_t i = 0; i <= std::min<size_t>(counter, SYS_T); ++i)
        {
            d ^= crypto_mceliece_gf_mul(C[i], seq[counter - i]);
        }

        uint16_t l = d;
        l -= 1;
        l >>= 15;
        l -= 1;

        uint16_t k = static_cast<uint16_t>(counter);
        k -= 2 * A;
        k >>= 15;
        k -= 1;
        k &= l;

        for (size_t i = 0; i <= SYS_T; ++i)
        {
            B[i] = C[i];
        }

        uint16_t f = crypto_mceliece_gf_frac(b, d);

        for (size_t i = 0; i <= SYS_T; ++i)
        {
            C[i] ^= crypto_mceliece_gf_mul(f, D[i]) & l;
        }

        A = (A & ~k) | ((counter + 1 - A) & k);

        for (size_t i = 0; i <= SYS_T; ++i)
        {
            D[i] = (D[i] & ~k) | (B[i] & k);
        }

        b = (b & ~k) | (d & k);

        for (size_t i = SYS_T; i >= 1; --i)
        {
            D[i] = D[i - 1];
        }
        D[0] = 0;
    }

    for (size_t i = 0; i <= SYS_T; ++i)
    {
        res[i] = C[SYS_T - i];
    }
}

void crypto_mceliece_synd(uint16_t * res, uint16_t * gpPoly, uint16_t * sup, const unsigned char * receivWord)
{
    uint16_t a, aInv, b;

    for (size_t j = 0; j < 2 * SYS_T; ++j)
    {
        res[j] = 0;
    }

    for (size_t i = 0; i < SYS_N; ++i)
    {
        b = (receivWord[i / 8] >> (i % 8)) & 1;

        a = crypto_mceliece_eval(gpPoly, sup[i]);
        aInv = crypto_mceliece_gf_inv(crypto_mceliece_gf_mul(a, a));

        for (int j = 0; j < 2 * SYS_T; ++j)
        {
            res[j] = crypto_mceliece_gf_add(res[j], crypto_mceliece_gf_mul(aInv, b));
            aInv = crypto_mceliece_gf_mul(aInv, sup[i]);
        }
    }
}
