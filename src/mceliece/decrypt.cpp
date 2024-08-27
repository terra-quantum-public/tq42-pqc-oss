#include "decrypt.h"

#include <cstdint>

#include <buffer.h>
#include <mceliece/benes.h>
#include <mceliece/decrypt.h>
#include <mceliece/params.h>


uint16_t
mceliece_8192128_f_decrypt(unsigned char * errVec, const ConstBufferView & secKey, const unsigned char * cipher)
{
    int accum = 0;
    uint16_t flag;

    unsigned char a[SYS_N / 8];

    std::vector<uint16_t> b(SYS_T + 1);
    std::vector<uint16_t> A(SYS_N);

    std::vector<uint16_t> c(SYS_T * 2);
    std::vector<uint16_t> cCmp(SYS_T * 2);
    std::vector<uint16_t> lclizer(SYS_T + 1);
    std::vector<uint16_t> pics(SYS_N);

    for (size_t i = 0; i < SYND_BYTES; ++i)
    {
        a[i] = cipher[i];
    }
    for (size_t i = SYND_BYTES; i < SYS_N / 8; ++i)
    {
        a[i] = 0;
    }

    for (size_t i = 0; i < SYS_T; ++i)
    {
        b[i] = secKey.load_16_le(i) & GFMASK;
    }
    b[SYS_T] = 1;

    mceliece_8192128_f_support_gen(A.data(), secKey.mid(SYS_T * 2, std::nullopt));

    crypto_mceliece_synd(c.data(), b.data(), A.data(), a);

    crypto_mceliece_bm(lclizer.data(), c.data());

    crypto_mceliece_root(pics.data(), lclizer.data(), A.data());

    for (size_t i = 0; i < SYS_N / 8; ++i)
    {
        errVec[i] = 0;
    }

    for (size_t i = 0; i < SYS_N; ++i)
    {
        uint16_t t = crypto_mceliece_gf_iszero(pics[i]) & 1;

        errVec[i / 8] |= t << (i % 8);
        accum += t;
    }

    crypto_mceliece_synd(cCmp.data(), b.data(), A.data(), errVec);


    flag = (uint16_t)accum;
    flag ^= SYS_T;

    for (size_t i = 0; i < SYS_T * 2; ++i)
    {
        flag |= c[i] ^ cCmp[i];
    }

    flag -= 1;
    flag >>= 15;

    return flag ^ 1;
}
