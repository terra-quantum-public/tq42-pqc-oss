#pragma once

#include <pqc/slh-dsa.h>
#include <sha3.h>

namespace slh_dsa
{

#define SLH_DSA_SHAKE_128S 0
#define SLH_DSA_SHAKE_128F 1
#define SLH_DSA_SHAKE_192S 2
#define SLH_DSA_SHAKE_192F 3
#define SLH_DSA_SHAKE_256S 4
#define SLH_DSA_SHAKE_256F 5

#define PQC_SLH_DSA_SIGN_RANDOMIZED 1

struct ParameterSet
{
    constexpr ParameterSet(
        uint32_t id, size_t n, size_t h, size_t d, size_t h_prime, size_t a, size_t k, size_t lgw, size_t m
    )
        : CIPHER_ID(id), N(n), H(h), D(d), H_PRIME(h_prime), A(a), K(k), LGW(lgw), M(m), W((size_t)1 << LGW),
          LEN_1(2 * N), LEN_2(3), LEN(LEN_1 + LEN_2), CSUM_LEN(2), MSG_DIGEST_LEN((K * A + 8 - 1) / 8),
          PUBLIC_KEY_LEN(2 * N), PRIVATE_KEY_LEN(4 * N), SIGNATURE_LEN((1 + K * (1 + A) + H + D * LEN) * N)
    {
    }
    uint32_t CIPHER_ID;
    size_t N;
    size_t H;
    size_t D;
    size_t H_PRIME;
    size_t A;
    size_t K;
    size_t LGW;
    size_t M;
    size_t W;
    size_t LEN_1;
    size_t LEN_2;
    size_t LEN;
    size_t CSUM_LEN;
    size_t MSG_DIGEST_LEN;

    size_t PUBLIC_KEY_LEN;
    size_t PRIVATE_KEY_LEN;
    size_t SIGNATURE_LEN;
};

static constexpr ParameterSet ParameterSets[] = {
    ParameterSet{PQC_CIPHER_SLH_DSA_SHAKE_128S, 16, 63, 7, 9, 12, 14, 4, 30},
    ParameterSet{PQC_CIPHER_SLH_DSA_SHAKE_128F, 16, 66, 22, 3, 6, 33, 4, 34},
    ParameterSet{PQC_CIPHER_SLH_DSA_SHAKE_192S, 24, 63, 7, 9, 14, 17, 4, 39},
    ParameterSet{PQC_CIPHER_SLH_DSA_SHAKE_192F, 24, 66, 22, 3, 8, 33, 4, 42},
    ParameterSet{PQC_CIPHER_SLH_DSA_SHAKE_256S, 32, 64, 8, 8, 14, 22, 4, 47},
    ParameterSet{PQC_CIPHER_SLH_DSA_SHAKE_256F, 32, 68, 17, 4, 9, 35, 4, 49}};

inline void function_Hmsg(
    const ConstBufferView & R, const ConstBufferView & PKseed, const ConstBufferView & PKroot,
    const ConstBufferView & M, const BufferView & hash
)
{
    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.update(R);
    shake256_hash.update(PKseed);
    shake256_hash.update(PKroot);
    shake256_hash.update(M);
    shake256_hash.retrieve(hash);
}

inline void function_PRF(
    const ConstBufferView & PKseed, const ConstBufferView & ADRS, const ConstBufferView & SKseed,
    const BufferView & hash
)
{
    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.update(PKseed);
    shake256_hash.update(ADRS);
    shake256_hash.update(SKseed);
    shake256_hash.retrieve(hash);
}

inline void function_PRFmsg(
    const ConstBufferView & SKprf, const ConstBufferView & opt_rand, const ConstBufferView & M, const BufferView & hash
)
{
    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.update(SKprf);
    shake256_hash.update(opt_rand);
    shake256_hash.update(M);
    shake256_hash.retrieve(hash);
}

inline void function_F(
    const ConstBufferView & PKseed, const ConstBufferView & ADRS, const ConstBufferView & M1, const BufferView & hash
)
{
    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.update(PKseed);
    shake256_hash.update(ADRS);
    shake256_hash.update(M1);
    shake256_hash.retrieve(hash);
}

inline void function_H(
    const ConstBufferView & PKseed, const ConstBufferView & ADRS, const ConstBufferView & p1,
    const ConstBufferView & p2, const BufferView & hash
)
{
    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.update(PKseed);
    shake256_hash.update(ADRS);
    shake256_hash.update(p1);
    shake256_hash.update(p2);
    shake256_hash.retrieve(hash);
}

inline void function_Tl(
    const ConstBufferView & PKseed, const ConstBufferView & ADRS, const ConstBufferView & M, const BufferView & hash
)
{
    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.update(PKseed);
    shake256_hash.update(ADRS);
    shake256_hash.update(M);
    shake256_hash.retrieve(hash);
}

} // namespace slh_dsa
