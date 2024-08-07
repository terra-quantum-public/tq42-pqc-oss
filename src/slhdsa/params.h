#pragma once

#include <cassert>
#include <sha3.h>

// MODE: SLH-DSA-SHAKE-256f

namespace slh_dsa
{

#define PQC_SLH_DSA_N 32
#define PQC_SLH_DSA_H 68
#define PQC_SLH_DSA_D 17
#define PQC_SLH_DSA_H_PRIME 4
#define PQC_SLH_DSA_A 9
#define PQC_SLH_DSA_K 35
#define PQC_SLH_DSA_LGW 4
#define PQC_SLH_DSA_M 49
#define PQC_SLH_DSA_SECLEVEL 5

#define PQC_SLH_DSA_SIGN_RANDOMIZED 1

#define PQC_SLH_DSA_W (1L << 4)
#define PQC_SLH_DSA_LEN_1 (2 * PQC_SLH_DSA_N)
#define PQC_SLH_DSA_LEN_2 3
#define PQC_SLH_DSA_LEN (PQC_SLH_DSA_LEN_1 + PQC_SLH_DSA_LEN_2)
#define PQC_SLH_DSA_CSUM_LEN 2
#define PQC_SLH_DSA_MSG_DIGEST_LEN 40 // ceil(K*A/8)

inline void function_Hmsg(
    const ConstBufferView & R, const ConstBufferView & PKseed, const ConstBufferView & PKroot,
    const ConstBufferView & M, const BufferView & hash
)
{
    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.add_data(R);
    shake256_hash.add_data(PKseed);
    shake256_hash.add_data(PKroot);
    shake256_hash.add_data(M);
    shake256_hash.get_hash(hash);
}

inline void function_PRF(const ConstBufferView & data, const BufferView & hash)
{
    assert(hash.size() == PQC_SLH_DSA_N);

    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.add_data(data);
    shake256_hash.get_hash(hash);
}

inline void function_PRFmsg(
    const ConstBufferView & SKprf, const ConstBufferView & opt_rand, const ConstBufferView & M, const BufferView & hash
)
{
    assert(hash.size() == PQC_SLH_DSA_N);

    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.add_data(SKprf);
    shake256_hash.add_data(opt_rand);
    shake256_hash.add_data(M);
    shake256_hash.get_hash(hash);
}

inline void function_F(const ConstBufferView & data, const BufferView & hash)
{
    assert(hash.size() == PQC_SLH_DSA_N);

    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.add_data(data);
    shake256_hash.get_hash(hash);
}

inline void function_H(const ConstBufferView & data, const BufferView & hash)
{
    assert(hash.size() == PQC_SLH_DSA_N);

    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.add_data(data);
    shake256_hash.get_hash(hash);
}

inline void function_Tl(const ConstBufferView & data, const BufferView & hash)
{
    assert(hash.size() == PQC_SLH_DSA_N);

    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.add_data(data);
    shake256_hash.get_hash(hash);
}

} // namespace slh_dsa
