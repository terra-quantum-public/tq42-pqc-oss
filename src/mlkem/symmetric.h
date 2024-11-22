#pragma once

#include <sha3.h>

#include "params.h"
#include <stddef.h>
#include <stdint.h>

#include "fips202.h"

typedef keccak_state xof_state;

void kyber_shake128_absorb(keccak_state * s, const uint8_t seed[ML_RH_SIZE], uint8_t x, uint8_t y);

void kyber_shake256_prf(uint8_t * out, size_t outlen, const uint8_t key[ML_RH_SIZE], uint8_t nonce);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)

inline void function_PRF(const ConstBufferView & in, const BufferView & hash)
{
    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.update(in);
    shake256_hash.retrieve(hash);
}

inline void function_J(const ConstBufferView & in, const BufferView & hash)
{
    SHA3 shake256_hash(PQC_SHAKE_256);
    shake256_hash.update(in);
    shake256_hash.retrieve(hash);
}

inline void function_H(const ConstBufferView & in, const BufferView & hash)
{
    SHA3 mhash(PQC_SHA3_256);
    mhash.update(in);
    mhash.retrieve(hash);
}

inline void function_G(const ConstBufferView & in, const BufferView & hash)
{
    SHA3 mhash(PQC_SHA3_512);
    mhash.update(in);
    mhash.retrieve(hash);
}
