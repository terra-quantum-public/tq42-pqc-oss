#pragma once

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

namespace mldsa
{

typedef struct
{
    uint64_t s[25];
    unsigned int pos;
} keccak_state;


void shake128_init(keccak_state * state);

void shake128_absorb(keccak_state * state, const uint8_t * in, size_t inlen);

void shake128_finalize(keccak_state * state);

void shake128_squeezeblocks(uint8_t * out, size_t nblocks, keccak_state * state);

void shake128_squeeze(uint8_t * out, size_t outlen, keccak_state * state);

void shake256_init(keccak_state * state);

void shake256_absorb(keccak_state * state, const uint8_t * in, size_t inlen);

void shake256_finalize(keccak_state * state);

void shake256_squeezeblocks(uint8_t * out, size_t nblocks, keccak_state * state);

void shake256_squeeze(uint8_t * out, size_t outlen, keccak_state * state);

void shake128(uint8_t * out, size_t outlen, const uint8_t * in, size_t inlen);

void shake256(uint8_t * out, size_t outlen, const uint8_t * in, size_t inlen);

void sha3_256(uint8_t h[32], const uint8_t * in, size_t inlen);

void sha3_512(uint8_t h[64], const uint8_t * in, size_t inlen);

} // namespace mldsa
