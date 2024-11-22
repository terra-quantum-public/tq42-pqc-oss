#pragma once

#include "params.h"
#include "polyvec.h"
#include <stdint.h>

namespace dilithium
{

void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES], const polyveck * t1);

void pack_sk(
    uint8_t sk[CRYPTO_SECRETKEYBYTES], const uint8_t rho[SEEDBYTES], const uint8_t tr[CRHBYTES],
    const uint8_t key[SEEDBYTES], const polyveck * t0, const polyvecl * s1, const polyveck * s2
);

void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[SEEDBYTES], const poly * z, const poly * h);

void unpack_pk(uint8_t rho[SEEDBYTES], polyveck * t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

void unpack_sk(
    uint8_t rho[SEEDBYTES], uint8_t tr[CRHBYTES], uint8_t key[SEEDBYTES], poly * t0, poly * s1, poly * s2,
    const uint8_t sk[CRYPTO_SECRETKEYBYTES]
);

int unpack_sig(uint8_t c[SEEDBYTES], polyvecl * z, polyveck * h, const uint8_t sig[CRYPTO_BYTES]);

} // namespace dilithium
