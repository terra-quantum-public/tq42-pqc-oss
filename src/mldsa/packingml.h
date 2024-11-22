#pragma once

#include "polyvec.h"
#include <pqc/ml-dsa.h>
#include <stdint.h>

namespace mldsa
{

void pack_pkMldsa(
    uint8_t pk[], // CRYPTO_PUBLICKEYBYTES
    const uint8_t rho[SEEDBYTES], const poly * t1, uint8_t modeK
);

void pack_skMldsa(
    uint8_t sk[], const uint8_t rho[SEEDBYTES], const uint8_t tr[2 * SEEDBYTES], const uint8_t key[SEEDBYTES],
    const poly * t0, const poly * s1, const poly * s2, uint8_t modeK
);

void pack_sigMldsa(uint8_t sig[], const uint8_t c[], const poly * z, const poly * h, uint8_t modeK);

void unpack_pkMldsa(uint8_t rho[SEEDBYTES], poly * t1, const uint8_t pk[], uint8_t modeK);

void unpack_skMldsa(
    uint8_t rho[SEEDBYTES], uint8_t tr[2 * SEEDBYTES], uint8_t key[SEEDBYTES], poly * t0, poly * s1, poly * s2,
    const uint8_t sk[], uint8_t modeK
);


int unpack_sigMldsa(uint8_t c[], poly * z, poly * h, const uint8_t sig[], uint8_t modeK);

} // namespace mldsa
