#pragma once

#include "polyvec.h"
#include <pqc/ml-dsa.h>
#include <stdint.h>

namespace mldsa
{

void pack_pkMldsa(
    uint8_t pk[PQC_ML_DSA_PUBLIC_KEY_LEN], // CRYPTO_PUBLICKEYBYTES
    const uint8_t rho[SEEDBYTES], const polyveck * t1
);

void pack_skMldsa(
    uint8_t sk[PQC_ML_DSA_PRIVATE_KEY_LEN], const uint8_t rho[SEEDBYTES], const uint8_t tr[2 * SEEDBYTES],
    const uint8_t key[SEEDBYTES], const polyveck * t0, const polyvecl * s1, const polyveck * s2
);

void pack_sigMldsa(
    uint8_t sig[PQC_ML_DSA_SIGNATURE_LEN], const uint8_t c[2 * SEEDBYTES], const polyvecl * z, const polyveck * h
);

void unpack_pkMldsa(uint8_t rho[SEEDBYTES], polyveck * t1, const uint8_t pk[PQC_ML_DSA_PUBLIC_KEY_LEN]);

void unpack_skMldsa(
    uint8_t rho[SEEDBYTES], uint8_t tr[2 * SEEDBYTES], uint8_t key[SEEDBYTES], polyveck * t0, polyvecl * s1,
    polyveck * s2, const uint8_t sk[PQC_ML_DSA_PRIVATE_KEY_LEN]
);


int unpack_sigMldsa(uint8_t c[2 * SEEDBYTES], polyvecl * z, polyveck * h, const uint8_t sig[PQC_ML_DSA_SIGNATURE_LEN]);

} // namespace mldsa
