#pragma once

#include <pqc/kyber.h>
#include <pqc/ml-kem.h>
#include <sha3.h>

#define ML_N 256
#define ML_Q 3329
#define ML_RH_SIZE 32 /* size in bytes of hashes, and seeds */
#define ML_ETA2 2
#define ML_POLY_SIZE 384

#define ML_KEM_512 0
#define ML_KEM_768 1
#define ML_KEM_1024 2
#define KYBER_512 3
#define KYBER_768 4
#define KYBER_1024 5

struct ParameterSet
{
    constexpr ParameterSet(
        uint32_t id, size_t k, size_t eta_1, size_t du, size_t dv, size_t polycompr, size_t polyveccompr
    )
        : CIPHER_ID(id), K(k), ETA_1(eta_1), DU(du), DV(dv), POLYVEC_SIZE(K * ML_POLY_SIZE),
          POLYCOMPRESSED_SIZE(polycompr), POLYVECCOMPRESSED_SIZE(polyveccompr),
          PUBLIC_KEY_LEN(POLYVEC_SIZE + ML_RH_SIZE),
          PRIVATE_KEY_LEN(POLYVEC_SIZE + PUBLIC_KEY_LEN + ML_RH_SIZE + ML_RH_SIZE), MESSAGE_LEN(32 * (DU * K + DV)),
          SHARED_LEN(ML_RH_SIZE)
    {
    }
    uint32_t CIPHER_ID;
    size_t K;
    size_t ETA_1;
    size_t DU;
    size_t DV;

    size_t POLYVEC_SIZE;
    size_t POLYCOMPRESSED_SIZE;
    size_t POLYVECCOMPRESSED_SIZE;

    size_t PUBLIC_KEY_LEN;
    size_t PRIVATE_KEY_LEN;
    size_t MESSAGE_LEN;
    size_t SHARED_LEN;
};

static constexpr ParameterSet ParameterSets[] = {
    ParameterSet{PQC_CIPHER_ML_KEM_512, 2, 3, 10, 4, 128, 2 * 320},
    ParameterSet{PQC_CIPHER_ML_KEM_768, 3, 2, 10, 4, 128, 3 * 320},
    ParameterSet{PQC_CIPHER_ML_KEM_1024, 4, 2, 11, 5, 160, 4 * 352},
    ParameterSet{PQC_CIPHER_KYBER_512, 2, 3, 10, 4, 128, 2 * 320},
    ParameterSet{PQC_CIPHER_KYBER_768, 3, 2, 10, 4, 128, 3 * 320},
    ParameterSet{PQC_CIPHER_KYBER_1024, 4, 2, 11, 5, 160, 4 * 352}};
