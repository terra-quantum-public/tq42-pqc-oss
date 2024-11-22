#pragma once
#include <pqc/dilithium.h>

#define DILITHIUM_RANDOMIZED_SIGNING

#define SEEDBYTES 32
#define CRHBYTES 48
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#define POLYT1_PACKEDBYTES 320
#define POLYT0_PACKEDBYTES 416

// for dilithium
#define K 8
#define L 7
#define ETA 2
#define TAU 60
#define BETA 120
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q - 1) / 32)
#define OMEGA 75

#define POLYZ_PACKEDBYTES 640
#define POLYW1_PACKEDBYTES 128
#define POLYETA_PACKEDBYTES 96

#define POLYVECH_PACKEDBYTES (OMEGA + K)
//

#define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K * POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES                                                                                          \
    (2 * SEEDBYTES + CRHBYTES + L * POLYETA_PACKEDBYTES + K * POLYETA_PACKEDBYTES + K * POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES (SEEDBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)
