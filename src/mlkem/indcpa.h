#pragma once

#include "params.h"
#include "polyvec.h"
#include <buffer.h>
#include <core.h>
#include <stdint.h>

void gen_matrix(polyvec * a, uint8_t param_k, const uint8_t seed[ML_RH_SIZE], int transposed);

void indcpa_keypair(const BufferView & pubkey, const BufferView & seckey, size_t mode, IRandomGenerator * rng);

void indcpa_enc(
    uint8_t * c, const uint8_t m[ML_RH_SIZE], const ConstBufferView & pk, const uint8_t coins[ML_RH_SIZE], size_t mode
);

void indcpa_dec(uint8_t m[ML_RH_SIZE], const uint8_t * c, const ConstBufferView & sk, size_t mode);
