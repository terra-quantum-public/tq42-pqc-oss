#pragma once

#include "poly.h"
#include <stdint.h>

using polyvec = std::vector<poly>;


void polyvec_compress(uint8_t * r, size_t r_size, polyvec * a, size_t param_k);

void polyvec_decompress(polyvec * r, const uint8_t * a, size_t a_size, size_t param_k);


void polyvec_tobytes(uint8_t * r, polyvec * a);

void polyvec_frombytes(polyvec * r, const uint8_t * a);


void polyvec_ntt(polyvec * r);

void polyvec_invntt_tomont(polyvec * r);


void polyvec_pointwise_acc_montgomery(poly * r, const polyvec * a, size_t offset, const polyvec * b);


void polyvec_reduce(polyvec * r);

void polyvec_csubq(polyvec * r);

void polyvec_add(polyvec * r, const polyvec * a, const polyvec * b);
