#pragma once

#include <cstdint>


void crypto_mceliece_transpose_64_x_64(uint64_t *, const uint64_t *);

uint16_t crypto_mceliece_eval(const uint16_t *, uint16_t);
void crypto_mceliece_root(uint16_t *, const uint16_t *, const uint16_t *);

uint16_t crypto_mceliece_bitrev(uint16_t);

uint16_t crypto_mceliece_gf_iszero(uint16_t a);
uint16_t crypto_mceliece_gf_add(uint16_t inp0, uint16_t inp1);
uint16_t crypto_mceliece_gf_mul(uint16_t inp0, uint16_t inp1);
uint16_t crypto_mceliece_gf_frac(uint16_t felemDen, uint16_t n);
uint16_t crypto_mceliece_gf_inv(uint16_t inp);
uint64_t crypto_mceliece_gf_mul_2(uint16_t a, uint16_t b0, uint16_t b1);

void crypto_mceliece_gf_mul(uint16_t * res, const uint16_t * inp0, const uint16_t * inp1);

void crypto_mceliece_bm(uint16_t *, const uint16_t *);

void crypto_mceliece_synd(uint16_t *, uint16_t *, uint16_t *, const unsigned char *);
