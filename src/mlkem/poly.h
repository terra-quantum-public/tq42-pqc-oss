#pragma once

#include "params.h"
#include <stdint.h>

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct
{
    int16_t coeffs[ML_N];
} poly;

void poly_compress(uint8_t * r, size_t r_size, poly * a);

void poly_decompress(poly * r, const uint8_t * a, size_t a_size);


void poly_tobytes(uint8_t r[ML_POLY_SIZE], poly * a);

void poly_frombytes(poly * r, const uint8_t a[ML_POLY_SIZE]);


void poly_frommsg(poly * r, const uint8_t msg[ML_RH_SIZE]);

void poly_tomsg(uint8_t msg[ML_RH_SIZE], poly * r);


void poly_getnoise_eta1(poly * r, const uint8_t seed[ML_RH_SIZE], uint8_t nonce, size_t eta1);


void poly_getnoise_eta2(poly * r, const uint8_t seed[ML_RH_SIZE], uint8_t nonce);


void poly_ntt(poly * r);

void poly_invntt_tomont(poly * r);

void poly_basemul_montgomery(poly * r, const poly * a, const poly * b);

void poly_tomont(poly * r);


void poly_reduce(poly * r);

void poly_csubq(poly * r);


void poly_add(poly * r, const poly * a, const poly * b);

void poly_sub(poly * r, const poly * a, const poly * b);
