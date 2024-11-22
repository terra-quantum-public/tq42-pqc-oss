#pragma once

#include "params.h"
#include "poly.h"
#include <stdint.h>

namespace dilithium
{

/* Vectors of polynomials of length L */
typedef struct
{
    poly vec[L];
} polyvecl;


// only dilithium function
void polyvecl_uniform_eta(polyvecl * v, const uint8_t seed[SEEDBYTES], uint16_t nonce, uint8_t mode);

void polyvecl_uniform_gamma1(poly * v, const uint8_t seed[SEEDBYTES], uint16_t nonce, uint8_t mode);

void polyvecl_reduce(poly * v, uint8_t mode);

void polyvecl_freeze(polyvecl * v, uint8_t mode);

void polyvecl_add(poly * w, const poly * u, const poly * v, uint8_t mode);

void polyvecl_ntt(poly * v, uint8_t mode);
void polyvecl_invntt_tomont(poly * v, uint8_t mode);
void polyvecl_pointwise_poly_montgomery(poly * r, const poly * a, const poly * v, uint8_t mode);
void polyvecl_pointwise_acc_montgomery(poly * w, const polyvecl * u, const polyvecl * v, uint8_t mode);

int polyvecl_chknorm(const poly * v, int32_t B, uint8_t mode);

/* Vectors of polynomials of length K */
typedef struct
{
    poly vec[K];
} polyveck;

// only dilithium function
void polyveck_uniform_eta(polyveck * v, const uint8_t seed[SEEDBYTES], uint16_t nonce, uint8_t mode);

void polyveck_reduce(poly * v, uint8_t mode);
void polyveck_caddq(poly * v, uint8_t mode);
void polyveck_freeze(polyveck * v, uint8_t mode);

void polyveck_add(poly * w, const poly * u, const poly * v, uint8_t mode);
void polyveck_sub(poly * w, const poly * u, const poly * v, uint8_t mode);
void polyveck_shiftl(poly * v, uint8_t mode);

void polyveck_ntt(poly * v, uint8_t mode);
void polyveck_invntt_tomont(poly * v, uint8_t mode);
void polyveck_pointwise_poly_montgomery(poly * r, const poly * a, const poly * v, uint8_t mode);

int polyveck_chknorm(const poly * v, int32_t B, uint8_t mode);

void polyveck_power2round(poly * v1, poly * v0, const poly * v, uint8_t mode);
void polyveck_decompose(poly * v1, poly * v0, const poly * v, uint8_t mode);
unsigned int polyveck_make_hint(poly * h, const poly * v0, const poly * v1, uint8_t mode);
void polyveck_use_hint(poly * w, const poly * v, const poly * h, uint8_t mode);

void polyveck_pack_w1(uint8_t r[K * POLYW1_PACKEDBYTES], const poly * w1, uint8_t mode);

void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES], uint8_t mode);

void polyvec_matrix_pointwise_montgomery(polyveck * t, const polyvecl mat[K], const polyvecl * v, uint8_t modeK);


void polyvecl_uniform_gamma1Mldsa(polyvecl * v, const uint8_t seed[2 * SEEDBYTES], uint16_t nonce, uint8_t mode);

} // namespace dilithium
