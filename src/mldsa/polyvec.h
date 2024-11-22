#pragma once

#include "params.h"
#include "poly.h"
#include <stdint.h>

namespace mldsa
{

/* Vectors of polynomials of length L */
// typedef struct
//{
//     poly vec[L_87];
// } polyvecl;
//------------------------
typedef struct
{
    poly vec[L_87];
} polyvecl_87;
typedef struct
{
    poly vec[L_65];
} polyvecl_65;

typedef struct
{
    poly vec[L_44];
} polyvecl_44;
//------------------------
typedef struct
{
    poly vec[K_87];
} polyveck_87;

typedef struct
{
    poly vec[K_65];
} polyveck_65;

typedef struct
{
    poly vec[K_44];
} polyveck_44;
//------------------------

void polyvecl_uniform_etaMldsa(poly * v, const uint8_t seed[2 * SEEDBYTES], uint16_t nonce, uint8_t modeL);
void polyveck_uniform_etaMldsa(poly * v, const uint8_t seed[2 * SEEDBYTES], uint16_t nonce, uint8_t modeK);

// only dilithium function
// void polyvecl_uniform_eta(polyvecl * v, const uint8_t seed[SEEDBYTES], uint16_t nonce, uint8_t mode);

// void polyvecl_uniform_gamma1(poly * v, const uint8_t seed[SEEDBYTES], uint16_t nonce, uint8_t mode);

void polyvecl_reduce(poly * v, uint8_t mode);

// void polyvecl_freeze(polyvecl * v, uint8_t mode);

void polyvecl_add(poly * w, const poly * u, const poly * v, uint8_t mode);

void polyvecl_ntt(poly * v, uint8_t mode);
void polyvecl_invntt_tomont(poly * v, uint8_t mode);
void polyvecl_pointwise_poly_montgomery(poly * r, const poly * a, const poly * v, uint8_t mode);
// void polyvecl_pointwise_acc_montgomery(poly * w, const polyvecl * u, const polyvecl * v, uint8_t mode);
void polyvecl_pointwise_acc_montgomery_87(poly * w, const polyvecl_87 * u, const poly * v, uint8_t modeL);
void polyvecl_pointwise_acc_montgomery_65(poly * w, const polyvecl_65 * u, const poly * v, uint8_t modeL);
void polyvecl_pointwise_acc_montgomery_44(poly * w, const polyvecl_44 * u, const poly * v, uint8_t modeL);

int polyvecl_chknorm(const poly * v, int32_t B, uint8_t mode);

/* Vectors of polynomials of length K */
// typedef struct
//{
//     poly vec[K_87];
// } polyveck;

// only dilithium function
// void polyveck_uniform_eta(polyveck * v, const uint8_t seed[SEEDBYTES], uint16_t nonce, uint8_t mode);

void polyveck_reduce(poly * v, uint8_t mode);
void polyveck_caddq(poly * v, uint8_t mode);
// void polyveck_freeze(polyveck * v, uint8_t mode);

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

void polyveck_pack_w1(uint8_t r[], const poly * w1, uint8_t mode);

// void polyvec_matrix_expand(polyvecl mat[], const uint8_t rho[SEEDBYTES], uint8_t mode);
void polyvec_matrix_expand_87(polyvecl_87 mat[K_87], const uint8_t rho[SEEDBYTES], uint8_t mode);
void polyvec_matrix_expand_65(polyvecl_65 mat[K_65], const uint8_t rho[SEEDBYTES], uint8_t mode);
void polyvec_matrix_expand_44(polyvecl_44 mat[K_44], const uint8_t rho[SEEDBYTES], uint8_t mode);

// void polyvec_matrix_pointwise_montgomery(polyveck * t, const polyvecl mat[K], const polyvecl * v, uint8_t modeK);
void polyvec_matrix_pointwise_montgomery_87(poly * t, const polyvecl_87 mat[K_87], const poly * v, uint8_t modeK);
void polyvec_matrix_pointwise_montgomery_65(poly * t, const polyvecl_65 mat[K_65], const poly * v, uint8_t modeK);
void polyvec_matrix_pointwise_montgomery_44(poly * t, const polyvecl_44 mat[K_44], const poly * v, uint8_t modeK);


void polyvecl_uniform_gamma1Mldsa_44(polyvecl_44 * v, const uint8_t seed[2 * SEEDBYTES], uint16_t nonce, uint8_t mode);
void polyvecl_uniform_gamma1Mldsa_65(polyvecl_65 * v, const uint8_t seed[2 * SEEDBYTES], uint16_t nonce, uint8_t mode);
void polyvecl_uniform_gamma1Mldsa_87(polyvecl_87 * v, const uint8_t seed[2 * SEEDBYTES], uint16_t nonce, uint8_t mode);

} // namespace mldsa
