#include "polyvec.h"
#include "params.h"
#include "poly.h"
#include <stdint.h>

namespace dilithium
{

/*************************************************
 * Name:        expand_mat
 *
 * Description: Implementation of ExpandA. Generates matrix A with uniformly
 *              random coefficients a_{i,j} by performing rejection
 *              sampling on the output stream of SHAKE128(rho|j|i)
 *              or AES256CTR(rho,j|i).
 *
 * Arguments:   - polyvecl mat[K]: output matrix
 *              - const uint8_t rho[]: byte array containing seed rho
 **************************************************/


void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES], uint8_t modeK)
{
    unsigned int i, j;
    for (i = 0; i < modeK; ++i)
        for (j = 0; j < L; ++j)
            poly_uniform(&mat[i].vec[j], rho, static_cast<uint16_t>((i << 8) + j));
}

void polyvec_matrix_pointwise_montgomery(polyveck * t, const polyvecl mat[K], const polyvecl * v, uint8_t modeK)
{
    unsigned int i;
    for (i = 0; i < modeK; ++i)
        polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v, L);
}


/**************************************************************/
/************ Vectors of polynomials of length L **************/
/**************************************************************/

void polyvecl_uniform_eta(polyvecl * v, const uint8_t seed[SEEDBYTES], uint16_t nonce, uint8_t modeL)
{
    unsigned int i;

    for (i = 0; i < modeL; ++i)
        poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void polyvecl_uniform_gamma1(poly * v, const uint8_t seed[SEEDBYTES], uint16_t nonce, uint8_t modeL)
{
    unsigned int i;

    for (i = 0; i < modeL; ++i)
        poly_uniform_gamma1(&v[i], seed, static_cast<uint16_t>(modeL * nonce + i));
}

void polyvecl_reduce(poly * v, uint8_t modeL)
{
    unsigned int i;

    for (i = 0; i < modeL; ++i)
        poly_reduce(&v[i]);
}

/*************************************************
 * Name:        polyvecl_freeze
 *
 * Description: Reduce coefficients of polynomials in vector of length L
 *              to standard representatives.
 *
 * Arguments:   - polyvecl *v: pointer to input/output vector
 **************************************************/
void polyvecl_freeze(polyvecl * v, uint8_t modeL)
{
    unsigned int i;

    for (i = 0; i < modeL; ++i)
        poly_freeze(&v->vec[i]);
}

/*************************************************
 * Name:        polyvecl_add
 *
 * Description: Add vectors of polynomials of length L.
 *              No modular reduction is performed.
 *
 * Arguments:   - polyvecl *w: pointer to output vector
 *              - const polyvecl *u: pointer to first summand
 *              - const polyvecl *v: pointer to second summand
 **************************************************/
void polyvecl_add(poly * w, const poly * u, const poly * v, uint8_t modeL)
{
    unsigned int i;

    for (i = 0; i < modeL; ++i)
        poly_add(&w[i], &u[i], &v[i]);
}

/*************************************************
 * Name:        polyvecl_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length L. Output
 *              coefficients can be up to 16*Q larger than input coefficients.
 *
 * Arguments:   - polyvecl *v: pointer to input/output vector
 **************************************************/
void polyvecl_ntt(poly * v, uint8_t modeL)
{
    unsigned int i;

    for (i = 0; i < modeL; ++i)
        poly_ntt(&v[i]);
}

void polyvecl_invntt_tomont(poly * v, uint8_t modeL)
{
    unsigned int i;

    for (i = 0; i < modeL; ++i)
        poly_invntt_tomont(&v[i]);
}

void polyvecl_pointwise_poly_montgomery(poly * r, const poly * a, const poly * v, uint8_t modeL)
{
    unsigned int i;

    for (i = 0; i < modeL; ++i)
        poly_pointwise_montgomery(&r[i], a, &v[i]);
}

/*************************************************
 * Name:        polyvecl_pointwise_acc_montgomery
 *
 * Description: Pointwise multiply vectors of polynomials of length L, multiply
 *              resulting vector by 2^{-32} and add (accumulate) polynomials
 *              in it. Input/output vectors are in NTT domain representation.
 *
 * Arguments:   - poly *w: output polynomial
 *              - const polyvecl *u: pointer to first input vector
 *              - const polyvecl *v: pointer to second input vector
 **************************************************/
void polyvecl_pointwise_acc_montgomery(poly * w, const polyvecl * u, const polyvecl * v, uint8_t modeL)
{
    unsigned int i;
    poly t;

    poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (i = 1; i < modeL; ++i)
    {
        poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        poly_add(w, w, &t);
    }
}

/*************************************************
 * Name:        polyvecl_chknorm
 *
 * Description: Check infinity norm of polynomials in vector of length L.
 *              Assumes input polyvecl to be reduced by polyvecl_reduce().
 *
 * Arguments:   - const polyvecl *v: pointer to vector
 *              - int32_t B: norm bound
 *
 * Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
 * and 1 otherwise.
 **************************************************/
int polyvecl_chknorm(const poly * v, int32_t bound, uint8_t modeL)
{
    unsigned int i;

    for (i = 0; i < modeL; ++i)
        if (poly_chknorm(&v[i], bound))
            return 1;

    return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

void polyveck_uniform_eta(polyveck * v, const uint8_t seed[SEEDBYTES], uint16_t nonce, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_uniform_eta(&v->vec[i], seed, nonce++);
}

/*************************************************
 * Name:        polyveck_reduce
 *
 * Description: Reduce coefficients of polynomials in vector of length K
 *              to representatives in [-6283009,6283007].
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_reduce(poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_reduce(&v[i]);
}

/*************************************************
 * Name:        polyveck_caddq
 *
 * Description: For all coefficients of polynomials in vector of length K
 *              add Q if coefficient is negative.
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_caddq(poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_caddq(&v[i]);
}

/*************************************************
 * Name:        polyveck_freeze
 *
 * Description: Reduce coefficients of polynomials in vector of length K
 *              to standard representatives.
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_freeze(polyveck * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_freeze(&v->vec[i]);
}

/*************************************************
 * Name:        polyveck_add
 *
 * Description: Add vectors of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - polyveck *w: pointer to output vector
 *              - const polyveck *u: pointer to first summand
 *              - const polyveck *v: pointer to second summand
 **************************************************/
void polyveck_add(poly * w, const poly * u, const poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_add(&w[i], &u[i], &v[i]);
}

/*************************************************
 * Name:        polyveck_sub
 *
 * Description: Subtract vectors of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - polyveck *w: pointer to output vector
 *              - const polyveck *u: pointer to first input vector
 *              - const polyveck *v: pointer to second input vector to be
 *                                   subtracted from first input vector
 **************************************************/
void polyveck_sub(poly * w, const poly * u, const poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_sub(&w[i], &u[i], &v[i]);
}

/*************************************************
 * Name:        polyveck_shiftl
 *
 * Description: Multiply vector of polynomials of Length K by 2^D without modular
 *              reduction. Assumes input coefficients to be less than 2^{31-D}.
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_shiftl(poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_shiftl(&v[i]);
}

/*************************************************
 * Name:        polyveck_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length K. Output
 *              coefficients can be up to 16*Q larger than input coefficients.
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_ntt(poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_ntt(&v[i]);
}

/*************************************************
 * Name:        polyveck_invntt_tomont
 *
 * Description: Inverse NTT and multiplication by 2^{32} of polynomials
 *              in vector of length K. Input coefficients need to be less
 *              than 2*Q.
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_invntt_tomont(poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_invntt_tomont(&v[i]);
}

void polyveck_pointwise_poly_montgomery(poly * r, const poly * a, const poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_pointwise_montgomery(&r[i], a, &v[i]);
}


/*************************************************
 * Name:        polyveck_chknorm
 *
 * Description: Check infinity norm of polynomials in vector of length K.
 *              Assumes input polyveck to be reduced by polyveck_reduce().
 *
 * Arguments:   - const polyveck *v: pointer to vector
 *              - int32_t B: norm bound
 *
 * Returns 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
 * and 1 otherwise.
 **************************************************/
int polyveck_chknorm(const poly * v, int32_t bound, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        if (poly_chknorm(&v[i], bound))
            return 1;

    return 0;
}

/*************************************************
 * Name:        polyveck_power2round
 *
 * Description: For all coefficients a of polynomials in vector of length K,
 *              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
 *              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
 *              standard representatives.
 *
 * Arguments:   - polyveck *v1: pointer to output vector of polynomials with
 *                              coefficients a1
 *              - polyveck *v0: pointer to output vector of polynomials with
 *                              coefficients a0
 *              - const polyveck *v: pointer to input vector
 **************************************************/
void polyveck_power2round(poly * v1, poly * v0, const poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_power2round(&v1[i], &v0[i], &v[i]);
}

/*************************************************
 * Name:        polyveck_decompose
 *
 * Description: For all coefficients a of polynomials in vector of length K,
 *              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
 *              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
 *              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
 *              Assumes coefficients to be standard representatives.
 *
 * Arguments:   - polyveck *v1: pointer to output vector of polynomials with
 *                              coefficients a1
 *              - polyveck *v0: pointer to output vector of polynomials with
 *                              coefficients a0
 *              - const polyveck *v: pointer to input vector
 **************************************************/
void polyveck_decompose(poly * v1, poly * v0, const poly * v, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_decompose(&v1[i], &v0[i], &v[i]);
}

/*************************************************
 * Name:        polyveck_make_hint
 *
 * Description: Compute hint vector.
 *
 * Arguments:   - polyveck *h: pointer to output vector
 *              - const polyveck *v0: pointer to low part of input vector
 *              - const polyveck *v1: pointer to high part of input vector
 *
 * Returns number of 1 bits.
 **************************************************/
unsigned int polyveck_make_hint(poly * h, const poly * v0, const poly * v1, uint8_t modeK)
{
    unsigned int i, s = 0;

    for (i = 0; i < modeK; ++i)
        s += poly_make_hint(&h[i], &v0[i], &v1[i]);

    return s;
}

/*************************************************
 * Name:        polyveck_use_hint
 *
 * Description: Use hint vector to correct the high bits of input vector.
 *
 * Arguments:   - polyveck *w: pointer to output vector of polynomials with
 *                             corrected high bits
 *              - const polyveck *u: pointer to input vector
 *              - const polyveck *h: pointer to input hint vector
 **************************************************/
void polyveck_use_hint(poly * w, const poly * u, const poly * h, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        poly_use_hint(&w[i], &u[i], &h[i]);
}

void polyveck_pack_w1(uint8_t r[K * POLYW1_PACKEDBYTES], const poly * w1, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < modeK; ++i)
        polyw1_pack(&r[i * POLYW1_PACKEDBYTES], &w1[i]);
}

void polyvecl_uniform_gamma1Mldsa(polyvecl * v, const uint8_t seed[2 * SEEDBYTES], uint16_t nonce, uint8_t modeL)
{
    uint16_t i;

    for (i = 0; i < modeL; ++i)
        poly_uniform_gamma1Mldsa(&v->vec[i], seed, L * nonce + i);
}

} // namespace dilithium
