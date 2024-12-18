#include "poly.h"
#include "cbd.h"
#include "ntt.h"
#include "params.h"
#include "reduce.h"
#include "symmetric.h"
#include <cassert>
#include <stdint.h>

/*************************************************
 * Name:        poly_compress
 *
 * Description: Compression and subsequent serialization of a polynomial
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *              - poly *a:    pointer to input polynomial
 **************************************************/
void poly_compress(uint8_t * r, size_t r_size, poly * a)
{
    assert((r_size == 128) || (r_size == 160));

    unsigned int i, j;
    uint8_t t[8];

    poly_csubq(a);

    if (r_size == 128)
    {
        for (i = 0; i < ML_N / 8; i++)
        {
            for (j = 0; j < 8; j++)
                t[j] = ((((uint16_t)a->coeffs[8 * i + j] << 4) + ML_Q / 2) / ML_Q) & 15;

            r[0] = t[0] | (t[1] << 4);
            r[1] = t[2] | (t[3] << 4);
            r[2] = t[4] | (t[5] << 4);
            r[3] = t[6] | (t[7] << 4);
            r += 4;
        }
    }
    else // if (r_size == 160)
    {
        for (i = 0; i < ML_N / 8; i++)
        {
            for (j = 0; j < 8; j++)
                t[j] = ((((uint32_t)a->coeffs[8 * i + j] << 5) + ML_Q / 2) / ML_Q) & 31;

            r[0] = (t[0] >> 0) | (t[1] << 5);
            r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            r[2] = (t[3] >> 1) | (t[4] << 4);
            r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            r[4] = (t[6] >> 2) | (t[7] << 3);
            r += 5;
        }
    }
}

/*************************************************
 * Name:        poly_decompress
 *
 * Description: De-serialization and subsequent decompression of a polynomial;
 *              approximate inverse of poly_compress
 *
 * Arguments:   - poly *r:          pointer to output polynomial
 *              - const uint8_t *a: pointer to input byte array
 **************************************************/
void poly_decompress(poly * r, const uint8_t * a, size_t a_size)
{
    assert((a_size == 128) || (a_size == 160));

    unsigned int i;

    if (a_size == 128)
    {
        for (i = 0; i < ML_N / 2; i++)
        {
            r->coeffs[2 * i + 0] = (((uint16_t)(a[0] & 15) * ML_Q) + 8) >> 4;
            r->coeffs[2 * i + 1] = (((uint16_t)(a[0] >> 4) * ML_Q) + 8) >> 4;
            a += 1;
        }
    }
    else // if (a_size == 160)
    {
        unsigned int j;
        uint8_t t[8];
        for (i = 0; i < ML_N / 8; i++)
        {
            t[0] = (a[0] >> 0);
            t[1] = (a[0] >> 5) | (a[1] << 3);
            t[2] = (a[1] >> 2);
            t[3] = (a[1] >> 7) | (a[2] << 1);
            t[4] = (a[2] >> 4) | (a[3] << 4);
            t[5] = (a[3] >> 1);
            t[6] = (a[3] >> 6) | (a[4] << 2);
            t[7] = (a[4] >> 3);
            a += 5;

            for (j = 0; j < 8; j++)
                r->coeffs[8 * i + j] = ((uint32_t)(t[j] & 31) * ML_Q + 16) >> 5;
        }
    }
}

/*************************************************
 * Name:        poly_tobytes
 *
 * Description: Serialization of a polynomial
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *                            (needs space for ML_POLY_SIZE bytes)
 *              - poly *a:    pointer to input polynomial
 **************************************************/
void poly_tobytes(uint8_t r[ML_POLY_SIZE], poly * a)
{
    unsigned int i;

    poly_csubq(a);

    for (i = 0; i < ML_N / 2; i++)
    {
        uint16_t t0 = a->coeffs[2 * i];
        uint16_t t1 = a->coeffs[2 * i + 1];
        r[3 * i + 0] = static_cast<uint8_t>(t0 >> 0);
        r[3 * i + 1] = static_cast<uint8_t>((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = static_cast<uint8_t>(t1 >> 4);
    }
}

/*************************************************
 * Name:        poly_frombytes
 *
 * Description: De-serialization of a polynomial;
 *              inverse of poly_tobytes
 *
 * Arguments:   - poly *r:          pointer to output polynomial
 *              - const uint8_t *a: pointer to input byte array
 *                                  (of ML_POLY_SIZE bytes)
 **************************************************/
void poly_frombytes(poly * r, const uint8_t a[ML_POLY_SIZE])
{
    unsigned int i;
    for (i = 0; i < ML_N / 2; i++)
    {
        r->coeffs[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

/*************************************************
 * Name:        poly_frommsg
 *
 * Description: Convert 32-byte message to polynomial
 *
 * Arguments:   - poly *r:            pointer to output polynomial
 *              - const uint8_t *msg: pointer to input message
 **************************************************/
void poly_frommsg(poly * r, const uint8_t msg[ML_RH_SIZE])
{
    unsigned int i, j;
    int16_t mask;

    for (i = 0; i < ML_N / 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            mask = -(int16_t)((msg[i] >> j) & 1);
            r->coeffs[8 * i + j] = mask & ((ML_Q + 1) / 2);
        }
    }
}

/*************************************************
 * Name:        poly_tomsg
 *
 * Description: Convert polynomial to 32-byte message
 *
 * Arguments:   - uint8_t *msg: pointer to output message
 *              - poly *a:      pointer to input polynomial
 **************************************************/
void poly_tomsg(uint8_t msg[ML_RH_SIZE], poly * a)
{
    unsigned int i, j;
    uint16_t t;

    poly_csubq(a);

    for (i = 0; i < ML_N / 8; i++)
    {
        msg[i] = 0;
        for (j = 0; j < 8; j++)
        {
            t = ((((uint16_t)a->coeffs[8 * i + j] << 1) + ML_Q / 2) / ML_Q) & 1;
            msg[i] |= t << j;
        }
    }
}

/*************************************************
 * Name:        poly_getnoise_eta1
 *
 * Description: Sample a polynomial deterministically from a seed and a nonce,
 *              with output polynomial close to centered binomial distribution
 *              with parameter ETA1
 *
 * Arguments:   - poly *r:             pointer to output polynomial
 *              - const uint8_t *seed: pointer to input seed
 *                                     (of length ML_RH_SIZE bytes)
 *              - uint8_t nonce:       one-byte input nonce
 **************************************************/
void poly_getnoise_eta1(poly * r, const uint8_t seed[ML_RH_SIZE], uint8_t nonce, size_t eta1)
{
    std::vector<uint8_t> buf(eta1 * ML_N / 4);
    // BufferView buf_buf(&buf, ETA1 * ML_N / 4);
    // StackBuffer<33> seed_nonce;
    // ConstBufferView seed_buf(&seed, 32);
    // seed_nonce.mid(0, 32).store(seed_buf);
    // seed_nonce[32] = nonce;
    prf(buf.data(), buf.size(), seed, nonce);
    // function_PRF(seed_nonce, buf_buf);
    cbd_eta1(r, buf.data(), eta1);
}

/*************************************************
 * Name:        poly_getnoise_eta2
 *
 * Description: Sample a polynomial deterministically from a seed and a nonce,
 *              with output polynomial close to centered binomial distribution
 *              with parameter ML_ETA2
 *
 * Arguments:   - poly *r:             pointer to output polynomial
 *              - const uint8_t *seed: pointer to input seed
 *                                     (of length ML_RH_SIZE bytes)
 *              - uint8_t nonce:       one-byte input nonce
 **************************************************/
void poly_getnoise_eta2(poly * r, const uint8_t seed[ML_RH_SIZE], uint8_t nonce)
{
    uint8_t buf[ML_ETA2 * ML_N / 4];
    prf(buf, sizeof(buf), seed, nonce);
    cbd_eta2(r, buf);
}


/*************************************************
 * Name:        poly_ntt
 *
 * Description: Computes negacyclic number-theoretic transform (NTT) of
 *              a polynomial in place;
 *              inputs assumed to be in normal order, output in bitreversed order
 *
 * Arguments:   - uint16_t *r: pointer to in/output polynomial
 **************************************************/
void poly_ntt(poly * r)
{
    ntt(r->coeffs);
    poly_reduce(r);
}

/*************************************************
 * Name:        poly_invntt_tomont
 *
 * Description: Computes inverse of negacyclic number-theoretic transform (NTT)
 *              of a polynomial in place;
 *              inputs assumed to be in bitreversed order, output in normal order
 *
 * Arguments:   - uint16_t *a: pointer to in/output polynomial
 **************************************************/
void poly_invntt_tomont(poly * r) { invntt(r->coeffs); }

/*************************************************
 * Name:        poly_basemul_montgomery
 *
 * Description: Multiplication of two polynomials in NTT domain
 *
 * Arguments:   - poly *r:       pointer to output polynomial
 *              - const poly *a: pointer to first input polynomial
 *              - const poly *b: pointer to second input polynomial
 **************************************************/
void poly_basemul_montgomery(poly * r, const poly * a, const poly * b)
{
    unsigned int i;
    for (i = 0; i < ML_N / 4; i++)
    {
        basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[64 + i]);
        basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2], -zetas[64 + i]);
    }
}

/*************************************************
 * Name:        poly_tomont
 *
 * Description: Inplace conversion of all coefficients of a polynomial
 *              from normal domain to Montgomery domain
 *
 * Arguments:   - poly *r: pointer to input/output polynomial
 **************************************************/
void poly_tomont(poly * r)
{
    unsigned int i;
    const int16_t f = (1ULL << 32) % ML_Q;
    for (i = 0; i < ML_N; i++)
        r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * f);
}

/*************************************************
 * Name:        poly_reduce
 *
 * Description: Applies Barrett reduction to all coefficients of a polynomial
 *              for details of the Barrett reduction see comments in reduce.c
 *
 * Arguments:   - poly *r: pointer to input/output polynomial
 **************************************************/
void poly_reduce(poly * r)
{
    unsigned int i;
    for (i = 0; i < ML_N; i++)
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

/*************************************************
 * Name:        poly_csubq
 *
 * Description: Applies conditional subtraction of q to each coefficient
 *              of a polynomial. For details of conditional subtraction
 *              of q see comments in reduce.c
 *
 * Arguments:   - poly *r: pointer to input/output polynomial
 **************************************************/
void poly_csubq(poly * r)
{
    unsigned int i;
    for (i = 0; i < ML_N; i++)
        r->coeffs[i] = csubq(r->coeffs[i]);
}

/*************************************************
 * Name:        poly_add
 *
 * Description: Add two polynomials
 *
 * Arguments: - poly *r:       pointer to output polynomial
 *            - const poly *a: pointer to first input polynomial
 *            - const poly *b: pointer to second input polynomial
 **************************************************/
void poly_add(poly * r, const poly * a, const poly * b)
{
    unsigned int i;
    for (i = 0; i < ML_N; i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
 * Name:        poly_sub
 *
 * Description: Subtract two polynomials
 *
 * Arguments: - poly *r:       pointer to output polynomial
 *            - const poly *a: pointer to first input polynomial
 *            - const poly *b: pointer to second input polynomial
 **************************************************/
void poly_sub(poly * r, const poly * a, const poly * b)
{
    unsigned int i;
    for (i = 0; i < ML_N; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}
