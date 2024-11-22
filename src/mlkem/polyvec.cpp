#include "polyvec.h"
#include "params.h"
#include "poly.h"
#include <cassert>
#include <stdint.h>

/*************************************************
 * Name:        polyvec_compress
 *
 * Description: Compress and serialize vector of polynomials
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *              - polyvec *a: pointer to input vector of polynomials
 **************************************************/
void polyvec_compress(uint8_t * r, size_t r_size, polyvec * a, size_t param_k)
{
    assert((r_size == param_k * 352) || (r_size == param_k * 320));

    unsigned int i, j, k;

    polyvec_csubq(a);

    if (r_size == (param_k * 352))
    {
        uint16_t t[8];
        for (i = 0; i < param_k; i++)
        {
            for (j = 0; j < ML_N / 8; j++)
            {
                for (k = 0; k < 8; k++)
                    t[k] = ((((uint32_t)(*a)[i].coeffs[8 * j + k] << 11) + ML_Q / 2) / ML_Q) & 0x7ff;

                r[0] = static_cast<uint8_t>(t[0] >> 0);
                r[1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 3));
                r[2] = static_cast<uint8_t>((t[1] >> 5) | (t[2] << 6));
                r[3] = static_cast<uint8_t>(t[2] >> 2);
                r[4] = static_cast<uint8_t>((t[2] >> 10) | (t[3] << 1));
                r[5] = static_cast<uint8_t>((t[3] >> 7) | (t[4] << 4));
                r[6] = static_cast<uint8_t>((t[4] >> 4) | (t[5] << 7));
                r[7] = static_cast<uint8_t>(t[5] >> 1);
                r[8] = static_cast<uint8_t>((t[5] >> 9) | (t[6] << 2));
                r[9] = static_cast<uint8_t>((t[6] >> 6) | (t[7] << 5));
                r[10] = static_cast<uint8_t>(t[7] >> 3);
                r += 11;
            }
        }
    }
    else // if (r_size == (param_k * 320))
    {
        uint16_t t[4];
        for (i = 0; i < param_k; i++)
        {
            for (j = 0; j < ML_N / 4; j++)
            {
                for (k = 0; k < 4; k++)
                    t[k] = ((((uint32_t)(*a)[i].coeffs[4 * j + k] << 10) + ML_Q / 2) / ML_Q) & 0x3ff;

                r[0] = static_cast<uint8_t>(t[0] >> 0);
                r[1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 2));
                r[2] = static_cast<uint8_t>((t[1] >> 6) | (t[2] << 4));
                r[3] = static_cast<uint8_t>((t[2] >> 4) | (t[3] << 6));
                r[4] = static_cast<uint8_t>((t[3] >> 2));
                r += 5;
            }
        }
    }
}

/*************************************************
 * Name:        polyvec_decompress
 *
 * Description: De-serialize and decompress vector of polynomials;
 *              approximate inverse of polyvec_compress
 *
 * Arguments:   - polyvec *r:       pointer to output vector of polynomials
 *              - const uint8_t *a: pointer to input byte array
 **************************************************/
void polyvec_decompress(polyvec * r, const uint8_t * a, size_t a_size, size_t param_k)
{
    assert((a_size == param_k * 352) || (a_size == param_k * 320));

    unsigned int i, j, k;

    if (a_size == (param_k * 352))
    {
        uint16_t t[8];
        for (i = 0; i < param_k; i++)
        {
            for (j = 0; j < ML_N / 8; j++)
            {
                t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
                t[1] = (a[1] >> 3) | ((uint16_t)a[2] << 5);
                t[2] = (a[2] >> 6) | ((uint16_t)a[3] << 2) | ((uint16_t)a[4] << 10);
                t[3] = (a[4] >> 1) | ((uint16_t)a[5] << 7);
                t[4] = (a[5] >> 4) | ((uint16_t)a[6] << 4);
                t[5] = (a[6] >> 7) | ((uint16_t)a[7] << 1) | ((uint16_t)a[8] << 9);
                t[6] = (a[8] >> 2) | ((uint16_t)a[9] << 6);
                t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
                a += 11;

                for (k = 0; k < 8; k++)
                    (*r)[i].coeffs[8 * j + k] = ((uint32_t)(t[k] & 0x7FF) * ML_Q + 1024) >> 11;
            }
        }
    }
    else // if (a_size == (param_k * 320))
    {
        uint16_t t[4];
        for (i = 0; i < param_k; i++)
        {
            for (j = 0; j < ML_N / 4; j++)
            {
                t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
                t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
                t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
                t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
                a += 5;

                for (k = 0; k < 4; k++)
                    (*r)[i].coeffs[4 * j + k] = ((uint32_t)(t[k] & 0x3FF) * ML_Q + 512) >> 10;
            }
        }
    }
}

/*************************************************
 * Name:        polyvec_tobytes
 *
 * Description: Serialize vector of polynomials
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *              - polyvec *a: pointer to input vector of polynomials
 **************************************************/
void polyvec_tobytes(uint8_t * r, polyvec * a)
{
    for (size_t i = 0; i < (*a).size(); ++i)
        poly_tobytes(r + i * ML_POLY_SIZE, &((*a)[i]));
}

/*************************************************
 * Name:        polyvec_frombytes
 *
 * Description: De-serialize vector of polynomials;
 *              inverse of polyvec_tobytes
 *
 * Arguments:   - uint8_t *r:       pointer to output byte array
 *              - const polyvec *a: pointer to input vector of polynomials
 **************************************************/
void polyvec_frombytes(polyvec * r, const uint8_t * a)
{
    for (size_t i = 0; i < (*r).size(); ++i)
        poly_frombytes(&((*r)[i]), a + i * ML_POLY_SIZE);
}

/*************************************************
 * Name:        polyvec_ntt
 *
 * Description: Apply forward NTT to all elements of a vector of polynomials
 *
 * Arguments:   - polyvec *r: pointer to in/output vector of polynomials
 **************************************************/
void polyvec_ntt(polyvec * r)
{
    for (size_t i = 0; i < (*r).size(); ++i)
        poly_ntt(&((*r)[i]));
}

/*************************************************
 * Name:        polyvec_invntt_tomont
 *
 * Description: Apply inverse NTT to all elements of a vector of polynomials
 *              and multiply by Montgomery factor 2^16
 *
 * Arguments:   - polyvec *r: pointer to in/output vector of polynomials
 **************************************************/
void polyvec_invntt_tomont(polyvec * r)
{
    for (size_t i = 0; i < (*r).size(); ++i)
        poly_invntt_tomont(&((*r)[i]));
}

/*************************************************
 * Name:        polyvec_pointwise_acc_montgomery
 *
 * Description: Pointwise multiply elements of a and b, accumulate into r,
 *              and multiply by 2^-16.
 *
 * Arguments: - poly *r:          pointer to output polynomial
 *            - const polyvec *a: pointer to first input vector of polynomials
 *            - const polyvec *b: pointer to second input vector of polynomials
 **************************************************/
void polyvec_pointwise_acc_montgomery(poly * r, const polyvec * a, size_t offset, const polyvec * b)
{
    poly t;

    poly_basemul_montgomery(r, &((*a)[offset + 0]), &((*b)[0]));
    for (size_t i = 1; i < (*b).size(); ++i)
    {
        poly_basemul_montgomery(&t, &((*a)[offset + i]), &((*b)[i]));
        poly_add(r, r, &t);
    }

    poly_reduce(r);
}

/*************************************************
 * Name:        polyvec_reduce
 *
 * Description: Applies Barrett reduction to each coefficient
 *              of each element of a vector of polynomials
 *              for details of the Barrett reduction see comments in reduce.c
 *
 * Arguments:   - poly *r: pointer to input/output polynomial
 **************************************************/
void polyvec_reduce(polyvec * r)
{
    for (size_t i = 0; i < (*r).size(); ++i)
        poly_reduce(&((*r)[i]));
}

/*************************************************
 * Name:        polyvec_csubq
 *
 * Description: Applies conditional subtraction of q to each coefficient
 *              of each element of a vector of polynomials
 *              for details of conditional subtraction of q see comments in
 *              reduce.c
 *
 * Arguments:   - poly *r: pointer to input/output polynomial
 **************************************************/
void polyvec_csubq(polyvec * r)
{
    for (size_t i = 0; i < (*r).size(); ++i)
        poly_csubq(&((*r)[i]));
}

/*************************************************
 * Name:        polyvec_add
 *
 * Description: Add vectors of polynomials
 *
 * Arguments: - polyvec *r:       pointer to output vector of polynomials
 *            - const polyvec *a: pointer to first input vector of polynomials
 *            - const polyvec *b: pointer to second input vector of polynomials
 **************************************************/
void polyvec_add(polyvec * r, const polyvec * a, const polyvec * b)
{
    for (size_t i = 0; i < (*r).size(); ++i)
        poly_add(&((*r)[i]), &((*a)[i]), &((*b)[i]));
}
