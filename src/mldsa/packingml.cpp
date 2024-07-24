#include "packingml.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"

namespace mldsa
{

void pack_pkMldsa(
    uint8_t pk[PQC_ML_DSA_PUBLIC_KEY_LEN], // CRYPTO_PUBLICKEYBYTES
    const uint8_t rho[SEEDBYTES], const polyveck * t1
)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        pk[i] = rho[i];
    pk += SEEDBYTES;

    for (i = 0; i < K; ++i)
        polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: Unpack public key pk = (rho, t1).
 *
 * Arguments:   - const uint8_t rho[]: output byte array for rho
 *              - const polyveck *t1: pointer to output vector t1
 *              - uint8_t pk[]: byte array containing bit-packed pk
 **************************************************/
void unpack_pkMldsa(
    uint8_t rho[SEEDBYTES], polyveck * t1,
    const uint8_t pk[PQC_ML_DSA_PUBLIC_KEY_LEN]
) // CRYPTO_PUBLICKEYBYTES
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = pk[i];
    pk += SEEDBYTES;

    for (i = 0; i < K; ++i)
        polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * Arguments:   - uint8_t sk[]: output byte array
 *              - const uint8_t rho[]: byte array containing rho
 *              - const uint8_t tr[]: byte array containing tr
 *              - const uint8_t key[]: byte array containing key
 *              - const polyveck *t0: pointer to vector t0
 *              - const polyvecl *s1: pointer to vector s1
 *              - const polyveck *s2: pointer to vector s2
 **************************************************/
void pack_skMldsa(
    uint8_t sk[PQC_ML_DSA_PRIVATE_KEY_LEN], // #changed CRYPTO_SECRETKEYBYTES],
    const uint8_t rho[SEEDBYTES],
    const uint8_t tr[2 * SEEDBYTES], // #changed CRHBYTES],
    const uint8_t key[SEEDBYTES], const polyveck * t0, const polyvecl * s1, const polyveck * s2
)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = rho[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = key[i];
    sk += SEEDBYTES;

    for (i = 0; i < 2 * SEEDBYTES; ++i) // #changed CRHBYTES
        sk[i] = tr[i];
    sk += 2 * SEEDBYTES; // #changed CRHBYTES;

    for (i = 0; i < L; ++i)
        polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s1->vec[i]);
    sk += L * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; ++i)
        polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s2->vec[i]);
    sk += K * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; ++i)
        polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
}

/*************************************************
 * Name:        unpack_sk
 *
 * Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * Arguments:   - const uint8_t rho[]: output byte array for rho
 *              - const uint8_t tr[]: output byte array for tr
 *              - const uint8_t key[]: output byte array for key
 *              - const polyveck *t0: pointer to output vector t0
 *              - const polyvecl *s1: pointer to output vector s1
 *              - const polyveck *s2: pointer to output vector s2
 *              - uint8_t sk[]: byte array containing bit-packed sk
 **************************************************/
void unpack_skMldsa(
    uint8_t rho[SEEDBYTES],
    uint8_t tr[2 * SEEDBYTES], // #changed     CRHBYTES],
    uint8_t key[SEEDBYTES], polyveck * t0, polyvecl * s1, polyveck * s2,
    const uint8_t sk[PQC_ML_DSA_PRIVATE_KEY_LEN]
) // #changed CRYPTO_SECRETKEYBYTES],
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        key[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < 2 * SEEDBYTES; ++i) // #changed     CRHBYTES
        tr[i] = sk[i];
    sk += 2 * SEEDBYTES; // #changed     CRHBYTES;

    for (i = 0; i < L; ++i)
        polyeta_unpack(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES);
    sk += L * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; ++i)
        polyeta_unpack(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES);
    sk += K * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; ++i)
        polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
}

/*************************************************
 * Name:        pack_sig
 *
 * Description: Bit-pack signature sig = (c, z, h).
 *
 * Arguments:   - uint8_t sig[]: output byte array
 *              - const uint8_t *c: pointer to challenge hash length SEEDBYTES
 *              - const polyvecl *z: pointer to vector z
 *              - const polyveck *h: pointer to hint vector h
 **************************************************/
void pack_sigMldsa(
    uint8_t sig[PQC_ML_DSA_SIGNATURE_LEN], // CRYPTO_BYTES
    const uint8_t c[2 * SEEDBYTES],        // #changed
    const polyvecl * z, const polyveck * h
)
{
    unsigned int i, j, k;

    for (i = 0; i < 2 * SEEDBYTES; ++i)
        sig[i] = c[i];
    sig += 2 * SEEDBYTES;

    for (i = 0; i < L; ++i)
        polyz_pack(sig + i * POLYZ_PACKEDBYTES, &z->vec[i]);
    sig += L * POLYZ_PACKEDBYTES;

    /* Encode h */
    for (i = 0; i < OMEGA + K; ++i)
        sig[i] = 0;

    k = 0;
    for (i = 0; i < K; ++i)
    {
        for (j = 0; j < N; ++j)
            if (h->vec[i].coeffs[j] != 0)
                sig[k++] = (uint8_t)j;

        sig[OMEGA + i] = (uint8_t)k;
    }
}

/*************************************************
 * Name:        unpack_sig
 *
 * Description: Unpack signature sig = (c, z, h).
 *
 * Arguments:   - uint8_t *c: pointer to output challenge hash
 *              - polyvecl *z: pointer to output vector z
 *              - polyveck *h: pointer to output hint vector h
 *              - const uint8_t sig[]: byte array containing
 *                bit-packed signature
 *
 * Returns 1 in case of malformed signature; otherwise 0.
 **************************************************/


int unpack_sigMldsa(
    uint8_t c[2 * SEEDBYTES], // #changed SEEDBYTES
    polyvecl * z, polyveck * h,
    const uint8_t sig[PQC_ML_DSA_SIGNATURE_LEN]
) // CRYPTO_BYTES
{
    unsigned int i, j, k;

    for (i = 0; i < 2 * SEEDBYTES; ++i) // #changed SEEDBYTES
        c[i] = sig[i];
    sig += 2 * SEEDBYTES; // #changed SEEDBYTES

    for (i = 0; i < L; ++i)
        polyz_unpack(&z->vec[i], sig + i * POLYZ_PACKEDBYTES);
    sig += L * POLYZ_PACKEDBYTES;

    /* Decode h */
    k = 0; // fips 204 Alg 15 step 2
    for (i = 0; i < K; ++i)
    {
        for (j = 0; j < N; ++j)
            h->vec[i].coeffs[j] = 0; // fips 204 Alg 15 step 1

        if (sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA)
        {
            return 1;
        }


        for (j = k; j < sig[OMEGA + i]; ++j)
        { // fips 204 Alg 15 step 6
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1])
            {
                return 1;
            }
            h->vec[i].coeffs[sig[j]] = 1; // fips 204 Alg 15 step 7
        }

        k = sig[OMEGA + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for (j = k; j < OMEGA; ++j)
        if (sig[j])
        {
            return 1;
        }
    return 0;
}

} // namespace mldsa
