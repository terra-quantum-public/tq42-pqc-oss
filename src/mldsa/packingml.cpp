#include "packingml.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"

namespace mldsa
{

void pack_pkMldsa(uint8_t pk[], const uint8_t rho[SEEDBYTES], const poly * t1, uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        pk[i] = rho[i];
    pk += SEEDBYTES;

    for (i = 0; i < modeK; ++i)
        polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1[i]);
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
void unpack_pkMldsa(uint8_t rho[SEEDBYTES], poly * t1, const uint8_t pk[], uint8_t modeK)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = pk[i];
    pk += SEEDBYTES;

    for (i = 0; i < modeK; ++i)
        polyt1_unpack(&t1[i], pk + i * POLYT1_PACKEDBYTES);
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
    uint8_t sk[], const uint8_t rho[SEEDBYTES], const uint8_t tr[2 * SEEDBYTES], const uint8_t key[SEEDBYTES],
    const poly * t0, const poly * s1, const poly * s2, uint8_t modeK
)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = rho[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = key[i];
    sk += SEEDBYTES;

    for (i = 0; i < 2 * SEEDBYTES; ++i)
        sk[i] = tr[i];
    sk += 2 * SEEDBYTES;

    if (modeK == K_87)
    {
        for (i = 0; i < L_87; ++i)
            polyeta_pack_87(sk + i * POLYETA_PACKEDBYTES_87, &s1[i]);
        sk += L_87 * POLYETA_PACKEDBYTES_87;

        for (i = 0; i < K_87; ++i)
            polyeta_pack_87(sk + i * POLYETA_PACKEDBYTES_87, &s2[i]);
        sk += K_87 * POLYETA_PACKEDBYTES_87;

        for (i = 0; i < K_87; ++i)
            polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0[i]);
    }
    else if (modeK == K_65)
    {
        for (i = 0; i < L_65; ++i)
            polyeta_pack_65(sk + i * POLYETA_PACKEDBYTES_65, &s1[i]);
        sk += L_65 * POLYETA_PACKEDBYTES_65;

        for (i = 0; i < K_65; ++i)
            polyeta_pack_65(sk + i * POLYETA_PACKEDBYTES_65, &s2[i]);
        sk += K_65 * POLYETA_PACKEDBYTES_65;

        for (i = 0; i < K_65; ++i)
            polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0[i]);
    }
    else
    {
        for (i = 0; i < L_44; ++i)
            polyeta_pack_44(sk + i * POLYETA_PACKEDBYTES_44, &s1[i]);
        sk += L_44 * POLYETA_PACKEDBYTES_44;

        for (i = 0; i < K_44; ++i)
            polyeta_pack_44(sk + i * POLYETA_PACKEDBYTES_44, &s2[i]);
        sk += K_44 * POLYETA_PACKEDBYTES_44;

        for (i = 0; i < K_44; ++i)
            polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0[i]);
    }
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
    uint8_t rho[SEEDBYTES], uint8_t tr[2 * SEEDBYTES], uint8_t key[SEEDBYTES], poly * t0, poly * s1, poly * s2,
    const uint8_t sk[], uint8_t modeK
)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        key[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < 2 * SEEDBYTES; ++i)
        tr[i] = sk[i];
    sk += 2 * SEEDBYTES;


    if (modeK == K_87)
    {
        for (i = 0; i < L_87; ++i)
            polyeta_unpack_87(&s1[i], sk + i * POLYETA_PACKEDBYTES_87);
        sk += L_87 * POLYETA_PACKEDBYTES_87;

        for (i = 0; i < K_87; ++i)
            polyeta_unpack_87(&s2[i], sk + i * POLYETA_PACKEDBYTES_87);
        sk += K_87 * POLYETA_PACKEDBYTES_87;

        for (i = 0; i < K_87; ++i)
            polyt0_unpack(&t0[i], sk + i * POLYT0_PACKEDBYTES);
    }
    else if (modeK == K_65)
    {
        for (i = 0; i < L_65; ++i)
            polyeta_unpack_65(&s1[i], sk + i * POLYETA_PACKEDBYTES_65);
        sk += L_65 * POLYETA_PACKEDBYTES_65;

        for (i = 0; i < K_65; ++i)
            polyeta_unpack_65(&s2[i], sk + i * POLYETA_PACKEDBYTES_65);
        sk += K_65 * POLYETA_PACKEDBYTES_65;

        for (i = 0; i < K_65; ++i)
            polyt0_unpack(&t0[i], sk + i * POLYT0_PACKEDBYTES);
    }
    else
    {
        for (i = 0; i < L_44; ++i)
            polyeta_unpack_44(&s1[i], sk + i * POLYETA_PACKEDBYTES_44);
        sk += L_44 * POLYETA_PACKEDBYTES_44;

        for (i = 0; i < K_44; ++i)
            polyeta_unpack_44(&s2[i], sk + i * POLYETA_PACKEDBYTES_44);
        sk += K_44 * POLYETA_PACKEDBYTES_44;

        for (i = 0; i < K_44; ++i)
            polyt0_unpack(&t0[i], sk + i * POLYT0_PACKEDBYTES);
    }
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
void pack_sigMldsa(uint8_t sig[], const uint8_t c[], const poly * z, const poly * h, uint8_t modeK)
{
    unsigned int CTILDEBYTES, varribleL, OMEGA_varrible, POLYZ_PACKEDBYTES_varrible;
    if (modeK == K_87)
    {
        CTILDEBYTES = CTILDEBYTES_87;
        varribleL = L_87;
        OMEGA_varrible = OMEGA_87;
        POLYZ_PACKEDBYTES_varrible = POLYZ_PACKEDBYTES_87;
    }
    else if (modeK == K_65)
    {
        CTILDEBYTES = CTILDEBYTES_65;
        varribleL = L_65;
        OMEGA_varrible = OMEGA_65;
        POLYZ_PACKEDBYTES_varrible = POLYZ_PACKEDBYTES_65;
    }
    else
    {
        CTILDEBYTES = CTILDEBYTES_44;
        varribleL = L_44;
        OMEGA_varrible = OMEGA_44;
        POLYZ_PACKEDBYTES_varrible = POLYZ_PACKEDBYTES_44;
    }

    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES; ++i)
        sig[i] = c[i];
    sig += CTILDEBYTES;

    if (modeK == K_87)
    {
        for (i = 0; i < varribleL; ++i)
            polyz_pack_87(sig + i * POLYZ_PACKEDBYTES_varrible, &z[i]);
    }
    else if (modeK == K_65)
    {
        for (i = 0; i < varribleL; ++i)
            polyz_pack_65(sig + i * POLYZ_PACKEDBYTES_varrible, &z[i]);
    }
    else
    {
        for (i = 0; i < varribleL; ++i)
            polyz_pack_44(sig + i * POLYZ_PACKEDBYTES_varrible, &z[i]);
    }
    sig += varribleL * POLYZ_PACKEDBYTES_varrible;

    /* Encode h */
    for (i = 0; i < OMEGA_varrible + static_cast<unsigned int>(modeK); ++i)
        sig[i] = 0;

    k = 0;
    for (i = 0; i < modeK; ++i)
    {
        for (j = 0; j < N; ++j)
            if (h[i].coeffs[j] != 0)
                sig[k++] = (uint8_t)j;

        sig[OMEGA_varrible + i] = (uint8_t)k;
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


int unpack_sigMldsa(uint8_t c[], poly * z, poly * h, const uint8_t sig[], uint8_t modeK)
{
    unsigned int CTILDEBYTES, varribleL, OMEGA_varrible, POLYZ_PACKEDBYTES_varrible;
    if (modeK == K_87)
    {
        CTILDEBYTES = CTILDEBYTES_87;
        varribleL = L_87;
        OMEGA_varrible = OMEGA_87;
        POLYZ_PACKEDBYTES_varrible = POLYZ_PACKEDBYTES_87;
    }
    else if (modeK == K_65)
    {
        CTILDEBYTES = CTILDEBYTES_65;
        varribleL = L_65;
        OMEGA_varrible = OMEGA_65;
        POLYZ_PACKEDBYTES_varrible = POLYZ_PACKEDBYTES_65;
    }
    else
    {
        CTILDEBYTES = CTILDEBYTES_44;
        varribleL = L_44;
        OMEGA_varrible = OMEGA_44;
        POLYZ_PACKEDBYTES_varrible = POLYZ_PACKEDBYTES_44;
    }

    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES; ++i)
        c[i] = sig[i];
    sig += CTILDEBYTES;

    if (modeK == K_87)
    {
        for (i = 0; i < varribleL; ++i)
            polyz_unpack_87(&z[i], sig + i * POLYZ_PACKEDBYTES_varrible);
    }
    else if (modeK == K_65)
    {
        for (i = 0; i < varribleL; ++i)
            polyz_unpack_65(&z[i], sig + i * POLYZ_PACKEDBYTES_varrible);
    }
    else
    {
        for (i = 0; i < varribleL; ++i)
            polyz_unpack_44(&z[i], sig + i * POLYZ_PACKEDBYTES_varrible);
    }
    sig += varribleL * POLYZ_PACKEDBYTES_varrible;

    /* Decode h */
    k = 0; // fips 204 Alg 15 step 2
    for (i = 0; i < modeK; ++i)
    {
        for (j = 0; j < N; ++j)
            h[i].coeffs[j] = 0; // fips 204 Alg 15 step 1

        if (sig[OMEGA_varrible + i] < k || sig[OMEGA_varrible + i] > OMEGA_varrible)
        {
            return 1;
        }

        for (j = k; j < sig[OMEGA_varrible + i]; ++j)
        { // fips 204 Alg 15 step 6
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1])
            {
                return 1;
            }
            h[i].coeffs[sig[j]] = 1; // fips 204 Alg 15 step 7
        }
        k = sig[OMEGA_varrible + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for (j = k; j < OMEGA_varrible; ++j)
        if (sig[j])
        {
            return 1;
        }
    return 0;
}

} // namespace mldsa
