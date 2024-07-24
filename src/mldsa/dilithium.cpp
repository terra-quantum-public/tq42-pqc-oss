#include "dilithium.h"
#include <rng/rng.h>

#include "fips202.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"

using namespace mldsa;

DilithiumFactory::DilithiumFactory() {}

uint32_t DilithiumFactory::cipher_id() const { return PQC_CIPHER_DILITHIUM; }

std::unique_ptr<PQC_Context> DilithiumFactory::create_context(const ConstBufferView & private_key) const
{
    if (private_key.size() != PQC_DILITHIUM_PRIVATE_KEY_LEN)
    {
        throw BadLength();
    }
    return std::make_unique<DilithiumContext>(
        reinterpret_cast<const pqc_dilithium_private_key *>(private_key.const_data())
    );
}

void DilithiumFactory::generate_keypair(const BufferView & public_key, const BufferView & private_key) const
{

    if (private_key.size() != PQC_DILITHIUM_PRIVATE_KEY_LEN || public_key.size() != PQC_DILITHIUM_PUBLIC_KEY_LEN)
    {
        throw BadLength();
    }
    else
    {
        uint8_t seedbuf[3 * SEEDBYTES];
        uint8_t tr[CRHBYTES];
        const uint8_t *rho, *rhoprime, *key;
        polyvecl mat[K];
        polyvecl s1, s1hat;
        polyveck s2, t1, t0;

        /* Get randomness for rho, rhoprime and key */
        randombytes(BufferView(&seedbuf, SEEDBYTES));
        shake256(seedbuf, 3 * SEEDBYTES, seedbuf, SEEDBYTES);
        rho = seedbuf;
        rhoprime = seedbuf + SEEDBYTES;
        key = seedbuf + 2 * SEEDBYTES;

        /* Expand matrix */
        polyvec_matrix_expand(mat, rho);

        /* Sample short vectors s1 and s2 */
        polyvecl_uniform_eta(&s1, rhoprime, 0);
        polyveck_uniform_eta(&s2, rhoprime, L);

        /* Matrix-vector multiplication */
        s1hat = s1;
        polyvecl_ntt(&s1hat);
        polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
        polyveck_reduce(&t1);
        polyveck_invntt_tomont(&t1);

        /* Add error vector s2 */
        polyveck_add(&t1, &t1, &s2);

        /* Extract t1 and write public key */
        polyveck_caddq(&t1);
        polyveck_power2round(&t1, &t0, &t1);
        pack_pk(public_key.data(), rho, &t1);

        /* Compute CRH(rho, t1) and write secret key */
        crh(tr, public_key.data(), CRYPTO_PUBLICKEYBYTES);
        pack_sk(private_key.data(), rho, tr, key, &t0, &s1, &s2);
    }
}


bool DilithiumFactory::verify(
    const ConstBufferView & public_key, const ConstBufferView buffer, const ConstBufferView signature
) const
{
    if (signature.size() != PQC_DILITHIUM_SIGNATURE_LEN)
    {
        throw BadLength();
    }

    if (public_key.size() != PQC_DILITHIUM_PUBLIC_KEY_LEN)
    {
        throw BadLength();
    }

    unsigned int i;
    uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[SEEDBYTES];
    uint8_t c2[SEEDBYTES];
    poly cp;
    polyvecl mat[K], z;
    polyveck t1, w1, h;
    keccak_state state;

    unpack_pk(rho, &t1, public_key.const_data());
    if (unpack_sig(c, &z, &h, signature.const_data()))
        return false;
    if (polyvecl_chknorm(&z, GAMMA1 - BETA))
        return false;

    /* Compute CRH(CRH(rho, t1), msg) */
    crh(mu, public_key.const_data(), CRYPTO_PUBLICKEYBYTES);
    shake256_init(&state);
    shake256_absorb(&state, mu, CRHBYTES);
    shake256_absorb(&state, buffer.const_data(), buffer.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, CRHBYTES, &state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challenge(&cp, c);
    polyvec_matrix_expand(mat, rho);

    polyvecl_ntt(&z);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    poly_ntt(&cp);
    polyveck_shiftl(&t1);
    polyveck_ntt(&t1);
    polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    polyveck_sub(&w1, &w1, &t1);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);

    /* Reconstruct w1 */
    polyveck_caddq(&w1);
    polyveck_use_hint(&w1, &w1, &h);
    polyveck_pack_w1(buf, &w1);

    /* Call random oracle and verify challenge */
    shake256_init(&state);
    shake256_absorb(&state, mu, CRHBYTES);
    shake256_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(c2, SEEDBYTES, &state);
    for (i = 0; i < SEEDBYTES; ++i)
        if (c[i] != c2[i])
            return false;

    return true;
}


size_t DilithiumFactory::get_length(uint32_t type) const
{
    switch (type)
    {
    case PQC_LENGTH_PUBLIC:
        return PQC_DILITHIUM_PUBLIC_KEY_LEN;
    case PQC_LENGTH_PRIVATE:
        return PQC_DILITHIUM_PRIVATE_KEY_LEN;
    case PQC_LENGTH_SIGNATURE:
        return PQC_DILITHIUM_SIGNATURE_LEN;
    }
    return 0;
}

size_t DilithiumContext::get_length(uint32_t type) const { return DilithiumFactory().get_length(type); }


void DilithiumContext::sign(const ConstBufferView & buffer, const BufferView & signature) const
{
    if (signature.size() != PQC_DILITHIUM_SIGNATURE_LEN)
    {
        throw BadLength();
    }

    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + 3 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    keccak_state state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + CRHBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    unpack_sk(rho, tr, key, &t0, &s1, &s2, private_key_.private_key);

    /* Compute CRH(tr, msg) */
    shake256_init(&state);
    shake256_absorb(&state, tr, CRHBYTES);
    shake256_absorb(&state, buffer.const_data(), buffer.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
    randombytes(BufferView(rhoprime, CRHBYTES));
#else
    crh(rhoprime, key, SEEDBYTES + CRHBYTES);
#endif

    /* Expand matrix and transform vectors */
    polyvec_matrix_expand(mat, rho);
    polyvecl_ntt(&s1);
    polyveck_ntt(&s2);
    polyveck_ntt(&t0);

rej:
    /* Sample intermediate vector y */
    polyvecl_uniform_gamma1(&y, rhoprime, nonce++);
    z = y;
    polyvecl_ntt(&z);

    /* Matrix-vector multiplication */
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    polyveck_caddq(&w1);
    polyveck_decompose(&w1, &w0, &w1);
    polyveck_pack_w1(signature.data(), &w1);

    shake256_init(&state);
    shake256_absorb(&state, mu, CRHBYTES);
    shake256_absorb(&state, signature.const_data(), K * POLYW1_PACKEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(signature.data(), SEEDBYTES, &state);
    poly_challenge(&cp, signature.const_data());
    poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    polyvecl_invntt_tomont(&z);
    polyvecl_add(&z, &z, &y);
    polyvecl_reduce(&z);
    if (polyvecl_chknorm(&z, GAMMA1 - BETA))
        goto rej;

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    polyveck_invntt_tomont(&h);
    polyveck_sub(&w0, &w0, &h);
    polyveck_reduce(&w0);
    if (polyveck_chknorm(&w0, GAMMA2 - BETA))
        goto rej;

    /* Compute hints for w1 */
    polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    polyveck_invntt_tomont(&h);
    polyveck_reduce(&h);
    if (polyveck_chknorm(&h, GAMMA2))
        goto rej;

    polyveck_add(&w0, &w0, &h);
    polyveck_caddq(&w0);
    n = polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA)
        goto rej;

    /* Write signature */
    pack_sig(signature.data(), signature.const_data(), &z, &h);
}
