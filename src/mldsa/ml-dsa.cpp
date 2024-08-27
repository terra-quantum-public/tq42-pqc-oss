#include "ml-dsa.h"
#include <rng/rng.h>

#include "fips202.h"
#include "packingml.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"

using namespace mldsa;

MLDSAFactory::MLDSAFactory() {}

uint32_t MLDSAFactory::cipher_id() const { return PQC_CIPHER_ML_DSA; }

std::unique_ptr<PQC_Context> MLDSAFactory::create_context(const ConstBufferView & private_key) const
{
    if (private_key.size() != PQC_ML_DSA_PRIVATE_KEY_LEN)
    {
        throw BadLength();
    }
    return std::make_unique<MLDSAContext>(reinterpret_cast<const pqc_ml_dsa_private_key *>(private_key.const_data()));
}

void polyvecl_uniform_etaMldsa(polyvecl * v, const uint8_t seed[2 * SEEDBYTES], uint16_t nonce)
{
    unsigned int i;

    for (i = 0; i < L; ++i)
        poly_uniform_etaMldsa(&v->vec[i], seed, nonce++);
}
void polyveck_uniform_etaMldsa(polyveck * v, const uint8_t seed[2 * SEEDBYTES], uint16_t nonce)
{
    unsigned int i;

    for (i = 0; i < K; ++i)
        poly_uniform_etaMldsa(&v->vec[i], seed, nonce++);
}

void MLDSAFactory::generate_keypair(const BufferView & public_key, const BufferView & private_key) const
{

    if (private_key.size() != PQC_ML_DSA_PRIVATE_KEY_LEN || public_key.size() != PQC_ML_DSA_PUBLIC_KEY_LEN)
    {
        throw BadLength();
    }
    else
    {
        uint8_t seedbuf[4 * SEEDBYTES];
        uint8_t tr[2 * SEEDBYTES];
        const uint8_t *rho, *rhoprime, *key;
        polyvecl mat[K];
        polyvecl s1, s1hat;
        polyveck s2, t1, t0;

        randombytes(BufferView(&seedbuf, SEEDBYTES)); // get seed
        // expand seed H(sedd|k|l)
        seedbuf[SEEDBYTES] = K;
        seedbuf[SEEDBYTES + 1] = L;
        shake256(seedbuf, 4 * SEEDBYTES, seedbuf, SEEDBYTES + 2);

        rho = seedbuf;
        rhoprime = seedbuf + SEEDBYTES;
        key = seedbuf + 3 * SEEDBYTES;

        //  Expand matrix
        polyvec_matrix_expand(mat, rho);

        // Sample short vectors s1 and s2
        polyvecl_uniform_etaMldsa(&s1, rhoprime, 0);
        polyveck_uniform_etaMldsa(&s2, rhoprime, L);

        // Matrix-vector multiplication
        s1hat = s1;
        polyvecl_ntt(&s1hat);
        polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
        polyveck_reduce(&t1);
        polyveck_invntt_tomont(&t1);

        // Add error vector s2
        polyveck_add(&t1, &t1, &s2);

        // here is step 6 Alg 1 fips 204
        //  Extract t1 and write public key
        polyveck_caddq(&t1);
        polyveck_power2round(&t1, &t0, &t1);
        pack_pkMldsa(public_key.data(), rho, &t1);

        // Compute CRH(rho, t1) and write secret key
        shake256(tr, 2 * SEEDBYTES, public_key.const_data(), PQC_ML_DSA_PUBLIC_KEY_LEN);

        pack_skMldsa(private_key.data(), rho, tr, key, &t0, &s1, &s2);
    }
}


bool MLDSAFactory::verify(
    const ConstBufferView & public_key, const ConstBufferView buffer, const ConstBufferView signature
) const
{
    if (signature.size() != PQC_ML_DSA_SIGNATURE_LEN)
    {
        throw BadLength();
    }

    if (public_key.size() != PQC_ML_DSA_PUBLIC_KEY_LEN)
    {
        throw BadLength();
    }

    unsigned int i;
    uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[2 * SEEDBYTES];
    uint8_t c[2 * SEEDBYTES];
    uint8_t c2[SEEDBYTES];
    poly cp;
    polyvecl mat[K], z;
    polyveck t1, w1, h;
    keccak_state state;

    unpack_pkMldsa(rho, &t1, public_key.const_data()); // unpack_pkMldsa
    if (unpack_sigMldsa(c, &z, &h, signature.const_data()))
    {
        return false;
    }
    if (polyvecl_chknorm(&z, GAMMA1 - BETA))
        return false;

    /* Compute CRH(CRH(rho, t1), msg) */
    // crh(mu, pk, PQC_MLDSA_PUBLIC_KEYLEN);
    shake256(
        mu, 2 * SEEDBYTES, public_key.const_data(), PQC_ML_DSA_PUBLIC_KEY_LEN
    ); // New instead of crh //Step 6 alg 3 fips 204

    // step 7 alg 3 fips 204
    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    shake256_absorb(&state, buffer.const_data(), buffer.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, 2 * SEEDBYTES, &state); // #changed    CRHBYTES);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challengeMldsa(&cp, c);
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
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    shake256_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(c2, SEEDBYTES, &state);

    for (i = 0; i < SEEDBYTES; ++i)
        if (c[i] != c2[i])
            return false;

    return true;
}


size_t MLDSAFactory::get_length(uint32_t type) const
{
    switch (type)
    {
    case PQC_LENGTH_PUBLIC:
        return PQC_ML_DSA_PUBLIC_KEY_LEN;
    case PQC_LENGTH_PRIVATE:
        return PQC_ML_DSA_PRIVATE_KEY_LEN;
    case PQC_LENGTH_SIGNATURE:
        return PQC_ML_DSA_SIGNATURE_LEN;
    }
    return 0;
}

size_t MLDSAContext::get_length(uint32_t type) const { return MLDSAFactory().get_length(type); }


void MLDSAContext::sign(const ConstBufferView & buffer, const BufferView & signature) const
{
    if (signature.size() != PQC_ML_DSA_SIGNATURE_LEN)
    {
        throw BadLength();
    }

    unsigned int n;
    uint8_t seedbuf[9 * SEEDBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint8_t * rnd;
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    keccak_state state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + 2 * SEEDBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + SEEDBYTES;
    rhoprime = mu + 2 * SEEDBYTES;
    unpack_skMldsa(rho, tr, key, &t0, &s1, &s2, private_key_.private_key);

    //   Expand matrix and transform vectors
    polyvecl_ntt(&s1);
    polyveck_ntt(&s2);
    polyveck_ntt(&t0);

    polyvec_matrix_expand(mat, rho);

    //  Compute CRH(tr, msg)
    shake256_init(&state);
    shake256_absorb(&state, tr, 2 * SEEDBYTES);
    shake256_absorb(&state, buffer.const_data(), buffer.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, 2 * SEEDBYTES, &state);

    randombytes(BufferView(rnd, SEEDBYTES));
    shake256(rhoprime, 2 * SEEDBYTES, key, 4 * SEEDBYTES);

rej:
    // Sample intermediate vector y
    polyvecl_uniform_gamma1Mldsa(&y, rhoprime, nonce++);
    z = y;
    polyvecl_ntt(&z);

    // Matrix-vector multiplication
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);

    // Decompose w and call the random oracle
    polyveck_caddq(&w1);
    polyveck_decompose(&w1, &w0, &w1);
    polyveck_pack_w1(signature.data(), &w1);

    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    shake256_absorb(&state, signature.const_data(), K * POLYW1_PACKEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(signature.data(), 2 * SEEDBYTES, &state);
    poly_challengeMldsa(&cp, signature.const_data());
    poly_ntt(&cp);

    // Compute z, reject if it reveals secret
    polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    polyvecl_invntt_tomont(&z);
    polyvecl_add(&z, &z, &y);
    polyvecl_reduce(&z);
    if (polyvecl_chknorm(&z, GAMMA1 - BETA))
        goto rej;

    // Check that subtracting cs2 does not change high bits of w and low bits
    // do not reveal secret information
    polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    polyveck_invntt_tomont(&h);
    polyveck_sub(&w0, &w0, &h);
    polyveck_reduce(&w0);
    if (polyveck_chknorm(&w0, GAMMA2 - BETA))
        goto rej;

    // Compute hints for w1
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

    // Write signature
    pack_sigMldsa(signature.data(), signature.const_data(), &z, &h);
}
