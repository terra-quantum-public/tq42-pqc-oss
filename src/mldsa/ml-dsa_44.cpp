#include "ml-dsa_44.h"
#include "fips202.h"
#include "packingml.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"
#include <rng/random_generator.h>

using namespace mldsa;

MLDSAFactory_44::MLDSAFactory_44() {}

uint32_t MLDSAFactory_44::cipher_id() const { return PQC_CIPHER_ML_DSA_44; }

std::unique_ptr<PQC_Context> MLDSAFactory_44::create_context_asymmetric(
    const ConstBufferView & public_key, const ConstBufferView & private_key
) const
{
    check_size_or_empty(private_key, PQC_ML_DSA_PRIVATE_KEY_LEN_44);
    check_size_or_empty(public_key, PQC_ML_DSA_PUBLIC_KEY_LEN_44);
    return std::make_unique<MLDSAContext_44>(public_key, private_key);
}

void MLDSAContext_44::generate_keypair()
{
    const uint8_t modeK = K_44;
    const uint8_t modeL = L_44;

    auto [public_key_view, private_key_view] =
        allocate_keys(PQC_ML_DSA_PUBLIC_KEY_LEN_44, PQC_ML_DSA_PRIVATE_KEY_LEN_44);

    uint8_t seedbuf[4 * SEEDBYTES];
    uint8_t tr[2 * SEEDBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl_44 mat[modeK];
    polyvecl_44 s1, s1hat;
    polyveck_44 s2, t1, t0;

    get_random_generator().random_bytes(BufferView(&seedbuf, SEEDBYTES)); // get seed
    // expand seed H(sedd|k|l)
    seedbuf[SEEDBYTES] = modeK;
    seedbuf[SEEDBYTES + 1] = modeL;
    shake256(seedbuf, 4 * SEEDBYTES, seedbuf, SEEDBYTES + 2);

    rho = seedbuf;
    rhoprime = seedbuf + SEEDBYTES;
    key = seedbuf + 3 * SEEDBYTES;

    //  Expand matrix
    polyvec_matrix_expand_44(mat, rho, modeK);

    // Sample short vectors s1 and s2
    polyvecl_uniform_etaMldsa(s1.vec, rhoprime, 0, modeL);
    polyveck_uniform_etaMldsa(s2.vec, rhoprime, modeL, modeK);

    // Matrix-vector multiplication
    s1hat = s1;
    polyvecl_ntt(s1hat.vec, modeL);
    polyvec_matrix_pointwise_montgomery_44(t1.vec, mat, s1hat.vec, modeK);

    polyveck_reduce(t1.vec, modeK);
    polyveck_invntt_tomont(t1.vec, modeK);

    // Add error vector s2
    polyveck_add(t1.vec, t1.vec, s2.vec, modeK);

    // here is step 6 Alg 1 fips 204
    //  Extract t1 and write public key
    polyveck_caddq(t1.vec, modeK);
    polyveck_power2round(t1.vec, t0.vec, t1.vec, modeK);
    pack_pkMldsa(public_key_view.data(), rho, t1.vec, modeK);

    // Compute CRH(rho, t1) and write secret key
    shake256(tr, 2 * SEEDBYTES, public_key_view.const_data(), PQC_ML_DSA_PUBLIC_KEY_LEN_44);
    pack_skMldsa(private_key_view.data(), rho, tr, key, t0.vec, s1.vec, s2.vec, modeK);
}


bool MLDSAContext_44::verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const
{
    const uint8_t modeK = K_44;
    const uint8_t modeL = L_44;

    if (signature.size() != PQC_ML_DSA_SIGNATURE_LEN_44)
    {
        throw BadLength();
    }

    unsigned int i;
    uint8_t buf[K_44 * POLYW1_PACKEDBYTES_44];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[2 * SEEDBYTES];
    uint8_t c[2 * SEEDBYTES];
    uint8_t c2[SEEDBYTES];
    poly cp;
    polyvecl_44 z;
    polyvecl_44 mat[K_44];
    polyveck_44 t1, w1, h;
    keccak_state state;

    unpack_pkMldsa(rho, t1.vec, public_key().const_data(), modeK);
    if (unpack_sigMldsa(c, z.vec, h.vec, signature.const_data(), modeK))
    {
        return false;
    }
    if (polyvecl_chknorm(z.vec, GAMMA1_44 - BETA_44, modeL))
        return false;

    /* Compute CRH(CRH(rho, t1), msg) */
    shake256(
        mu, 2 * SEEDBYTES, public_key().const_data(), PQC_ML_DSA_PUBLIC_KEY_LEN_44
    ); // New instead of crh //Step 6 alg 3 fips 204

    // step 7 alg 3 fips 204
    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    shake256_absorb(&state, buffer.const_data(), buffer.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, 2 * SEEDBYTES, &state); // #changed    CRHBYTES);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challengeMldsa(&cp, c, modeK);
    polyvec_matrix_expand_44(mat, rho, modeK);

    polyvecl_ntt(z.vec, modeL);
    polyvec_matrix_pointwise_montgomery_44(w1.vec, mat, z.vec, modeK);

    poly_ntt(&cp);
    polyveck_shiftl(t1.vec, modeK);
    polyveck_ntt(t1.vec, modeK);
    polyveck_pointwise_poly_montgomery(t1.vec, &cp, t1.vec, modeK);

    polyveck_sub(w1.vec, w1.vec, t1.vec, modeK);
    polyveck_reduce(w1.vec, modeK);
    polyveck_invntt_tomont(w1.vec, modeK);

    /* Reconstruct w1 */
    polyveck_caddq(w1.vec, modeK);
    polyveck_use_hint(w1.vec, w1.vec, h.vec, modeK);
    polyveck_pack_w1(buf, w1.vec, modeK);

    /* Call random oracle and verify challenge */
    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    shake256_absorb(&state, buf, modeK * POLYW1_PACKEDBYTES_44);
    shake256_finalize(&state);
    shake256_squeeze(c2, SEEDBYTES, &state);

    for (i = 0; i < SEEDBYTES; ++i)
        if (c[i] != c2[i])
            return false;

    return true;
}


size_t MLDSAFactory_44::get_length(uint32_t type) const
{
    switch (type)
    {
    case PQC_LENGTH_PUBLIC:
        return PQC_ML_DSA_PUBLIC_KEY_LEN_44;
    case PQC_LENGTH_PRIVATE:
        return PQC_ML_DSA_PRIVATE_KEY_LEN_44;
    case PQC_LENGTH_SIGNATURE:
        return PQC_ML_DSA_SIGNATURE_LEN_44;
    }
    return 0;
}

size_t MLDSAContext_44::get_length(uint32_t type) const { return MLDSAFactory_44().get_length(type); }


void MLDSAContext_44::create_signature(const ConstBufferView & buffer, const BufferView & signature)
{
    const uint8_t modeK = K_44;
    const uint8_t modeL = L_44;

    if (signature.size() != PQC_ML_DSA_SIGNATURE_LEN_44)
    {
        throw BadLength();
    }

    unsigned int n;
    uint8_t seedbuf[9 * SEEDBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint8_t * rnd;
    uint16_t nonce = 0;
    polyvecl_44 y, z;
    polyvecl_44 mat[modeK];
    polyveck_44 w1, w0, h;
    poly s1[modeL], s2[modeK], t0[modeK];
    poly cp;
    keccak_state state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + 2 * SEEDBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + SEEDBYTES;
    rhoprime = mu + 2 * SEEDBYTES;
    unpack_skMldsa(rho, tr, key, t0, s1, s2, private_key().const_data(), modeK);

    //   Expand matrix and transform vectors
    polyvecl_ntt(s1, modeL);
    polyveck_ntt(s2, modeK);
    polyveck_ntt(t0, modeK);

    // polyvec_matrix_expand(mat, rho, modeK);
    polyvec_matrix_expand_44(mat, rho, modeK);

    //  Compute CRH(tr, msg)
    shake256_init(&state);
    shake256_absorb(&state, tr, 2 * SEEDBYTES);
    shake256_absorb(&state, buffer.const_data(), buffer.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, 2 * SEEDBYTES, &state);

    get_random_generator().random_bytes(BufferView(rnd, SEEDBYTES));
    shake256(rhoprime, 2 * SEEDBYTES, key, 4 * SEEDBYTES);

rej:
    // Sample intermediate vector y
    polyvecl_uniform_gamma1Mldsa_44(&y, rhoprime, nonce++, modeL);
    z = y;
    polyvecl_ntt(z.vec, modeL);

    // Matrix-vector multiplication
    polyvec_matrix_pointwise_montgomery_44(w1.vec, mat, z.vec, modeK);
    polyveck_reduce(w1.vec, modeK);
    polyveck_invntt_tomont(w1.vec, modeK);

    // Decompose w and call the random oracle
    polyveck_caddq(w1.vec, modeK);
    polyveck_decompose(w1.vec, w0.vec, w1.vec, modeK);
    polyveck_pack_w1(signature.data(), w1.vec, modeK);

    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    shake256_absorb(&state, signature.const_data(), K_44 * POLYW1_PACKEDBYTES_44);
    shake256_finalize(&state);
    shake256_squeeze(signature.data(), CTILDEBYTES_44, &state);
    poly_challengeMldsa(&cp, signature.const_data(), modeK);
    poly_ntt(&cp);

    // Compute z, reject if it reveals secret
    polyvecl_pointwise_poly_montgomery(z.vec, &cp, s1, modeL);
    polyvecl_invntt_tomont(z.vec, modeL);
    polyvecl_add(z.vec, z.vec, y.vec, modeL);
    polyvecl_reduce(z.vec, modeL);
    if (polyvecl_chknorm(z.vec, GAMMA1_44 - BETA_44, modeL))
        goto rej;

    // Check that subtracting cs2 does not change high bits of w and low bits
    // do not reveal secret information
    polyveck_pointwise_poly_montgomery(h.vec, &cp, s2, modeK);
    polyveck_invntt_tomont(h.vec, modeK);
    polyveck_sub(w0.vec, w0.vec, h.vec, modeK);
    polyveck_reduce(w0.vec, modeK);
    if (polyveck_chknorm(w0.vec, GAMMA2_44 - BETA_44, modeK))
        goto rej;

    // Compute hints for w1
    polyveck_pointwise_poly_montgomery(h.vec, &cp, t0, modeK);
    polyveck_invntt_tomont(h.vec, modeK);
    polyveck_reduce(h.vec, modeK);
    if (polyveck_chknorm(h.vec, GAMMA2_44, modeK))
        goto rej;

    polyveck_add(w0.vec, w0.vec, h.vec, modeK);
    polyveck_caddq(w0.vec, modeK);
    n = polyveck_make_hint(h.vec, w0.vec, w1.vec, modeK);
    if (n > OMEGA_44)
        goto rej;

    // Write signature
    pack_sigMldsa(signature.data(), signature.const_data(), z.vec, h.vec, modeK);
}
