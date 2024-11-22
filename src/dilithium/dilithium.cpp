#include "dilithium.h"

#include "fips202.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"

using namespace dilithium;

DilithiumFactory::DilithiumFactory() {}

uint32_t DilithiumFactory::cipher_id() const { return PQC_CIPHER_DILITHIUM; }

std::unique_ptr<PQC_Context> DilithiumFactory::create_context_asymmetric(
    const ConstBufferView & public_key, const ConstBufferView & private_key
) const
{
    check_size_or_empty(private_key, PQC_DILITHIUM_PRIVATE_KEY_LEN);
    check_size_or_empty(public_key, PQC_DILITHIUM_PUBLIC_KEY_LEN);
    return std::make_unique<DilithiumContext>(public_key, private_key);
}

void DilithiumContext::generate_keypair()
{
    // 5 mode of Dilithium
    const uint8_t modeK = 8;
    const uint8_t modeL = 7;

    auto [public_key_view, private_key_view] =
        allocate_keys(PQC_DILITHIUM_PUBLIC_KEY_LEN, PQC_DILITHIUM_PRIVATE_KEY_LEN);

    uint8_t seedbuf[3 * SEEDBYTES];
    uint8_t tr[CRHBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    /* Get randomness for rho, rhoprime and key */
    get_random_generator().random_bytes(BufferView(&seedbuf, SEEDBYTES));
    shake256(seedbuf, 3 * SEEDBYTES, seedbuf, SEEDBYTES);
    rho = seedbuf;
    rhoprime = seedbuf + SEEDBYTES;
    key = seedbuf + 2 * SEEDBYTES;

    /* Expand matrix */
    polyvec_matrix_expand(mat, rho, modeK);

    /* Sample short vectors s1 and s2 */
    polyvecl_uniform_eta(&s1, rhoprime, 0, modeL);
    polyveck_uniform_eta(&s2, rhoprime, L, modeK);

    /* Matrix-vector multiplication */
    s1hat = s1;
    polyvecl_ntt(s1hat.vec, modeL);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat, modeK);
    polyveck_reduce(t1.vec, modeK);
    polyveck_invntt_tomont(t1.vec, modeK);

    /* Add error vector s2 */
    polyveck_add(t1.vec, t1.vec, s2.vec, modeK);

    /* Extract t1 and write public key */
    polyveck_caddq(t1.vec, modeK);
    polyveck_power2round(t1.vec, t0.vec, t1.vec, modeK);
    pack_pk(public_key_view.data(), rho, &t1);

    /* Compute CRH(rho, t1) and write secret key */
    crh(tr, public_key_view.data(), CRYPTO_PUBLICKEYBYTES);
    pack_sk(private_key_view.data(), rho, tr, key, &t0, &s1, &s2);
}


bool DilithiumContext::verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const
{
    // 5 mode of Dilithium
    const uint8_t modeK = 8;
    const uint8_t modeL = 7;

    if (signature.size() != PQC_DILITHIUM_SIGNATURE_LEN)
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

    unpack_pk(rho, &t1, public_key().const_data());
    if (unpack_sig(c, &z, &h, signature.const_data()))
        return false;
    if (polyvecl_chknorm(z.vec, GAMMA1 - BETA, modeL))
        return false;

    /* Compute CRH(CRH(rho, t1), msg) */
    crh(mu, public_key().const_data(), CRYPTO_PUBLICKEYBYTES);
    shake256_init(&state);
    shake256_absorb(&state, mu, CRHBYTES);
    shake256_absorb(&state, buffer.const_data(), buffer.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, CRHBYTES, &state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challenge(&cp, c);
    polyvec_matrix_expand(mat, rho, modeK);

    polyvecl_ntt(z.vec, modeL);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z, modeK);

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


void DilithiumContext::create_signature(const ConstBufferView & buffer, const BufferView & signature)
{
    // 5 mode of Dilithium
    const uint8_t modeK = 8;
    const uint8_t modeL = 7;

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
    unpack_sk(rho, tr, key, t0.vec, s1.vec, s2.vec, private_key().const_data());

    /* Compute CRH(tr, msg) */
    shake256_init(&state);
    shake256_absorb(&state, tr, CRHBYTES);
    shake256_absorb(&state, buffer.const_data(), buffer.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
    get_random_generator().random_bytes(BufferView(rhoprime, CRHBYTES));
#else
    crh(rhoprime, key, SEEDBYTES + CRHBYTES);
#endif

    /* Expand matrix and transform vectors */
    // polyvec_matrix_expand(mat, rho, modeK);
    polyvec_matrix_expand(mat, rho, modeK);
    polyvecl_ntt(s1.vec, modeL);
    polyveck_ntt(s2.vec, modeK);
    polyveck_ntt(t0.vec, modeK);

rej:
    /* Sample intermediate vector y */
    polyvecl_uniform_gamma1(y.vec, rhoprime, nonce++, modeL);
    z = y;
    polyvecl_ntt(z.vec, modeL);

    /* Matrix-vector multiplication */
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z, modeK);
    // polyvec_matrix_pointwise_montgomery(w1.vec, mat, z.vec, modeK);
    polyveck_reduce(w1.vec, modeK);
    polyveck_invntt_tomont(w1.vec, modeK);

    /* Decompose w and call the random oracle */
    polyveck_caddq(w1.vec, modeK);
    polyveck_decompose(w1.vec, w0.vec, w1.vec, modeK);
    polyveck_pack_w1(signature.data(), w1.vec, modeK);

    shake256_init(&state);
    shake256_absorb(&state, mu, CRHBYTES);
    shake256_absorb(&state, signature.const_data(), K * POLYW1_PACKEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(signature.data(), SEEDBYTES, &state);
    poly_challenge(&cp, signature.const_data());
    poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    polyvecl_pointwise_poly_montgomery(z.vec, &cp, s1.vec, modeL);
    polyvecl_invntt_tomont(z.vec, modeL);
    polyvecl_add(z.vec, z.vec, y.vec, modeL);
    polyvecl_reduce(z.vec, modeL);
    if (polyvecl_chknorm(z.vec, GAMMA1 - BETA, modeL))
        goto rej;

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    polyveck_pointwise_poly_montgomery(h.vec, &cp, s2.vec, modeK);
    polyveck_invntt_tomont(h.vec, modeK);
    polyveck_sub(w0.vec, w0.vec, h.vec, modeK);
    polyveck_reduce(w0.vec, modeK);
    if (polyveck_chknorm(w0.vec, GAMMA2 - BETA, modeK))
        goto rej;

    /* Compute hints for w1 */
    polyveck_pointwise_poly_montgomery(h.vec, &cp, t0.vec, modeK);
    polyveck_invntt_tomont(h.vec, modeK);
    polyveck_reduce(h.vec, modeK);
    if (polyveck_chknorm(h.vec, GAMMA2, modeK))
        goto rej;

    polyveck_add(w0.vec, w0.vec, h.vec, modeK);
    polyveck_caddq(w0.vec, modeK);
    n = polyveck_make_hint(h.vec, w0.vec, w1.vec, modeK);
    if (n > OMEGA)
        goto rej;

    /* Write signature */
    pack_sig(signature.data(), signature.const_data(), z.vec, h.vec);
}
