#include "mldsa_internal.h"
#include "fips202.h"
#include "packingml.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"

namespace mldsa
{

void PQC_API
mldsa_keygen_internal_44(const BufferView & pk, const BufferView & sk, const ConstBufferView & optrand, size_t mode)
{
    const uint8_t modeK = K_44;
    const uint8_t modeL = L_44;

    uint8_t seedbuf[4 * SEEDBYTES];
    uint8_t tr[2 * SEEDBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl_44 mat[modeK];
    polyvecl_44 s1, s1hat;
    polyveck_44 s2, t1, t0;

    BufferView initial_seed(&seedbuf, SEEDBYTES);
    initial_seed.store(optrand);
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
    pack_pkMldsa(pk.data(), rho, t1.vec, modeK);

    // Compute CRH(rho, t1) and write secret key
    shake256(tr, 2 * SEEDBYTES, pk.const_data(), ParameterSets[mode].PUBLIC_KEY_LEN);
    pack_skMldsa(sk.data(), rho, tr, key, t0.vec, s1.vec, s2.vec, modeK);
}


bool PQC_API mldsa_verify_internal_44(
    const ConstBufferView & msg, const ConstBufferView & pk, const ConstBufferView & signature, size_t mode,
    const std::optional<ConstBufferView> & context
)
{
    const uint8_t modeK = K_44;
    const uint8_t modeL = L_44;

    if (signature.size() != ParameterSets[mode].SIGNATURE_LEN)
    {
        return false;
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

    unpack_pkMldsa(rho, t1.vec, pk.const_data(), modeK);
    if (unpack_sigMldsa(c, z.vec, h.vec, signature.const_data(), modeK))
    {
        return false;
    }
    if (polyvecl_chknorm(z.vec, GAMMA1_44 - BETA_44, modeL))
        return false;

    /* Compute CRH(CRH(rho, t1), msg) */
    shake256(
        mu, 2 * SEEDBYTES, pk.const_data(), ParameterSets[mode].PUBLIC_KEY_LEN
    ); // New instead of crh //Step 6 alg 3 fips 204

    // step 7 alg 3 fips 204
    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    if (context)
    {
        StackBuffer<2> header;
        header[0] = 0;
        header[1] = (uint8_t)(context.value().size());
        shake256_absorb(&state, header.const_data(), header.size());
        shake256_absorb(&state, context.value().const_data(), context.value().size());
    }
    shake256_absorb(&state, msg.const_data(), msg.size());
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

void PQC_API mldsa_sign_internal_44(
    const ConstBufferView & msg, const ConstBufferView & sk, const ConstBufferView & optrand,
    const BufferView & signature, size_t mode, const std::optional<ConstBufferView> & context
)
{
    const uint8_t modeK = K_44;
    const uint8_t modeL = L_44;

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
    unpack_skMldsa(rho, tr, key, t0, s1, s2, sk.const_data(), modeK);

    //   Expand matrix and transform vectors
    polyvecl_ntt(s1, modeL);
    polyveck_ntt(s2, modeK);
    polyveck_ntt(t0, modeK);

    // polyvec_matrix_expand(mat, rho, modeK);
    polyvec_matrix_expand_44(mat, rho, modeK);

    //  Compute CRH(tr, msg)
    shake256_init(&state);
    shake256_absorb(&state, tr, 2 * SEEDBYTES);
    if (context)
    {
        StackBuffer<2> header;
        header[0] = 0;
        header[1] = (uint8_t)(context.value().size());
        shake256_absorb(&state, header.const_data(), header.size());
        shake256_absorb(&state, context.value().const_data(), context.value().size());
    }
    shake256_absorb(&state, msg.const_data(), msg.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, 2 * SEEDBYTES, &state);

    BufferView rnd_buf(rnd, SEEDBYTES);
    rnd_buf.store(optrand);
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
    shake256_absorb(&state, signature.const_data(), ParameterSets[mode].K * POLYW1_PACKEDBYTES_44);
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

void PQC_API
mldsa_keygen_internal_65(const BufferView & pk, const BufferView & sk, const ConstBufferView & optrand, size_t mode)
{
    const uint8_t modeK = K_65;
    const uint8_t modeL = L_65;

    uint8_t seedbuf[4 * SEEDBYTES];
    uint8_t tr[2 * SEEDBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl_65 mat[modeK];
    polyvecl_65 s1, s1hat;
    polyveck_65 s2, t1, t0;

    BufferView initial_seed(&seedbuf, SEEDBYTES);
    initial_seed.store(optrand);
    // expand seed H(sedd|k|l)
    seedbuf[SEEDBYTES] = modeK;
    seedbuf[SEEDBYTES + 1] = modeL;
    shake256(seedbuf, 4 * SEEDBYTES, seedbuf, SEEDBYTES + 2);

    rho = seedbuf;
    rhoprime = seedbuf + SEEDBYTES;
    key = seedbuf + 3 * SEEDBYTES;

    //  Expand matrix
    polyvec_matrix_expand_65(mat, rho, modeK);

    // Sample short vectors s1 and s2
    polyvecl_uniform_etaMldsa(s1.vec, rhoprime, 0, modeL);
    polyveck_uniform_etaMldsa(s2.vec, rhoprime, modeL, modeK);

    // Matrix-vector multiplication
    s1hat = s1;
    polyvecl_ntt(s1hat.vec, modeL);
    polyvec_matrix_pointwise_montgomery_65(t1.vec, mat, s1hat.vec, modeK);

    polyveck_reduce(t1.vec, modeK);
    polyveck_invntt_tomont(t1.vec, modeK);

    // Add error vector s2
    polyveck_add(t1.vec, t1.vec, s2.vec, modeK);

    // here is step 6 Alg 1 fips 204
    //  Extract t1 and write public key
    polyveck_caddq(t1.vec, modeK);
    polyveck_power2round(t1.vec, t0.vec, t1.vec, modeK);
    pack_pkMldsa(pk.data(), rho, t1.vec, modeK);

    // Compute CRH(rho, t1) and write secret key
    shake256(tr, 2 * SEEDBYTES, pk.const_data(), ParameterSets[mode].PUBLIC_KEY_LEN);
    pack_skMldsa(sk.data(), rho, tr, key, t0.vec, s1.vec, s2.vec, modeK);
}


bool PQC_API mldsa_verify_internal_65(
    const ConstBufferView & msg, const ConstBufferView & pk, const ConstBufferView & signature, size_t mode,
    const std::optional<ConstBufferView> & context
)
{
    const uint8_t modeK = K_65;
    const uint8_t modeL = L_65;

    if (signature.size() != ParameterSets[mode].SIGNATURE_LEN)
    {
        return false;
    }

    unsigned int i;
    uint8_t buf[K_65 * POLYW1_PACKEDBYTES_65];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[2 * SEEDBYTES];
    uint8_t c[2 * SEEDBYTES];
    uint8_t c2[SEEDBYTES];
    poly cp;
    polyvecl_65 z;
    polyvecl_65 mat[K_65];
    polyveck_65 t1, w1, h;
    keccak_state state;

    unpack_pkMldsa(rho, t1.vec, pk.const_data(), modeK);
    if (unpack_sigMldsa(c, z.vec, h.vec, signature.const_data(), modeK))
    {
        return false;
    }
    if (polyvecl_chknorm(z.vec, GAMMA1_65 - BETA_65, modeL))
        return false;

    /* Compute CRH(CRH(rho, t1), msg) */
    shake256(
        mu, 2 * SEEDBYTES, pk.const_data(), ParameterSets[mode].PUBLIC_KEY_LEN
    ); // New instead of crh //Step 6 alg 3 fips 204

    // step 7 alg 3 fips 204
    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    if (context)
    {
        StackBuffer<2> header;
        header[0] = 0;
        header[1] = (uint8_t)(context.value().size());
        shake256_absorb(&state, header.const_data(), header.size());
        shake256_absorb(&state, context.value().const_data(), context.value().size());
    }
    shake256_absorb(&state, msg.const_data(), msg.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, 2 * SEEDBYTES, &state); // #changed    CRHBYTES);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challengeMldsa(&cp, c, modeK);
    polyvec_matrix_expand_65(mat, rho, modeK);

    polyvecl_ntt(z.vec, modeL);
    polyvec_matrix_pointwise_montgomery_65(w1.vec, mat, z.vec, modeK);

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
    shake256_absorb(&state, buf, modeK * POLYW1_PACKEDBYTES_65);
    shake256_finalize(&state);
    shake256_squeeze(c2, SEEDBYTES, &state);

    for (i = 0; i < SEEDBYTES; ++i)
        if (c[i] != c2[i])
            return false;

    return true;
}

void PQC_API mldsa_sign_internal_65(
    const ConstBufferView & msg, const ConstBufferView & sk, const ConstBufferView & optrand,
    const BufferView & signature, size_t mode, const std::optional<ConstBufferView> & context
)
{
    const uint8_t modeK = K_65;
    const uint8_t modeL = L_65;

    unsigned int n;
    uint8_t seedbuf[9 * SEEDBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint8_t * rnd;
    uint16_t nonce = 0;
    polyvecl_65 y, z;
    polyvecl_65 mat[modeK];
    polyveck_65 w1, w0, h;
    poly s1[modeL], s2[modeK], t0[modeK];
    poly cp;
    keccak_state state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + 2 * SEEDBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + SEEDBYTES;
    rhoprime = mu + 2 * SEEDBYTES;
    unpack_skMldsa(rho, tr, key, t0, s1, s2, sk.const_data(), modeK);

    //   Expand matrix and transform vectors
    polyvecl_ntt(s1, modeL);
    polyveck_ntt(s2, modeK);
    polyveck_ntt(t0, modeK);

    // polyvec_matrix_expand(mat, rho, modeK);
    polyvec_matrix_expand_65(mat, rho, modeK);

    //  Compute CRH(tr, msg)
    shake256_init(&state);
    shake256_absorb(&state, tr, 2 * SEEDBYTES);
    if (context)
    {
        StackBuffer<2> header;
        header[0] = 0;
        header[1] = (uint8_t)(context.value().size());
        shake256_absorb(&state, header.const_data(), header.size());
        shake256_absorb(&state, context.value().const_data(), context.value().size());
    }
    shake256_absorb(&state, msg.const_data(), msg.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, 2 * SEEDBYTES, &state);

    BufferView rnd_buf(rnd, SEEDBYTES);
    rnd_buf.store(optrand);
    shake256(rhoprime, 2 * SEEDBYTES, key, 4 * SEEDBYTES);

rej:
    // Sample intermediate vector y
    polyvecl_uniform_gamma1Mldsa_65(&y, rhoprime, nonce++, modeL);
    z = y;
    polyvecl_ntt(z.vec, modeL);

    // Matrix-vector multiplication
    polyvec_matrix_pointwise_montgomery_65(w1.vec, mat, z.vec, modeK);
    polyveck_reduce(w1.vec, modeK);
    polyveck_invntt_tomont(w1.vec, modeK);

    // Decompose w and call the random oracle
    polyveck_caddq(w1.vec, modeK);
    polyveck_decompose(w1.vec, w0.vec, w1.vec, modeK);
    polyveck_pack_w1(signature.data(), w1.vec, modeK);

    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    shake256_absorb(&state, signature.const_data(), ParameterSets[mode].K * POLYW1_PACKEDBYTES_65);
    shake256_finalize(&state);
    shake256_squeeze(signature.data(), CTILDEBYTES_65, &state);
    poly_challengeMldsa(&cp, signature.const_data(), modeK);
    poly_ntt(&cp);

    // Compute z, reject if it reveals secret
    polyvecl_pointwise_poly_montgomery(z.vec, &cp, s1, modeL);
    polyvecl_invntt_tomont(z.vec, modeL);
    polyvecl_add(z.vec, z.vec, y.vec, modeL);
    polyvecl_reduce(z.vec, modeL);
    if (polyvecl_chknorm(z.vec, GAMMA1_65 - BETA_65, modeL))
        goto rej;

    // Check that subtracting cs2 does not change high bits of w and low bits
    // do not reveal secret information
    polyveck_pointwise_poly_montgomery(h.vec, &cp, s2, modeK);
    polyveck_invntt_tomont(h.vec, modeK);
    polyveck_sub(w0.vec, w0.vec, h.vec, modeK);
    polyveck_reduce(w0.vec, modeK);
    if (polyveck_chknorm(w0.vec, GAMMA2_65 - BETA_65, modeK))
        goto rej;

    // Compute hints for w1
    polyveck_pointwise_poly_montgomery(h.vec, &cp, t0, modeK);
    polyveck_invntt_tomont(h.vec, modeK);
    polyveck_reduce(h.vec, modeK);
    if (polyveck_chknorm(h.vec, GAMMA2_65, modeK))
        goto rej;

    polyveck_add(w0.vec, w0.vec, h.vec, modeK);
    polyveck_caddq(w0.vec, modeK);
    n = polyveck_make_hint(h.vec, w0.vec, w1.vec, modeK);
    if (n > OMEGA_65)
        goto rej;

    // Write signature
    pack_sigMldsa(signature.data(), signature.const_data(), z.vec, h.vec, modeK);
}

void PQC_API
mldsa_keygen_internal_87(const BufferView & pk, const BufferView & sk, const ConstBufferView & optrand, size_t mode)
{
    const uint8_t modeK = K_87;
    const uint8_t modeL = L_87;

    uint8_t seedbuf[4 * SEEDBYTES];
    uint8_t tr[2 * SEEDBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl_87 mat[modeK];
    polyvecl_87 s1, s1hat;
    polyveck_87 s2, t1, t0;

    BufferView initial_seed(&seedbuf, SEEDBYTES);
    initial_seed.store(optrand);
    // expand seed H(sedd|k|l)
    seedbuf[SEEDBYTES] = modeK;
    seedbuf[SEEDBYTES + 1] = modeL;
    shake256(seedbuf, 4 * SEEDBYTES, seedbuf, SEEDBYTES + 2);

    rho = seedbuf;
    rhoprime = seedbuf + SEEDBYTES;
    key = seedbuf + 3 * SEEDBYTES;

    //  Expand matrix
    polyvec_matrix_expand_87(mat, rho, modeK);

    // Sample short vectors s1 and s2
    polyvecl_uniform_etaMldsa(s1.vec, rhoprime, 0, modeL);
    polyveck_uniform_etaMldsa(s2.vec, rhoprime, modeL, modeK);

    // Matrix-vector multiplication
    s1hat = s1;
    polyvecl_ntt(s1hat.vec, modeL);
    polyvec_matrix_pointwise_montgomery_87(t1.vec, mat, s1hat.vec, modeK);

    polyveck_reduce(t1.vec, modeK);
    polyveck_invntt_tomont(t1.vec, modeK);

    // Add error vector s2
    polyveck_add(t1.vec, t1.vec, s2.vec, modeK);

    // here is step 6 Alg 1 fips 204
    //  Extract t1 and write public key
    polyveck_caddq(t1.vec, modeK);
    polyveck_power2round(t1.vec, t0.vec, t1.vec, modeK);
    pack_pkMldsa(pk.data(), rho, t1.vec, modeK);

    // Compute CRH(rho, t1) and write secret key
    shake256(tr, 2 * SEEDBYTES, pk.const_data(), ParameterSets[mode].PUBLIC_KEY_LEN);
    pack_skMldsa(sk.data(), rho, tr, key, t0.vec, s1.vec, s2.vec, modeK);
}


bool PQC_API mldsa_verify_internal_87(
    const ConstBufferView & msg, const ConstBufferView & pk, const ConstBufferView & signature, size_t mode,
    const std::optional<ConstBufferView> & context
)
{
    const uint8_t modeK = K_87;
    const uint8_t modeL = L_87;

    if (signature.size() != ParameterSets[mode].SIGNATURE_LEN)
    {
        return false;
    }

    unsigned int i;
    uint8_t buf[K_87 * POLYW1_PACKEDBYTES_87];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[2 * SEEDBYTES];
    uint8_t c[2 * SEEDBYTES];
    uint8_t c2[SEEDBYTES];
    poly cp;
    polyvecl_87 z;
    polyvecl_87 mat[K_87];
    polyveck_87 t1, w1, h;
    keccak_state state;

    unpack_pkMldsa(rho, t1.vec, pk.const_data(), modeK);
    if (unpack_sigMldsa(c, z.vec, h.vec, signature.const_data(), modeK))
    {
        return false;
    }
    if (polyvecl_chknorm(z.vec, GAMMA1_87 - BETA_87, modeL))
        return false;

    /* Compute CRH(CRH(rho, t1), msg) */
    shake256(
        mu, 2 * SEEDBYTES, pk.const_data(), ParameterSets[mode].PUBLIC_KEY_LEN
    ); // New instead of crh //Step 6 alg 3 fips 204

    // step 7 alg 3 fips 204
    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    if (context)
    {
        StackBuffer<2> header;
        header[0] = 0;
        header[1] = (uint8_t)(context.value().size());
        shake256_absorb(&state, header.const_data(), header.size());
        shake256_absorb(&state, context.value().const_data(), context.value().size());
    }
    shake256_absorb(&state, msg.const_data(), msg.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, 2 * SEEDBYTES, &state); // #changed    CRHBYTES);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challengeMldsa(&cp, c, modeK);
    polyvec_matrix_expand_87(mat, rho, modeK);

    polyvecl_ntt(z.vec, modeL);
    polyvec_matrix_pointwise_montgomery_87(w1.vec, mat, z.vec, modeK);

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
    shake256_absorb(&state, buf, modeK * POLYW1_PACKEDBYTES_87);
    shake256_finalize(&state);
    shake256_squeeze(c2, SEEDBYTES, &state);

    for (i = 0; i < SEEDBYTES; ++i)
        if (c[i] != c2[i])
            return false;

    return true;
}

void PQC_API mldsa_sign_internal_87(
    const ConstBufferView & msg, const ConstBufferView & sk, const ConstBufferView & optrand,
    const BufferView & signature, size_t mode, const std::optional<ConstBufferView> & context
)
{
    const uint8_t modeK = K_87;
    const uint8_t modeL = L_87;

    unsigned int n;
    uint8_t seedbuf[9 * SEEDBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint8_t * rnd;
    uint16_t nonce = 0;
    polyvecl_87 y, z;
    polyvecl_87 mat[modeK];
    polyveck_87 w1, w0, h;
    poly s1[modeL], s2[modeK], t0[modeK];
    poly cp;
    keccak_state state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + 2 * SEEDBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + SEEDBYTES;
    rhoprime = mu + 2 * SEEDBYTES;
    unpack_skMldsa(rho, tr, key, t0, s1, s2, sk.const_data(), modeK);

    //   Expand matrix and transform vectors
    polyvecl_ntt(s1, modeL);
    polyveck_ntt(s2, modeK);
    polyveck_ntt(t0, modeK);

    // polyvec_matrix_expand(mat, rho, modeK);
    polyvec_matrix_expand_87(mat, rho, modeK);

    //  Compute CRH(tr, msg)
    shake256_init(&state);
    shake256_absorb(&state, tr, 2 * SEEDBYTES);
    if (context)
    {
        StackBuffer<2> header;
        header[0] = 0;
        header[1] = (uint8_t)(context.value().size());
        shake256_absorb(&state, header.const_data(), header.size());
        shake256_absorb(&state, context.value().const_data(), context.value().size());
    }
    shake256_absorb(&state, msg.const_data(), msg.size());
    shake256_finalize(&state);
    shake256_squeeze(mu, 2 * SEEDBYTES, &state);

    BufferView rnd_buf(rnd, SEEDBYTES);
    rnd_buf.store(optrand);
    shake256(rhoprime, 2 * SEEDBYTES, key, 4 * SEEDBYTES);

rej:
    // Sample intermediate vector y
    polyvecl_uniform_gamma1Mldsa_87(&y, rhoprime, nonce++, modeL);
    z = y;
    polyvecl_ntt(z.vec, modeL);

    // Matrix-vector multiplication
    polyvec_matrix_pointwise_montgomery_87(w1.vec, mat, z.vec, modeK);
    polyveck_reduce(w1.vec, modeK);
    polyveck_invntt_tomont(w1.vec, modeK);

    // Decompose w and call the random oracle
    polyveck_caddq(w1.vec, modeK);
    polyveck_decompose(w1.vec, w0.vec, w1.vec, modeK);
    polyveck_pack_w1(signature.data(), w1.vec, modeK);

    shake256_init(&state);
    shake256_absorb(&state, mu, 2 * SEEDBYTES);
    shake256_absorb(&state, signature.const_data(), K_87 * POLYW1_PACKEDBYTES_87);
    shake256_finalize(&state);
    shake256_squeeze(signature.data(), CTILDEBYTES_87, &state);
    poly_challengeMldsa(&cp, signature.const_data(), modeK);
    poly_ntt(&cp);

    // Compute z, reject if it reveals secret
    polyvecl_pointwise_poly_montgomery(z.vec, &cp, s1, modeL);
    polyvecl_invntt_tomont(z.vec, modeL);
    polyvecl_add(z.vec, z.vec, y.vec, modeL);
    polyvecl_reduce(z.vec, modeL);
    if (polyvecl_chknorm(z.vec, GAMMA1_87 - BETA_87, modeL))
        goto rej;

    // Check that subtracting cs2 does not change high bits of w and low bits
    // do not reveal secret information
    polyveck_pointwise_poly_montgomery(h.vec, &cp, s2, modeK);
    polyveck_invntt_tomont(h.vec, modeK);
    polyveck_sub(w0.vec, w0.vec, h.vec, modeK);
    polyveck_reduce(w0.vec, modeK);
    if (polyveck_chknorm(w0.vec, GAMMA2_87 - BETA_87, modeK))
        goto rej;

    // Compute hints for w1
    polyveck_pointwise_poly_montgomery(h.vec, &cp, t0, modeK);
    polyveck_invntt_tomont(h.vec, modeK);
    polyveck_reduce(h.vec, modeK);
    if (polyveck_chknorm(h.vec, GAMMA2_87, modeK))
        goto rej;

    polyveck_add(w0.vec, w0.vec, h.vec, modeK);
    polyveck_caddq(w0.vec, modeK);
    n = polyveck_make_hint(h.vec, w0.vec, w1.vec, modeK);
    if (n > OMEGA_87)
        goto rej;

    // Write signature
    pack_sigMldsa(signature.data(), signature.const_data(), z.vec, h.vec, modeK);
}

} // namespace mldsa
